import AppKit

/// Bounded NDJSON transport over an exclusive inherited pipe, not a public listener.
/// Parsing and every surface operation run on the application's main actor.
@MainActor public final class WardenDesktopStandardIO {
    private let surface: WardenDesktopSurface
    private var initialized = false
    private var stopped = false
    public init(surface: WardenDesktopSurface) { self.surface = surface }
    #if WARDEN_DESKTOP_TESTS
    public var extraRequest: ((String, [String: Any]) throws -> [String: Any]?)?
    #endif
    private func send(_ value: [String: Any]) {
        do {
            let data = try JSONSerialization.data(withJSONObject: value, options: [.withoutEscapingSlashes, .sortedKeys])
            guard data.count <= 1_048_576 else { throw DesktopError.invalid }
            try FileHandle.standardOutput.write(contentsOf: data + Data([10]))
        } catch { stopped = true; NSApp.terminate(nil) }
    }
    public func receive(_ data: Data) {
        guard !stopped else { return }
        var id: Any = NSNull()
        do {
            let raw = try DesktopJSON.parse(data)
            guard let msg = raw as? [String: Any], Set(msg.keys).isSubset(of: ["jsonrpc", "id", "method", "params"]), msg["jsonrpc"] as? String == "2.0",
                  let method = msg["method"] as? String else { throw DesktopError.invalid }
            if let v = msg["id"] {
                guard v is String || (v is NSNumber && CFGetTypeID(v as! NSNumber) != CFBooleanGetTypeID() && (v as! NSNumber).doubleValue.isFinite && abs((v as! NSNumber).doubleValue) <= 9_007_199_254_740_991 && (v as! NSNumber).doubleValue.rounded() == (v as! NSNumber).doubleValue) else { throw DesktopError.invalid }
                id = v
            }
            let params: [String: Any]
            if let p = msg["params"] { guard let object = p as? [String: Any] else { throw DesktopError.invalid }; params = object } else { params = [:] }
            if method == "notifications/initialized" || method == "notifications/cancelled" { return }
            if method == "warden/screen/cancel" { try surface.cancel(params); if msg["id"] != nil { send(["jsonrpc": "2.0", "id": id, "result": [:]]) }; return }
            guard msg["id"] != nil else { return }
            let result: [String: Any]
            if method == "initialize" {
                guard !initialized else { throw DesktopError.invalid }; initialized = true
                result = ["protocolVersion": "2025-06-18", "capabilities": ["tools": [:]], "serverInfo": ["name": "warden-macos-owned-surface", "version": "1.0.0"]]
            } else {
                guard initialized else { throw DesktopError.invalid }
                let extra: [String: Any]?
                #if WARDEN_DESKTOP_TESTS
                extra = try extraRequest?(method, params)
                #else
                extra = nil
                #endif
                if let extra = extra { result = extra }
                else if method == "tools/list" {
                    result = ["tools": [
                        ["name": "screenshot", "description": "Observe registered native controls in the connected application.", "inputSchema": ["type": "object", "properties": [:], "additionalProperties": false]],
                        ["name": "click", "description": "Activate a registered native button through an atomic target-side commit.", "inputSchema": ["type": "object", "properties": ["index": ["type": "string"]], "required": ["index"], "additionalProperties": false]],
                    ]]
                } else if method == "tools/call" {
                    guard Set(params.keys).isSubset(of: ["name", "arguments"]), params["name"] as? String == "screenshot" else { throw DesktopError.unsupported }
                    if let a = params["arguments"] { guard let args = a as? [String: Any], args.isEmpty else { throw DesktopError.invalid } }
                    result = try surface.read()
                } else if method == "warden/screen/prepare" { result = try surface.prepare(params) }
                else if method == "warden/screen/commit" { result = try surface.commit(params) }
                else if method == "ping" { result = [:] }
                else { throw DesktopError.unsupported }
            }
            send(["jsonrpc": "2.0", "id": id, "result": result])
        } catch {
            // No raw UI text, arguments, tickets, paths or arbitrary backend errors in diagnostics.
            send(["jsonrpc": "2.0", "id": id, "error": ["code": -32041, "message": "Native desktop refused or outcome is uncertain; do not retry automatically."]])
        }
    }
    public func start() {
        DispatchQueue.global(qos: .userInitiated).async {
            var buffer = Data()
            let pending = DispatchSemaphore(value: 32)
            while true {
                let chunk = FileHandle.standardInput.availableData
                if chunk.isEmpty { DispatchQueue.main.async { NSApp.terminate(nil) }; return }
                for byte in chunk {
                    if byte == 10 {
                        let line = buffer; buffer.removeAll(keepingCapacity: true)
                        if !line.isEmpty { pending.wait(); DispatchQueue.main.async { defer { pending.signal() }; self.receive(line) } }
                    } else {
                        buffer.append(byte)
                        if buffer.count > 65_536 { DispatchQueue.main.async { NSApp.terminate(nil) }; return }
                    }
                }
            }
        }
    }
}

/// Audit duplicate JSON keys before Foundation parsing (including escaped aliases).
/// Depth and wire limits apply before recursively constructing a Foundation object.
public enum DesktopJSON {
    public static func parse(_ data: Data) throws -> Any {
        guard data.count <= 65_536, String(data: data, encoding: .utf8) != nil else { throw DesktopError.invalid }
        var scan = Scanner(bytes: Array(data)); try scan.value(0); scan.whitespace()
        guard scan.offset == data.count else { throw DesktopError.invalid }
        return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }
    private struct Scanner {
        let bytes: [UInt8]; var offset = 0
        mutating func whitespace() { while offset < bytes.count && [9, 10, 13, 32].contains(bytes[offset]) { offset += 1 } }
        mutating func take(_ b: UInt8) throws { whitespace(); guard offset < bytes.count, bytes[offset] == b else { throw DesktopError.invalid }; offset += 1 }
        mutating func string() throws -> String {
            try take(34); let start = offset - 1
            while offset < bytes.count {
                let b = bytes[offset]; offset += 1
                if b == 92 { guard offset < bytes.count else { throw DesktopError.invalid }; offset += 1 }
                else if b == 34 {
                    guard let text = try JSONSerialization.jsonObject(with: Data(bytes[start..<offset]), options: [.fragmentsAllowed]) as? String else { throw DesktopError.invalid }; return text
                }
            }
            throw DesktopError.invalid
        }
        mutating func value(_ depth: Int) throws {
            guard depth <= 32 else { throw DesktopError.invalid }; whitespace(); guard offset < bytes.count else { throw DesktopError.invalid }
            switch bytes[offset] {
            case 123:
                offset += 1; whitespace(); if offset < bytes.count && bytes[offset] == 125 { offset += 1; return }
                var keys = Set<String>()
                while true {
                    let key = try string(); guard keys.insert(key).inserted else { throw DesktopError.invalid }
                    try take(58); try value(depth + 1); whitespace(); guard offset < bytes.count else { throw DesktopError.invalid }
                    if bytes[offset] == 125 { offset += 1; return }; try take(44)
                }
            case 91:
                offset += 1; whitespace(); if offset < bytes.count && bytes[offset] == 93 { offset += 1; return }
                while true {
                    try value(depth + 1); whitespace(); guard offset < bytes.count else { throw DesktopError.invalid }
                    if bytes[offset] == 93 { offset += 1; return }; try take(44)
                }
            case 34: _ = try string()
            default:
                let start = offset
                while offset < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[offset]) { offset += 1 }
                guard offset > start else { throw DesktopError.invalid }
            }
        }
    }
}
