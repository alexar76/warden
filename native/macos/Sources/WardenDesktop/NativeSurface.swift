import AppKit
import CryptoKit
import Security
import ObjectiveC

public let wardenAtomicProtocol = "warden.screen.atomic.v1"

public enum DesktopError: Error { case invalid, unavailable, unsupported, uncertain }
private func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
private func digest(_ text: String) -> String { digest(Data(text.utf8)) }
private func opaque() throws -> String {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw DesktopError.unavailable }
    return bytes.map { String(format: "%02x", $0) }.joined()
}
private func json(_ value: Any) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .withoutEscapingSlashes, .sortedKeys])
    guard let result = String(data: data, encoding: .utf8) else { throw DesktopError.invalid }
    return result
}
private func exact(_ value: [String: Any], _ keys: [String]) -> Bool { Set(value.keys) == Set(keys) }
private func hex(_ value: Any?) -> String? {
    guard let s = value as? String, s.count == 64, s.allSatisfy({ "0123456789abcdef".contains($0) }) else { return nil }; return s
}
private func number(_ value: Any?) -> Double? {
    guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue.isFinite, abs(n.doubleValue) <= 1_000_000 else { return nil }
    return n.doubleValue
}
private typealias NativeAction = @convention(c) (AnyObject, Selector, AnyObject) -> Void
private func actionImplementation(_ target: NSObject, _ selector: Selector) -> IMP? {
    guard NSStringFromSelector(selector).filter({ $0 == ":" }).count == 1,
          let method = class_getInstanceMethod(type(of: target), selector), method_getNumberOfArguments(method) == 3 else { return nil }
    var returns = [CChar](repeating: 0, count: 32), argument = [CChar](repeating: 0, count: 32)
    method_getReturnType(method, &returns, returns.count); method_getArgumentType(method, 2, &argument, argument.count)
    // A block (@?) is not an object sender, despite sharing the '@' prefix.
    guard returns[0] == 118 && returns[1] == 0 && argument[0] == 64 && argument[1] == 0 else { return nil } // void action(id sender)
    return method_getImplementation(method)
}

/// Target-side authority. Embed INSIDE the application that owns these AppKit controls.
/// All model/handler changes must run on MainActor and call invalidate BEFORE mutation.
/// This is deliberately not an AXUIElement/CGEvent proxy for other applications.
@MainActor public final class WardenDesktopSurface {
    private struct Binding {
        let button: NSButton
        let target: NSObject
        let selector: Selector
        let implementation: IMP
        let identity: String
    }
    private struct Capture { let observation: [String: Any]; let fingerprint: String; let boxes: [String: CGRect]; let stamps: [String: String] }
    private struct Ticket {
        let revision: String; let stamp: String; let fingerprint: String; let action: String; let target: String
        let expires: Double; let deadline: UInt64
    }
    private let window: NSWindow
    private let applicationID: String
    private var bindings: [String: Binding] = [:]
    private var tickets: [String: Ticket] = [:]
    private var revision: String
    private var poisoned = false
    private var uncertain = false
    private var committing = false
    private var lastFingerprint: String?
    private let now: () -> Double
    private let uptime: () -> UInt64
    private var observers: [NSObjectProtocol] = []
    deinit { for observer in observers { NotificationCenter.default.removeObserver(observer) } }

    public init(window: NSWindow, applicationID: String, now: @escaping () -> Double = { Date().timeIntervalSince1970 * 1000 }, uptime: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }) throws {
        guard !applicationID.isEmpty, applicationID.utf16.count <= 200, !applicationID.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { throw DesktopError.invalid }
        self.window = window; self.applicationID = applicationID; self.revision = try opaque(); self.now = now; self.uptime = uptime
        for event in [NSWindow.didMoveNotification, NSWindow.didResizeNotification, NSWindow.willCloseNotification, NSWindow.willMiniaturizeNotification, NSWindow.didMiniaturizeNotification,
                      NSWindow.willBeginSheetNotification, NSWindow.didEndSheetNotification,
                      NSWindow.didDeminiaturizeNotification, NSWindow.didChangeScreenNotification, NSWindow.didBecomeKeyNotification, NSWindow.didResignKeyNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: event, object: window, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { if let s = self, !s.committing, !s.uncertain { try? s.invalidate() } }
            })
        }
    }

    /// Only explicit, retained action targets; nil/first-responder routing is not supported.
    /// Register momentary push buttons whose synchronous handlers do not pump a nested run loop.
    public func register(id: String, button: NSButton, target: NSObject, selector: Selector) throws {
        guard !committing, !uncertain else { throw DesktopError.unavailable }
        let identity = button.accessibilityIdentifier()
        guard !committing, bindings.count < 64, bindings[id] == nil, id.range(of: "^[A-Za-z0-9_.:-]{1,40}$", options: .regularExpression) != nil,
              button.window === window, button.target === target, button.action == selector,
              !identity.isEmpty, identity.utf16.count <= 200, !identity.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
              !bindings.values.contains(where: { $0.identity == identity || $0.button === button }),
              button.accessibilityRole() == .button,
              let cell = button.cell as? NSButtonCell, cell.showsStateBy.isEmpty,
              let implementation = actionImplementation(target, selector) else { throw DesktopError.unsupported }
        try invalidate()
        bindings[id] = Binding(button: button, target: target, selector: selector, implementation: implementation, identity: identity)
    }

    /// Mandatory for invisible model/recipient/handler changes, even A -> B -> A.
    /// Failure invalidates existing approvals. Does not recover an uncertain effect.
    public func invalidate() throws {
        guard !committing, !uncertain else { throw DesktopError.unavailable }
        poisoned = true; revision = try opaque(); lastFingerprint = nil; poisoned = false
    }

    private func capture() throws -> Capture {
        guard !poisoned, !bindings.isEmpty, window.isVisible, !window.isMiniaturized,
              window.alphaValue.isFinite, window.alphaValue > 0, window.attachedSheet == nil, window.sheets.isEmpty,
              !NSApp.windows.contains(where: { $0.sheetParent === window }),
              NSApp.modalWindow == nil || NSApp.modalWindow === window,
              window.title.utf16.count <= 160, let content = window.contentView else { throw DesktopError.unavailable }
        let top = NSScreen.screens.first?.frame.maxY ?? 0
        var elements: [[String: Any]] = [], boxes: [String: CGRect] = [:], stamps: [String: String] = [:], internals: [[String: Any]] = []
        for id in bindings.keys.sorted() {
            let b = bindings[id]!, button = b.button
            guard button.window === window, button.isDescendant(of: content), !button.isHiddenOrHasHiddenAncestor, button.isEnabled,
                  button.target === b.target, button.action == b.selector, actionImplementation(b.target, b.selector) == b.implementation,
                  button.accessibilityIdentifier() == b.identity, button.accessibilityRole() == .button,
                  (button.cell as? NSButtonCell)?.showsStateBy.isEmpty == true else { throw DesktopError.unavailable }
            guard button.title.utf16.count <= 160 else { throw DesktopError.unavailable }
            var appearance: [[String: Any]] = [], ancestor: NSView? = button
            while let view = ancestor {
                guard appearance.count < 128, view.alphaValue.isFinite, view.alphaValue > 0 else { throw DesktopError.unavailable }
                appearance.append(["view": String(describing: ObjectIdentifier(view)), "alpha": view.alphaValue])
                if view === content { break }
                ancestor = view.superview
            }
            let screen = window.convertToScreen(button.convert(button.bounds, to: nil))
            let box = CGRect(x: screen.minX, y: top - screen.maxY, width: screen.width, height: screen.height)
            guard [box.minX, box.minY, box.width, box.height].allSatisfy({ $0.isFinite && abs($0) <= 1_000_000 }), box.width > 0, box.height > 0 else { throw DesktopError.unavailable }
            let bounds: [String: Any] = ["x": box.minX, "y": box.minY, "width": box.width, "height": box.height]
            elements.append(["index": id, "role": "button", "name": button.title, "accessibilityIdentifier": b.identity, "bounds": bounds])
            boxes[id] = box
            // Match flow-guard-screen.ts screenTargetEvidence exactly; conformance is integration-tested.
            let label = try json([button.title] + Array(repeating: NSNull() as Any, count: 8))
            let geometry = try "{\"x\":\(json(box.minX)),\"y\":\(json(box.minY)),\"width\":\(json(box.width)),\"height\":\(json(box.height))}"
            let stampText = try "{\"target\":\(json(id)),\"role\":\"button\",\"reference\":\(json(digest(id))),\"identity\":\(json(digest(b.identity))),\"bounds\":\(geometry),\"label\":\(json(digest(label))),\"application\":\(json(applicationID)),\"titles\":[\(json(digest(String(window.title.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)))))]}"
            stamps[id] = digest(stampText)
            internals.append(["id": id, "object": String(describing: ObjectIdentifier(button)), "target": String(describing: ObjectIdentifier(b.target)),
                              "selector": NSStringFromSelector(b.selector), "frame": bounds, "title": button.title, "identity": b.identity,
                              "state": button.state.rawValue, "tag": button.tag, "alternateTitle": button.alternateTitle, "appearance": appearance])
        }
        let observation: [String: Any] = ["content": [["type": "text", "text": "Native AppKit controls owned by this application; coordinates are global top-left points, not pixels."]],
            "structuredContent": ["applicationId": applicationID, "windowTitle": window.title, "elements": elements]]
        let state: [String: Any] = ["elements": internals, "window": String(describing: ObjectIdentifier(window)), "windowNumber": window.windowNumber,
                                  "title": window.title, "alpha": window.alphaValue, "modal": NSApp.modalWindow.map { String(describing: ObjectIdentifier($0)) } ?? "",
                                  "key": window.isKeyWindow, "focus": window.firstResponder.map { String(describing: ObjectIdentifier($0)) } ?? ""]
        return Capture(observation: observation, fingerprint: digest(try json(state)), boxes: boxes, stamps: stamps)
    }
    private func fresh() throws -> Capture {
        guard !committing else { throw DesktopError.unavailable }
        do {
            let view = try capture()
            if let before = lastFingerprint, before != view.fingerprint { revision = try opaque() }
            lastFingerprint = view.fingerprint
            return view
        } catch {
            poisoned = true; tickets.removeAll(); throw DesktopError.unavailable
        }
    }
    public func read() throws -> [String: Any] { try fresh().observation }
    private func resolve(_ action: [String: Any], _ view: Capture) throws -> String {
        guard exact(action, ["name", "arguments"]), action["name"] as? String == "click", let args = action["arguments"] as? [String: Any] else { throw DesktopError.unsupported }
        let id: String
        var requestedPoint: CGPoint?
        if exact(args, ["index"]), let ref = args["index"] as? String, bindings[ref] != nil { id = ref }
        else if exact(args, ["x", "y"]), let x = number(args["x"]), let y = number(args["y"]) {
            let hits = view.boxes.filter { $0.value.contains(CGPoint(x: x, y: y)) }
            guard hits.count == 1, let ref = hits.first?.key else { throw DesktopError.unsupported }; id = ref
            requestedPoint = CGPoint(x: x, y: y)
        } else { throw DesktopError.unsupported }
        // Bind visible native hit target too; another view in this window must not cover it.
        let b = bindings[id]!, center = requestedPoint ?? CGPoint(x: view.boxes[id]!.midX, y: view.boxes[id]!.midY)
        let top = NSScreen.screens.first?.frame.maxY ?? 0
        let inWindow = window.convertPoint(fromScreen: CGPoint(x: center.x, y: top - center.y))
        guard let content = window.contentView, let hit = content.hitTest(content.convert(inWindow, from: nil)), hit === b.button || hit.isDescendant(of: b.button) else { throw DesktopError.unavailable }
        return id
    }
    public func prepare(_ params: [String: Any]) throws -> [String: Any] {
        guard exact(params, ["protocol", "observation", "action"]), params["protocol"] as? String == wardenAtomicProtocol,
              let observation = params["observation"] as? [String: Any], exact(observation, ["name", "arguments"]), observation["name"] as? String == "screenshot",
              let args = observation["arguments"] as? [String: Any], args.isEmpty, let action = params["action"] as? [String: Any] else { throw DesktopError.invalid }
        let view = try fresh(), observedRevision = revision, target = try resolve(action, view)
        let final = try fresh()
        guard revision == observedRevision, view.fingerprint == final.fingerprint,
              view.stamps[target] == final.stamps[target] else { throw DesktopError.unavailable }
        let actionText = try json(action), time = now(), monotonic = uptime()
        let (deadline, overflow) = monotonic.addingReportingOverflow(300_000_000_000)
        guard time.isFinite, time >= 0, time <= 9_007_199_254_440_991, !overflow,
              revision == observedRevision, !poisoned, !committing else { throw DesktopError.unavailable }
        tickets = tickets.filter { $0.value.expires > time && $0.value.deadline > monotonic }
        guard tickets.count < 256 else { throw DesktopError.unavailable }
        let ticket = try opaque(), expiry = floor(time + 300_000), stamp = view.stamps[target]!
        tickets[ticket] = Ticket(revision: observedRevision, stamp: stamp, fingerprint: view.fingerprint, action: actionText, target: target, expires: expiry, deadline: deadline)
        return ["protocol": wardenAtomicProtocol, "ticket": ticket, "revision": revision, "stamp": stamp, "expiresAt": expiry, "observation": view.observation]
    }
    public func cancel(_ params: [String: Any]) throws {
        guard exact(params, ["protocol", "ticket"]), params["protocol"] as? String == wardenAtomicProtocol, let ticket = hex(params["ticket"]) else { throw DesktopError.invalid }
        tickets.removeValue(forKey: ticket)
    }
    public func commit(_ params: [String: Any]) throws -> [String: Any] {
        guard exact(params, ["protocol", "ticket", "expected", "action"]), params["protocol"] as? String == wardenAtomicProtocol,
              let ticket = hex(params["ticket"]), let expected = params["expected"] as? [String: Any], exact(expected, ["revision", "stamp"]),
              let expectedRevision = hex(expected["revision"]), let stamp = hex(expected["stamp"]), let action = params["action"] as? [String: Any] else { throw DesktopError.invalid }
        func refused(_ reason: String) -> [String: Any] { ["protocol": wardenAtomicProtocol, "status": "refused", "reason": reason] }
        guard let approved = tickets.removeValue(forKey: ticket) else { return refused("unknown") }
        guard !poisoned, !committing else { return refused("unavailable") }
        let admissionTime = now()
        guard admissionTime < approved.expires, admissionTime >= approved.expires - 300_000, uptime() < approved.deadline else { return refused("expired") }
        guard expectedRevision == approved.revision, stamp == approved.stamp, try json(action) == approved.action else { return refused("mismatch") }
        let view: Capture
        do { view = try fresh() } catch { return refused("unavailable") }
        guard revision == approved.revision, view.fingerprint == approved.fingerprint, view.stamps[approved.target] == approved.stamp else { return refused("stale") }
        guard (try? resolve(action, view)) == approved.target, revision == approved.revision, !poisoned,
              let b = bindings[approved.target] else { return refused("stale") }
        // hitTest is overridable AppKit code. Do not rely solely on the host's
        // invalidation callback: visible properties/handler may have changed there.
        let final: Capture
        do { final = try fresh() } catch { return refused("unavailable") }
        guard revision == approved.revision, final.fingerprint == approved.fingerprint,
              final.stamps[approved.target] == approved.stamp else { return refused("stale") }
        // Validation itself may take time. Check both clocks at the dispatch boundary.
        // Allocate the receipt revision before any effect; entropy failure must not
        // escape as an ordinary unavailable error after a successful handler.
        let committedRevision = try opaque()
        let dispatchTime = now()
        guard dispatchTime < approved.expires, dispatchTime >= approved.expires - 300_000,
              uptime() < approved.deadline else { return refused("expired") }
        // Clock providers are injected host callbacks too. No callbacks may run
        // after this final CAS and before the pinned implementation invocation.
        guard revision == approved.revision, !poisoned, !committing else { return refused("stale") }
        // Linearization point in the TARGET APPLICATION's main run loop. No AX RPC,
        // CGEvent, performClick animation, await, timer or queued coordinate dispatch.
        committing = true
        defer { committing = false }
        uncertain = true; poisoned = true
        // NSApplication.sendAction is overridable and may reroute/queue or report
        // success without invoking this method. Call the checked, retained IMP.
        let invoke = unsafeBitCast(b.implementation, to: NativeAction.self)
        invoke(b.target, b.selector, b.button)
        revision = committedRevision; lastFingerprint = nil
        // A receipt attests local handler dispatch, never remote payment/mail completion.
        poisoned = false; uncertain = false
        return ["protocol": wardenAtomicProtocol, "status": "committed", "revisionBefore": approved.revision, "revisionAfter": revision, "stamp": stamp,
                "result": ["content": [["type": "text", "text": "Native AppKit action dispatched synchronously to the approved button target. External outcomes require reconciliation."]]]]
    }
}
