import AppKit
#if canImport(WardenDesktop)
import WardenDesktop
#endif

#if WARDEN_DESKTOP_TESTS
@MainActor final class TestApplication: NSApplication {
    var interceptActions = false
    var interceptedActions = 0
    override func sendAction(_ action: Selector, to target: Any?, from sender: Any?) -> Bool {
        if interceptActions { interceptedActions += 1; return true }
        return super.sendAction(action, to: target, from: sender)
    }
}
@MainActor final class RaceButton: NSButton {
    var onHit: (() -> Void)?
    override func hitTest(_ point: NSPoint) -> NSView? { onHit?(); return super.hitTest(point) }
}
#endif

@MainActor final class DemoOwner: NSObject {
    var count = 0
    var buttons: [NSButton] = []
    var window: NSWindow!
    var surface: WardenDesktopSurface!
    var clockOffset = 0.0
    var uptimeOffset: UInt64 = 0
    #if WARDEN_DESKTOP_TESTS
    var clockReads = 0
    var invalidateOnClockRead = 0
    var clockRaceTriggered = false
    var auxiliaryWindows: [NSWindow] = []
    var nestedCommit: [String: Any]?
    var reentrantRefused = false
    #endif
    var raceBeforeCommit = false
    var hitRaceTriggered = false
    @objc func pressed(_ sender: NSButton) {
        precondition(Thread.isMainThread)
        count += 1
        #if WARDEN_DESKTOP_TESTS
        if let params = nestedCommit {
            nestedCommit = nil
            let receipt = try? surface.commit(params)
            var readRefused = false, invalidateRefused = false
            do { _ = try surface.read() } catch { readRefused = true }
            do { try surface.invalidate() } catch { invalidateRefused = true }
            reentrantRefused = receipt?["status"] as? String == "refused" && readRefused && invalidateRefused
        }
        #endif
        sender.title = "Pressed \(count)"
    }
    @objc func alternate(_ sender: NSButton) { count += 100 }
    #if WARDEN_DESKTOP_TESTS
    @objc func invalidAction(_ sender: NSButton) -> String { "not a void action" }
    @objc func blockAction(_ sender: @convention(block) () -> Void) { count += 1000 }
    #endif
    func monotonicClock() -> UInt64 {
        #if WARDEN_DESKTOP_TESTS
        if invalidateOnClockRead > 0 {
            clockReads += 1
            if clockReads == invalidateOnClockRead {
                clockRaceTriggered = true
                try? surface.invalidate(); buttons[0].tag += 1
            }
        }
        #endif
        return DispatchTime.now().uptimeNanoseconds + uptimeOffset
    }
    func start() throws {
        window = NSWindow(contentRect: NSRect(x: 40, y: 80, width: 340, height: 160), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "WARDEN native test — local only"
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        #if WARDEN_DESKTOP_TESTS
        let button = RaceButton(title: "Local action", target: self, action: #selector(pressed(_:)))
        #else
        let button = NSButton(title: "Local action", target: self, action: #selector(pressed(_:)))
        #endif
        button.setAccessibilityElement(true); button.setAccessibilityRole(.button)
        button.setButtonType(.momentaryPushIn); button.setAccessibilityIdentifier("warden.demo.local-action")
        button.frame = NSRect(x: 30, y: 55, width: 180, height: 36)
        window.contentView!.addSubview(button); buttons = [button]
        window.orderFront(nil) // Never activate another app or generate global input.
        surface = try WardenDesktopSurface(window: window, applicationID: "dev.warden.macos.demo", now: { [weak self] in Date().timeIntervalSince1970 * 1000 + (self?.clockOffset ?? 0) }, uptime: { [weak self] in self?.monotonicClock() ?? DispatchTime.now().uptimeNanoseconds })
        try surface.register(id: "3", button: button, target: self, selector: #selector(pressed(_:)))
    }
    #if WARDEN_DESKTOP_TESTS
    func presentSheet() -> [String: Any] {
        let sheet = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 200, height: 80), styleMask: [.titled], backing: .buffered, defer: false)
        sheet.isReleasedWhenClosed = false; sheet.isRestorable = false
        auxiliaryWindows.append(sheet); window.beginSheet(sheet)
        return ["sheets": window.sheets.count, "attached": window.attachedSheet != nil, "logicalParent": sheet.sheetParent != nil, "knownSheet": NSApp.windows.contains(where: { $0 === sheet })]
    }
    func testRequest(_ method: String, _ params: [String: Any]) throws -> [String: Any]? {
        if method == "test/clock-race" {
            clockReads = 0; invalidateOnClockRead = params["at"] as? Int ?? 2
            return [:]
        }
        if method == "test/clock-stats" { return ["triggered": clockRaceTriggered] }
        if method == "test/intercept-dispatch" { (NSApp as! TestApplication).interceptActions = true; return [:] }
        if method == "test/dispatch-stats" { return ["intercepted": (NSApp as! TestApplication).interceptedActions] }
        if method == "test/arm-reentrant" { nestedCommit = params; return [:] }
        if method == "test/invalid-registration" {
            let button = NSButton(title: "Not registered", target: self, action: #selector(invalidAction(_:)))
            if params["kind"] as? String == "block" { button.action = #selector(blockAction(_:)) }
            button.setAccessibilityElement(true); button.setAccessibilityRole(.button); button.setButtonType(.momentaryPushIn)
            button.setAccessibilityIdentifier("warden.demo.invalid-signature"); button.frame = NSRect(x: 230, y: 10, width: 80, height: 30); window.contentView!.addSubview(button)
            defer { button.removeFromSuperview() }
            do { try surface.register(id: "4", button: button, target: self, selector: button.action!); return ["refused": false] }
            catch { return ["refused": true] }
        }
        if method == "warden/screen/commit" && raceBeforeCommit { try surface.invalidate(); raceBeforeCommit = false; return try surface.commit(params) }
        if method == "test/stats" { return ["count": count, "mainThread": Thread.isMainThread, "windowVisible": window.isVisible, "hitRaceTriggered": hitRaceTriggered, "reentrantRefused": reentrantRefused, "pid": ProcessInfo.processInfo.processIdentifier] }
        guard method == "test/change", let kind = params["kind"] as? String else { return nil }
        if kind == "race-before-commit" { raceBeforeCommit = true; return [:] }
        if kind == "monotonic-expiry" { uptimeOffset += 300_001_000_000; return [:] }
        if kind == "expiry" { clockOffset += 300_001; return [:] }
        if kind == "rollback" { clockOffset -= 1000; return [:] }
        if kind == "untracked-sheet" { return presentSheet() }
        if kind == "untracked-ancestor-alpha" { window.contentView!.alphaValue = 0; return [:] }
        if kind == "untracked-partial-alpha" { buttons[0].alphaValue = 0.5; return [:] }
        if kind == "untracked-implementation" {
            guard let a = class_getInstanceMethod(DemoOwner.self, #selector(pressed(_:))), let b = class_getInstanceMethod(DemoOwner.self, #selector(alternate(_:))) else { throw DesktopError.invalid }
            method_exchangeImplementations(a, b); return [:]
        }
        if kind == "untracked-button-alpha" { buttons[0].alphaValue = 0; return [:] }
        if kind == "untracked-window-alpha" { window.alphaValue = 0; return [:] }
        if kind == "untracked-title" { buttons[0].title = "Untracked change"; return [:] }
        if kind.hasPrefix("hit-untracked-") {
            (buttons[0] as! RaceButton).onHit = { [weak self] in
                guard let s = self, !s.hitRaceTriggered else { return }
                s.hitRaceTriggered = true
                switch kind {
                case "hit-untracked-sheet": _ = s.presentSheet()
                case "hit-untracked-button-alpha": s.buttons[0].alphaValue = 0
                case "hit-untracked-window-alpha": s.window.alphaValue = 0
                case "hit-untracked-handler": s.buttons[0].action = #selector(DemoOwner.alternate(_:))
                case "hit-untracked-title": s.buttons[0].title = "Different outcome"
                case "hit-untracked-disabled": s.buttons[0].isEnabled = false
                case "hit-untracked-bounds": s.buttons[0].frame.origin.x += 5
                case "hit-untracked-expiry": s.clockOffset += 300_001
                case "hit-untracked-monotonic-expiry": s.uptimeOffset += 300_001_000_000
                default: break
                }
            }
            return [:]
        }
        if kind == "hit-test-mutation" {
            (buttons[0] as! RaceButton).onHit = { [weak self] in
                guard let s = self, !s.hitRaceTriggered else { return }
                s.hitRaceTriggered = true; try? s.surface.invalidate(); s.buttons[0].tag += 1
            }
            return [:]
        }
        if kind == "replace-object" {
            try surface.invalidate()
            let old = buttons[0], replacement = NSButton(title: old.title, target: self, action: #selector(pressed(_:)))
            replacement.setAccessibilityElement(true); replacement.setAccessibilityRole(.button)
            replacement.setButtonType(.momentaryPushIn); replacement.frame = old.frame; replacement.setAccessibilityIdentifier(old.accessibilityIdentifier())
            old.removeFromSuperview(); window.contentView!.addSubview(replacement); return [:]
        }
        try surface.invalidate() // BEFORE every controlled mutation, including ABA/semantics.
        switch kind {
        case "aba", "semantic": break
        case "title": buttons[0].title = "Other action"
        case "unicode": buttons[0].title = "Отправить / 发送 / Envoyer"; window.title = "WARDEN — проверка 发送"
        case "identity": buttons[0].setAccessibilityIdentifier("warden.demo.changed")
        case "handler": buttons[0].action = #selector(alternate(_:))
        case "bounds": buttons[0].frame.origin.x += 5
        case "window": window.title = "Changed native window"
        case "disabled": buttons[0].isEnabled = false
        case "hidden": buttons[0].isHidden = true
        case "close": window.orderOut(nil)
        case "overlay":
            let overlay = NSView(frame: buttons[0].frame); window.contentView!.addSubview(overlay, positioned: .above, relativeTo: buttons[0])
        default: throw DesktopError.invalid
        }
        return [:]
    }
    #endif
}

@main struct WardenDesktopHost {
    @MainActor static func main() {
        // A native reference application, not an agent injected into unrelated applications.
        // The reusable library must be embedded by those applications themselves.
        guard Array(CommandLine.arguments.dropFirst()) == ["--demo"] else {
            FileHandle.standardError.write(Data("Usage: warden-desktop --demo (owned native window only; no external AX/CGEvent dispatch)\n".utf8)); exit(2)
        }
        #if WARDEN_DESKTOP_TESTS
        _ = TestApplication.shared
        precondition(NSApp is TestApplication)
        #else
        _ = NSApplication.shared
        #endif
        NSApp.setActivationPolicy(.accessory)
        let owner = DemoOwner()
        do {
            try owner.start()
            let io = WardenDesktopStandardIO(surface: owner.surface)
            #if WARDEN_DESKTOP_TESTS
            io.extraRequest = { method, params in try owner.testRequest(method, params) }
            #endif
            io.start()
            withExtendedLifetime([owner, io] as [AnyObject]) { NSApp.run() }
        } catch {
            FileHandle.standardError.write(Data("Native desktop unavailable; no action was run.\n".utf8)); exit(3)
        }
    }
}
