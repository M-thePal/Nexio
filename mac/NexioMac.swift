// Nexio — receives OTP codes from the Android companion app, copies them to the
// clipboard and shows a macOS notification.
//
// Two transports carry the same encrypted frame (duplicates are dropped):
//  - LAN: TCP on port 47800, advertised over Bonjour, one line per connection.
//  - Relay: an ntfy server (default https://ntfy.sh) for when the phone and Mac are on
//    different networks. The topic is derived from the pairing code; the relay only sees ciphertext.
//
// Frame: base64(iv[12] || ciphertext || tag[16]),
// AES-256-GCM with key = SHA256(pairing code). Plaintext is JSON:
// {"code": "123456", "sender": "Bank", "ts": <epoch ms>}

import AppKit
import CryptoKit
import Foundation
import Network
import UserNotifications

let port: NWEndpoint.Port = 47800
let serviceType = "_nexio._tcp"
let maxClockSkew: Double = 120          // seconds
let clipboardClearDelay: Double = 90    // seconds

let supportDir = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/Nexio")
let pairFile = supportDir.appendingPathComponent("pairing-code")
let relayFile = supportDir.appendingPathComponent("relay")
let defaultRelay = "https://ntfy.sh"

func log(_ s: String) {
    let f = ISO8601DateFormatter()
    print("[\(f.string(from: Date()))] \(s)")
    fflush(stdout)
}

// MARK: - Pairing code

func generatePairingCode() -> String {
    let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
    var chars: [Character] = []
    var rng = SystemRandomNumberGenerator()
    for i in 0..<16 {
        if i > 0 && i % 4 == 0 { chars.append("-") }
        chars.append(alphabet[Int(rng.next(upperBound: UInt32(alphabet.count)))])
    }
    return String(chars)
}

func loadOrCreatePairingCode(reset: Bool) throws -> String {
    try FileManager.default.createDirectory(at: supportDir, withIntermediateDirectories: true)
    if !reset, let s = try? String(contentsOf: pairFile, encoding: .utf8) {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if !t.isEmpty { return t }
    }
    let code = generatePairingCode()
    try code.write(to: pairFile, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pairFile.path)
    return code
}

func normalize(_ pairing: String) -> String {
    pairing.uppercased().filter { $0.isASCII && ($0.isLetter || $0.isNumber) }
}

func deriveKey(_ pairing: String) -> SymmetricKey {
    SymmetricKey(data: SHA256.hash(data: Data(normalize(pairing).utf8)))
}

func relayTopic(_ pairing: String) -> String {
    let hash = SHA256.hash(data: Data(("nexio-topic:" + normalize(pairing)).utf8))
    return "nexio-" + hash.map { String(format: "%02x", $0) }.joined().prefix(32)
}

func relayBase() -> String {
    let s = (try? String(contentsOf: relayFile, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return (s.isEmpty ? defaultRelay : s).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
}

// MARK: - Output

func copyToClipboard(_ code: String) {
    let pb = NSPasteboard.general
    pb.clearContents()
    pb.setString(code, forType: .string)
    let count = pb.changeCount
    DispatchQueue.main.asyncAfter(deadline: .now() + clipboardClearDelay) {
        // Only clear if nothing else was copied in the meantime.
        if pb.changeCount == count { pb.clearContents() }
    }
}

/// Uses UserNotifications (shows the Nexio icon) when running from Nexio.app,
/// otherwise falls back to AppleScript notifications.
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()
    private var useUN: Bool { Bundle.main.bundleIdentifier != nil }

    func setUp() {
        guard useUN else { return }
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound]) { granted, err in
            if !granted { log("notifications not allowed (\(err?.localizedDescription ?? "denied")) — enable Nexio in System Settings › Notifications") }
        }
    }

    func notify(code: String, sender: String) {
        let from = sender.isEmpty ? "unknown" : sender
        guard useUN else { return notifyViaAppleScript(code: code, sender: from) }
        let content = UNMutableNotificationContent()
        content.title = code
        content.subtitle = "From \(from)"
        content.body = "Copied to clipboard"
        content.sound = .default
        content.interruptionLevel = .timeSensitive
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { err in
            if let err { log("notification failed: \(err.localizedDescription)") }
        }
    }

    func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification,
                                withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .list, .sound])
    }

    private func notifyViaAppleScript(code: String, sender: String) {
        let script = """
        on run argv
            display notification ("Copied to clipboard") with title ("🔑 " & item 1 of argv) subtitle ("From " & item 2 of argv) sound name "Glass"
        end run
        """
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", script, code, sender]
        try? p.run()
    }
}

// MARK: - Server

struct Payload: Decodable {
    let code: String
    let sender: String?
    let ts: Double
}

final class Server {
    let key: SymmetricKey
    var seen: [String: Date] = [:]   // replay protection
    var listener: NWListener!

    init(key: SymmetricKey) { self.key = key }

    func start() throws {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        listener = try NWListener(using: params, on: port)
        listener.service = NWListener.Service(name: Host.current().localizedName ?? "Mac", type: serviceType)
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready: log("listening on port \(port), advertising \(serviceType)")
            case .failed(let e): log("listener failed: \(e)"); exit(1)
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] conn in self?.handle(conn) }
        listener.start(queue: .main)
    }

    func handle(_ conn: NWConnection) {
        conn.start(queue: .main)
        var buffer = Data()
        func receive() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, done, err in
                guard let self else { return }
                if let data { buffer.append(data) }
                if buffer.count > 16_384 { conn.cancel(); return }
                if let nl = buffer.firstIndex(of: 0x0A) {
                    let line = String(data: buffer[..<nl], encoding: .utf8) ?? ""
                    let ok = self.process(line, from: "\(conn.endpoint)")
                    conn.send(content: Data((ok ? "OK\n" : "ERR\n").utf8), completion: .contentProcessed { _ in conn.cancel() })
                } else if done || err != nil {
                    conn.cancel()
                } else {
                    receive()
                }
            }
        }
        receive()
    }

    func process(_ frame: String, from: String) -> Bool {
        let b64 = frame.trimmingCharacters(in: .whitespacesAndNewlines)
        if b64 == "PING" { return true }
        guard let raw = Data(base64Encoded: b64) else { log("bad frame from \(from)"); return false }

        guard let box = try? AES.GCM.SealedBox(combined: raw),
              let plain = try? AES.GCM.open(box, using: key) else {
            log("decryption failed from \(from) — pairing code mismatch?")
            return false
        }
        guard let p = try? JSONDecoder().decode(Payload.self, from: plain) else { return false }

        let now = Date()
        if abs(now.timeIntervalSince1970 - p.ts / 1000) > maxClockSkew { log("stale message rejected"); return false }
        seen = seen.filter { now.timeIntervalSince($0.value) < maxClockSkew * 2 }
        if seen[b64] != nil { return true }   // already handled via the other transport
        seen[b64] = now

        let code = String(p.code.filter { $0.isASCII && ($0.isNumber || $0.isLetter) }.prefix(12))
        guard !code.isEmpty else { return false }
        log("code received from \(p.sender ?? "?") via \(from)")
        copyToClipboard(code)
        Notifier.shared.notify(code: code, sender: p.sender ?? "")
        return true
    }
}

// MARK: - Relay

/// Subscribes to the ntfy topic as a long-lived JSON stream and reconnects on failure or network change.
final class RelaySubscriber: NSObject, URLSessionDataDelegate {
    let base: String
    let topic: String
    let onFrame: (String) -> Void
    private var session: URLSession!
    private var task: URLSessionDataTask?
    private var buffer = Data()
    private var lastId: String?
    private var backoff: Double = 1
    private let pathMonitor = NWPathMonitor()

    init(base: String, topic: String, onFrame: @escaping (String) -> Void) {
        self.base = base
        self.topic = topic
        self.onFrame = onFrame
    }

    func start() {
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 90          // ntfy sends keepalives every ~45s
        cfg.timeoutIntervalForResource = 60 * 60 * 24 * 365
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: .main)
        pathMonitor.pathUpdateHandler = { [weak self] path in
            // New network (Wi-Fi switch, VPN on/off): the old stream is likely dead, reconnect now.
            guard path.status == .satisfied else { return }
            DispatchQueue.main.async { self?.reconnect(after: 0.5) }
        }
        pathMonitor.start(queue: .main)
        connect()
    }

    private func connect() {
        // `since` replays anything published while we were disconnected (stale ones are rejected later).
        let since = lastId ?? "2m"
        guard let url = URL(string: "\(base)/\(topic)/json?since=\(since)") else { log("bad relay url"); return }
        buffer.removeAll()
        task = session.dataTask(with: url)
        task?.resume()
    }

    private func reconnect(after delay: Double) {
        task?.cancel()
        task = nil
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self, self.task == nil else { return }
            self.connect()
        }
    }

    func urlSession(_ s: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard dataTask == task else { return }
        buffer.append(data)
        while let nl = buffer.firstIndex(of: 0x0A) {
            let line = buffer[..<nl]
            buffer.removeSubrange(...nl)
            guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
                  let event = obj["event"] as? String else { continue }
            if event == "open" {
                backoff = 1
                log("relay connected (\(base))")
            } else if event == "message", let msg = obj["message"] as? String {
                if let id = obj["id"] as? String { lastId = id }
                onFrame(msg)
            }
        }
    }

    func urlSession(_ s: URLSession, task t: URLSessionTask, didCompleteWithError error: Error?) {
        guard t == task else { return }
        log("relay disconnected: \(error?.localizedDescription ?? "closed"), retrying in \(Int(backoff))s")
        task = nil
        let delay = backoff
        backoff = min(backoff * 2, 30)
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self, self.task == nil else { return }
            self.connect()
        }
    }
}

// MARK: - Main

let args = CommandLine.arguments.dropFirst()
do {
    if args.first == "pair" {
        print(try loadOrCreatePairingCode(reset: args.contains("--reset")))
        exit(0)
    }
    let code = try loadOrCreatePairingCode(reset: false)
    log("pairing code: \(code)")
    Notifier.shared.setUp()
    let server = Server(key: deriveKey(code))
    try server.start()
    let relay = RelaySubscriber(base: relayBase(), topic: relayTopic(code)) { frame in
        _ = server.process(frame, from: "relay")
    }
    relay.start()
    dispatchMain()
} catch {
    log("fatal: \(error)")
    exit(1)
}
