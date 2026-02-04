//
//  GuardState.swift
//  FarameshGuard
//
//  Shared state and daemon communication
//

import SwiftUI
import Combine
import Network

// MARK: - Models

struct PendingRequest: Identifiable, Codable {
    let id: String
    let actionType: String
    let resource: String
    let agentId: String
    let riskLevel: String
    let riskScore: Double
    let timestamp: Date
    let context: [String: String]?

    var riskColor: Color {
        switch riskLevel {
        case "critical": return .red
        case "high": return .orange
        case "medium": return .yellow
        case "low": return .green
        default: return .gray
        }
    }

    var actionIcon: String {
        switch actionType {
        case "file_read": return "doc.text"
        case "file_write": return "doc.text.fill"
        case "file_delete": return "trash"
        case "shell_execute": return "terminal"
        case "http_request": return "network"
        case "browser_action": return "globe"
        default: return "questionmark.circle"
        }
    }
}

struct AuditEntry: Identifiable, Codable {
    let id: String
    let timestamp: Date
    let actionType: String
    let resource: String
    let agentId: String
    let decision: String
    let decidedBy: String
    let riskScore: Double?
}

struct DaemonStats: Codable {
    let uptime: Int
    let totalRequests: Int
    let approvedRequests: Int
    let deniedRequests: Int
    let pendingRequests: Int
    let cacheHitRate: Double
}

// MARK: - Guard State

@MainActor
class GuardState: ObservableObject {
    static let shared = GuardState()

    // Connection state
    @Published var isConnected = false
    @Published var connectionError: String?

    // Protection state
    @Published var protectionEnabled = true
    @Published var protectionMode: ProtectionMode = .standard

    // Pending approvals
    @Published var pendingRequests: [PendingRequest] = []

    // Audit log
    @Published var auditLog: [AuditEntry] = []

    // Stats
    @Published var stats: DaemonStats?

    // Settings
    @AppStorage("autoApproveEnabled") var autoApproveEnabled = false
    @AppStorage("notificationsEnabled") var notificationsEnabled = true
    @AppStorage("soundEnabled") var soundEnabled = true
    @AppStorage("daemonHost") var daemonHost = "127.0.0.1"
    @AppStorage("daemonPort") var daemonPort = 8765

    private var webSocketTask: URLSessionWebSocketTask?
    private var reconnectTimer: Timer?

    enum ProtectionMode: String, CaseIterable {
        case permissive = "Permissive"
        case standard = "Standard"
        case strict = "Strict"
        case lockdown = "Lockdown"

        var description: String {
            switch self {
            case .permissive: return "Allow most actions, ask for high risk"
            case .standard: return "Balanced protection with smart approvals"
            case .strict: return "Ask for all non-trivial actions"
            case .lockdown: return "Deny everything not explicitly allowed"
            }
        }

        var icon: String {
            switch self {
            case .permissive: return "shield"
            case .standard: return "shield.checkmark"
            case .strict: return "shield.fill"
            case .lockdown: return "lock.shield"
            }
        }
    }

    private init() {}

    // MARK: - Daemon Communication

    func connectToDaemon() async {
        let urlString = "ws://\(daemonHost):\(daemonPort)/ws"
        guard let url = URL(string: urlString) else {
            connectionError = "Invalid daemon URL"
            return
        }

        let session = URLSession(configuration: .default)
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()

        isConnected = true
        connectionError = nil

        // Start receiving messages
        await receiveMessages()

        // Fetch initial state
        await fetchStats()
        await fetchPendingRequests()
        await fetchAuditLog()
    }

    func disconnect() {
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        isConnected = false
    }

    private func receiveMessages() async {
        guard let task = webSocketTask else { return }

        do {
            let message = try await task.receive()
            switch message {
            case .string(let text):
                handleMessage(text)
            case .data(let data):
                if let text = String(data: data, encoding: .utf8) {
                    handleMessage(text)
                }
            @unknown default:
                break
            }

            // Continue receiving
            await receiveMessages()
        } catch {
            isConnected = false
            connectionError = error.localizedDescription
            scheduleReconnect()
        }
    }

    private func handleMessage(_ text: String) {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String else { return }

        switch type {
        case "pending_request":
            if let requestData = json["data"] as? [String: Any] {
                handleNewPendingRequest(requestData)
            }
        case "request_resolved":
            if let requestId = json["request_id"] as? String {
                pendingRequests.removeAll { $0.id == requestId }
            }
        case "stats_update":
            if let statsData = json["data"] as? [String: Any] {
                // Update stats
            }
        default:
            break
        }
    }

    private func handleNewPendingRequest(_ data: [String: Any]) {
        // Parse and add to pending requests
        if let id = data["id"] as? String,
           let actionType = data["action_type"] as? String,
           let resource = data["resource"] as? String,
           let agentId = data["agent_id"] as? String {

            let request = PendingRequest(
                id: id,
                actionType: actionType,
                resource: resource,
                agentId: agentId,
                riskLevel: data["risk_level"] as? String ?? "medium",
                riskScore: data["risk_score"] as? Double ?? 0.5,
                timestamp: Date(),
                context: data["context"] as? [String: String]
            )

            pendingRequests.insert(request, at: 0)

            // Show notification
            if notificationsEnabled {
                showNotification(for: request)
            }
        }
    }

    private func scheduleReconnect() {
        reconnectTimer?.invalidate()
        reconnectTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: false) { [weak self] _ in
            Task { @MainActor in
                await self?.connectToDaemon()
            }
        }
    }

    // MARK: - API Calls

    func fetchStats() async {
        guard let url = URL(string: "http://\(daemonHost):\(daemonPort)/stats") else { return }

        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            stats = try JSONDecoder().decode(DaemonStats.self, from: data)
        } catch {
            print("Failed to fetch stats: \(error)")
        }
    }

    func fetchPendingRequests() async {
        guard let url = URL(string: "http://\(daemonHost):\(daemonPort)/pending") else { return }

        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            pendingRequests = try JSONDecoder().decode([PendingRequest].self, from: data)
        } catch {
            print("Failed to fetch pending requests: \(error)")
        }
    }

    func fetchAuditLog(limit: Int = 100) async {
        guard let url = URL(string: "http://\(daemonHost):\(daemonPort)/audit?limit=\(limit)") else { return }

        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            auditLog = try JSONDecoder().decode([AuditEntry].self, from: data)
        } catch {
            print("Failed to fetch audit log: \(error)")
        }
    }

    func approveRequest(requestId: String, remember: Bool = false) async {
        await resolveRequest(requestId: requestId, decision: "allow", remember: remember)
    }

    func denyRequest(requestId: String, remember: Bool = false) async {
        await resolveRequest(requestId: requestId, decision: "deny", remember: remember)
    }

    private func resolveRequest(requestId: String, decision: String, remember: Bool) async {
        guard let url = URL(string: "http://\(daemonHost):\(daemonPort)/resolve") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "request_id": requestId,
            "decision": decision,
            "remember": remember
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        do {
            let _ = try await URLSession.shared.data(for: request)
            pendingRequests.removeAll { $0.id == requestId }
        } catch {
            print("Failed to resolve request: \(error)")
        }
    }

    func setProtectionMode(_ mode: ProtectionMode) async {
        guard let url = URL(string: "http://\(daemonHost):\(daemonPort)/protection/mode") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["mode": mode.rawValue.lowercased()])

        do {
            let _ = try await URLSession.shared.data(for: request)
            protectionMode = mode
        } catch {
            print("Failed to set protection mode: \(error)")
        }
    }

    func toggleProtection() async {
        protectionEnabled.toggle()

        guard let url = URL(string: "http://\(daemonHost):\(daemonPort)/protection/\(protectionEnabled ? "enable" : "disable")") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"

        do {
            let _ = try await URLSession.shared.data(for: request)
        } catch {
            print("Failed to toggle protection: \(error)")
            protectionEnabled.toggle() // Revert on failure
        }
    }

    // MARK: - Notifications

    private func showNotification(for request: PendingRequest) {
        let content = UNMutableNotificationContent()
        content.title = "Action Approval Required"
        content.subtitle = "\(request.actionType.replacingOccurrences(of: "_", with: " ").capitalized)"
        content.body = request.resource
        content.sound = soundEnabled ? .default : nil
        content.categoryIdentifier = "APPROVAL_CATEGORY"

        // Add action buttons
        let approveAction = UNNotificationAction(identifier: "APPROVE_ACTION", title: "Approve", options: [])
        let denyAction = UNNotificationAction(identifier: "DENY_ACTION", title: "Deny", options: [.destructive])
        let category = UNNotificationCategory(identifier: "APPROVAL_CATEGORY", actions: [approveAction, denyAction], intentIdentifiers: [])

        UNUserNotificationCenter.current().setNotificationCategories([category])

        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 0.1, repeats: false)
        let notificationRequest = UNNotificationRequest(identifier: request.id, content: content, trigger: trigger)

        UNUserNotificationCenter.current().add(notificationRequest)
    }
}
