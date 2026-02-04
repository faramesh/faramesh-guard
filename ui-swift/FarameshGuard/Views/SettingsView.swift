//
//  SettingsView.swift
//  FarameshGuard
//
//  Native macOS settings panel
//

import SwiftUI
import ServiceManagement

struct SettingsView: View {
    @EnvironmentObject var guardState: GuardState

    var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem {
                    Label("General", systemImage: "gear")
                }
                .environmentObject(guardState)

            NotificationSettingsView()
                .tabItem {
                    Label("Notifications", systemImage: "bell")
                }
                .environmentObject(guardState)

            ConnectionSettingsView()
                .tabItem {
                    Label("Connection", systemImage: "network")
                }
                .environmentObject(guardState)

            SecuritySettingsView()
                .tabItem {
                    Label("Security", systemImage: "lock.shield")
                }
                .environmentObject(guardState)

            AdvancedSettingsView()
                .tabItem {
                    Label("Advanced", systemImage: "wrench.and.screwdriver")
                }
                .environmentObject(guardState)
        }
        .frame(width: 500, height: 400)
    }
}

// MARK: - General Settings

struct GeneralSettingsView: View {
    @EnvironmentObject var guardState: GuardState
    @AppStorage("launchAtLogin") private var launchAtLogin = true
    @AppStorage("showInDock") private var showInDock = false
    @AppStorage("autoApproveEnabled") private var autoApproveEnabled = false

    var body: some View {
        Form {
            Section {
                Toggle("Launch at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, newValue in
                        setLaunchAtLogin(newValue)
                    }

                Toggle("Show in Dock", isOn: $showInDock)
                    .onChange(of: showInDock) { _, newValue in
                        NSApp.setActivationPolicy(newValue ? .regular : .accessory)
                    }
            } header: {
                Text("Startup")
            }

            Section {
                Picker("Default Protection Mode", selection: Binding(
                    get: { guardState.protectionMode },
                    set: { mode in
                        Task { await guardState.setProtectionMode(mode) }
                    }
                )) {
                    ForEach(GuardState.ProtectionMode.allCases, id: \.self) { mode in
                        HStack {
                            Image(systemName: mode.icon)
                            VStack(alignment: .leading) {
                                Text(mode.rawValue)
                                Text(mode.description)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .tag(mode)
                    }
                }
            } header: {
                Text("Protection")
            }

            Section {
                Toggle("Enable auto-approve for trusted patterns", isOn: $autoApproveEnabled)

                if autoApproveEnabled {
                    Text("Actions matching learned patterns will be approved automatically.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } header: {
                Text("Auto-Approval")
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    private func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            print("Failed to set launch at login: \(error)")
        }
    }
}

// MARK: - Notification Settings

struct NotificationSettingsView: View {
    @EnvironmentObject var guardState: GuardState
    @AppStorage("notificationsEnabled") private var notificationsEnabled = true
    @AppStorage("soundEnabled") private var soundEnabled = true
    @AppStorage("criticalAlertsEnabled") private var criticalAlertsEnabled = true
    @AppStorage("notifyOnApprove") private var notifyOnApprove = false
    @AppStorage("notifyOnDeny") private var notifyOnDeny = true

    var body: some View {
        Form {
            Section {
                Toggle("Enable notifications", isOn: $notificationsEnabled)

                if notificationsEnabled {
                    Toggle("Play sound", isOn: $soundEnabled)
                    Toggle("Critical alerts for high-risk actions", isOn: $criticalAlertsEnabled)
                }
            } header: {
                Text("Notifications")
            }

            if notificationsEnabled {
                Section {
                    Toggle("When action is approved", isOn: $notifyOnApprove)
                    Toggle("When action is denied", isOn: $notifyOnDeny)
                } header: {
                    Text("Notify me")
                }
            }

            Section {
                Button("Request Notification Permission") {
                    requestNotificationPermission()
                }

                Button("Open System Notification Settings") {
                    openSystemNotificationSettings()
                }
            } header: {
                Text("System")
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    private func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if granted {
                print("Permission granted")
            }
        }
    }

    private func openSystemNotificationSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.notifications") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - Connection Settings

struct ConnectionSettingsView: View {
    @EnvironmentObject var guardState: GuardState
    @AppStorage("daemonHost") private var daemonHost = "127.0.0.1"
    @AppStorage("daemonPort") private var daemonPort = 8765
    @State private var isTestingConnection = false
    @State private var connectionTestResult: String?

    var body: some View {
        Form {
            Section {
                HStack {
                    Circle()
                        .fill(guardState.isConnected ? Color.green : Color.red)
                        .frame(width: 10, height: 10)

                    Text(guardState.isConnected ? "Connected to daemon" : "Disconnected")

                    Spacer()

                    if !guardState.isConnected {
                        Button("Reconnect") {
                            Task {
                                await guardState.connectToDaemon()
                            }
                        }
                    }
                }

                if let error = guardState.connectionError {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            } header: {
                Text("Status")
            }

            Section {
                TextField("Host", text: $daemonHost)
                    .textFieldStyle(.roundedBorder)

                TextField("Port", value: $daemonPort, formatter: NumberFormatter())
                    .textFieldStyle(.roundedBorder)

                HStack {
                    Button("Test Connection") {
                        testConnection()
                    }
                    .disabled(isTestingConnection)

                    if isTestingConnection {
                        ProgressView()
                            .scaleEffect(0.7)
                    }

                    if let result = connectionTestResult {
                        Text(result)
                            .font(.caption)
                            .foregroundColor(result.contains("✓") ? .green : .red)
                    }
                }
            } header: {
                Text("Daemon")
            }

            Section {
                Text("The daemon runs locally and handles all security decisions.")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Button("View Daemon Logs") {
                    openDaemonLogs()
                }
            } header: {
                Text("Help")
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    private func testConnection() {
        isTestingConnection = true
        connectionTestResult = nil

        Task {
            do {
                let url = URL(string: "http://\(daemonHost):\(daemonPort)/health")!
                let (_, response) = try await URLSession.shared.data(from: url)

                if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 {
                    connectionTestResult = "✓ Connection successful"
                } else {
                    connectionTestResult = "✗ Invalid response"
                }
            } catch {
                connectionTestResult = "✗ \(error.localizedDescription)"
            }

            isTestingConnection = false
        }
    }

    private func openDaemonLogs() {
        let logPath = "/var/log/faramesh-guard/daemon.log"
        NSWorkspace.shared.open(URL(fileURLWithPath: logPath))
    }
}

// MARK: - Security Settings

struct SecuritySettingsView: View {
    @AppStorage("requirePasswordForSettings") private var requirePasswordForSettings = false
    @AppStorage("requirePasswordForDisable") private var requirePasswordForDisable = true
    @AppStorage("blockHighRiskByDefault") private var blockHighRiskByDefault = true
    @AppStorage("allowlistEnabled") private var allowlistEnabled = true

    var body: some View {
        Form {
            Section {
                Toggle("Require password to change settings", isOn: $requirePasswordForSettings)
                Toggle("Require password to disable protection", isOn: $requirePasswordForDisable)
            } header: {
                Text("Authentication")
            }

            Section {
                Toggle("Block high-risk actions by default", isOn: $blockHighRiskByDefault)

                if blockHighRiskByDefault {
                    Text("High-risk actions will be denied unless explicitly approved.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } header: {
                Text("Default Behavior")
            }

            Section {
                Toggle("Enable contextual allowlist", isOn: $allowlistEnabled)

                Button("Manage Allowlist...") {
                    // Open allowlist manager
                }

                Button("Export Security Policy...") {
                    // Export policy
                }

                Button("Import Security Policy...") {
                    // Import policy
                }
            } header: {
                Text("Policies")
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

// MARK: - Advanced Settings

struct AdvancedSettingsView: View {
    @AppStorage("debugLoggingEnabled") private var debugLoggingEnabled = false
    @AppStorage("telemetryEnabled") private var telemetryEnabled = false
    @AppStorage("cacheSize") private var cacheSize = 10000
    @AppStorage("requestTimeout") private var requestTimeout = 30

    var body: some View {
        Form {
            Section {
                Toggle("Enable debug logging", isOn: $debugLoggingEnabled)
                Toggle("Send anonymous telemetry", isOn: $telemetryEnabled)

                if telemetryEnabled {
                    Text("Help improve Guard by sending anonymous usage statistics.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } header: {
                Text("Diagnostics")
            }

            Section {
                Stepper("Cache size: \(cacheSize) entries", value: $cacheSize, in: 1000...100000, step: 1000)
                Stepper("Request timeout: \(requestTimeout)s", value: $requestTimeout, in: 5...300, step: 5)
            } header: {
                Text("Performance")
            }

            Section {
                Button("Clear Cache") {
                    clearCache()
                }

                Button("Reset All Settings") {
                    resetAllSettings()
                }
                .foregroundColor(.red)

                Button("Export Diagnostics...") {
                    exportDiagnostics()
                }
            } header: {
                Text("Maintenance")
            }

            Section {
                LabeledContent("Version") {
                    Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown")
                }

                LabeledContent("Build") {
                    Text(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "Unknown")
                }

                Button("Check for Updates...") {
                    checkForUpdates()
                }
            } header: {
                Text("About")
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    private func clearCache() {
        // Clear cache via daemon API
    }

    private func resetAllSettings() {
        // Reset UserDefaults
        if let bundleID = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: bundleID)
        }
    }

    private func exportDiagnostics() {
        // Export diagnostics
    }

    private func checkForUpdates() {
        // Check for updates
    }
}

// MARK: - Preview

#Preview {
    SettingsView()
        .environmentObject(GuardState.shared)
}
