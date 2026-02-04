//
//  FarameshGuardApp.swift
//  FarameshGuard
//
//  Native macOS UI for Faramesh Guard
//  Provides: Approval dialogs, Menu bar, Settings, Audit log
//

import SwiftUI
import UserNotifications

@main
struct FarameshGuardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var guardState = GuardState.shared

    var body: some Scene {
        // Menu bar app (primary)
        MenuBarExtra {
            MenuBarView()
                .environmentObject(guardState)
        } label: {
            Image(systemName: guardState.protectionEnabled ? "shield.checkmark.fill" : "shield.slash")
                .symbolRenderingMode(.hierarchical)
                .foregroundColor(guardState.protectionEnabled ? .green : .red)
        }
        .menuBarExtraStyle(.window)

        // Settings window
        Settings {
            SettingsView()
                .environmentObject(guardState)
        }

        // Main window (hidden by default, shows audit log)
        WindowGroup("Faramesh Guard") {
            MainWindowView()
                .environmentObject(guardState)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .defaultPosition(.center)
    }
}

// MARK: - App Delegate

class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    var approvalWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Request notification permissions
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if granted {
                print("Notification permission granted")
            }
        }

        // Connect to daemon
        Task {
            await GuardState.shared.connectToDaemon()
        }

        // Hide dock icon (menu bar app)
        NSApp.setActivationPolicy(.accessory)
    }

    func applicationWillTerminate(_ notification: Notification) {
        GuardState.shared.disconnect()
    }

    // Handle notification actions
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let requestId = response.notification.request.identifier

        switch response.actionIdentifier {
        case "APPROVE_ACTION":
            Task {
                await GuardState.shared.approveRequest(requestId: requestId)
            }
        case "DENY_ACTION":
            Task {
                await GuardState.shared.denyRequest(requestId: requestId)
            }
        default:
            // Show approval window
            showApprovalWindow(for: requestId)
        }

        completionHandler()
    }

    func showApprovalWindow(for requestId: String) {
        if let pending = GuardState.shared.pendingRequests.first(where: { $0.id == requestId }) {
            DispatchQueue.main.async {
                let view = ApprovalView(request: pending)
                    .environmentObject(GuardState.shared)

                let hostingController = NSHostingController(rootView: view)

                self.approvalWindow = NSWindow(contentViewController: hostingController)
                self.approvalWindow?.title = "Action Approval Required"
                self.approvalWindow?.styleMask = [.titled, .closable]
                self.approvalWindow?.level = .floating
                self.approvalWindow?.center()
                self.approvalWindow?.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
            }
        }
    }
}
