//
//  MenuBarView.swift
//  FarameshGuard
//
//  Menu bar popover with quick actions and status
//

import SwiftUI

struct MenuBarView: View {
    @EnvironmentObject var guardState: GuardState
    @State private var isHoveringProtection = false
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            // Header
            headerView

            Divider()

            // Tab selector
            Picker("", selection: $selectedTab) {
                Text("Status").tag(0)
                Text("Pending (\(guardState.pendingRequests.count))").tag(1)
                Text("Recent").tag(2)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)
            .padding(.vertical, 8)

            Divider()

            // Content based on tab
            switch selectedTab {
            case 0:
                statusTabView
            case 1:
                pendingTabView
            case 2:
                recentTabView
            default:
                EmptyView()
            }

            Divider()

            // Footer with quick actions
            footerView
        }
        .frame(width: 340)
    }

    // MARK: - Header

    private var headerView: some View {
        HStack(spacing: 12) {
            // Shield icon with animation
            ZStack {
                Circle()
                    .fill(guardState.protectionEnabled ? Color.green.opacity(0.15) : Color.red.opacity(0.15))
                    .frame(width: 44, height: 44)

                Image(systemName: guardState.protectionEnabled ? "shield.checkmark.fill" : "shield.slash.fill")
                    .font(.title2)
                    .foregroundColor(guardState.protectionEnabled ? .green : .red)
                    .symbolEffect(.bounce, value: guardState.protectionEnabled)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text("Faramesh Guard")
                    .font(.headline)

                HStack(spacing: 4) {
                    Circle()
                        .fill(guardState.isConnected ? Color.green : Color.red)
                        .frame(width: 6, height: 6)

                    Text(guardState.isConnected ? "Connected" : "Disconnected")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            // Protection toggle
            Button {
                Task {
                    await guardState.toggleProtection()
                }
            } label: {
                Text(guardState.protectionEnabled ? "Enabled" : "Disabled")
                    .font(.caption.bold())
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(guardState.protectionEnabled ? Color.green : Color.red)
                    .foregroundColor(.white)
                    .clipShape(Capsule())
            }
            .buttonStyle(.plain)
            .scaleEffect(isHoveringProtection ? 1.05 : 1.0)
            .onHover { hovering in
                withAnimation(.spring(response: 0.3)) {
                    isHoveringProtection = hovering
                }
            }
        }
        .padding()
    }

    // MARK: - Status Tab

    private var statusTabView: some View {
        VStack(spacing: 12) {
            // Protection mode selector
            protectionModeView

            // Stats grid
            if let stats = guardState.stats {
                statsGridView(stats)
            } else {
                ProgressView("Loading stats...")
                    .frame(height: 100)
            }

            // Quick Security Insights
            securityInsightsView
        }
        .padding()
    }

    private var securityInsightsView: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Security Insights")
                .font(.caption)
                .foregroundColor(.secondary)

            HStack(spacing: 8) {
                // ML Risk
                VStack(spacing: 4) {
                    ZStack {
                        Circle()
                            .stroke(Color.gray.opacity(0.2), lineWidth: 4)
                            .frame(width: 36, height: 36)
                        Circle()
                            .trim(from: 0, to: 0.25)
                            .stroke(Color.green, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                            .frame(width: 36, height: 36)
                            .rotationEffect(.degrees(-90))
                        Text("25")
                            .font(.caption2.bold())
                            .foregroundColor(.green)
                    }
                    Text("Risk")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))

                // Learning
                VStack(spacing: 4) {
                    Image(systemName: "bolt.fill")
                        .font(.title3)
                        .foregroundColor(.blue)
                    Text("8 patterns")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))

                // Audit
                VStack(spacing: 4) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.title3)
                        .foregroundColor(.green)
                    Text("Verified")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private var protectionModeView: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Protection Mode")
                .font(.caption)
                .foregroundColor(.secondary)

            Picker("", selection: Binding(
                get: { guardState.protectionMode },
                set: { mode in
                    Task {
                        await guardState.setProtectionMode(mode)
                    }
                }
            )) {
                ForEach(GuardState.ProtectionMode.allCases, id: \.self) { mode in
                    HStack {
                        Image(systemName: mode.icon)
                        Text(mode.rawValue)
                    }
                    .tag(mode)
                }
            }
            .pickerStyle(.menu)

            Text(guardState.protectionMode.description)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    private func statsGridView(_ stats: DaemonStats) -> some View {
        LazyVGrid(columns: [
            GridItem(.flexible()),
            GridItem(.flexible())
        ], spacing: 12) {
            StatCard(title: "Total", value: "\(stats.totalRequests)", icon: "chart.bar", color: .blue)
            StatCard(title: "Approved", value: "\(stats.approvedRequests)", icon: "checkmark.circle", color: .green)
            StatCard(title: "Denied", value: "\(stats.deniedRequests)", icon: "xmark.circle", color: .red)
            StatCard(title: "Cache Hit", value: "\(Int(stats.cacheHitRate * 100))%", icon: "bolt", color: .orange)
        }
    }

    // MARK: - Pending Tab

    private var pendingTabView: some View {
        ScrollView {
            LazyVStack(spacing: 8) {
                if guardState.pendingRequests.isEmpty {
                    emptyPendingView
                } else {
                    ForEach(guardState.pendingRequests) { request in
                        PendingRequestRow(request: request)
                    }
                }
            }
            .padding()
        }
        .frame(height: 250)
    }

    private var emptyPendingView: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.seal")
                .font(.largeTitle)
                .foregroundColor(.green)

            Text("No Pending Requests")
                .font(.headline)

            Text("All clear! No actions waiting for approval.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }

    // MARK: - Recent Tab

    private var recentTabView: some View {
        ScrollView {
            LazyVStack(spacing: 4) {
                if guardState.auditLog.isEmpty {
                    Text("No recent activity")
                        .foregroundColor(.secondary)
                        .padding(.vertical, 40)
                } else {
                    ForEach(guardState.auditLog.prefix(10)) { entry in
                        AuditLogRow(entry: entry)
                    }
                }
            }
            .padding()
        }
        .frame(height: 250)
    }

    // MARK: - Footer

    private var footerView: some View {
        HStack {
            Button {
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
            } label: {
                Label("Settings", systemImage: "gear")
            }
            .buttonStyle(.plain)

            Spacer()

            Button {
                if let window = NSApp.windows.first(where: { $0.title == "Faramesh Guard" }) {
                    window.makeKeyAndOrderFront(nil)
                    NSApp.activate(ignoringOtherApps: true)
                }
            } label: {
                Label("Open Dashboard", systemImage: "rectangle.on.rectangle")
            }
            .buttonStyle(.plain)

            Spacer()

            Button {
                NSApp.terminate(nil)
            } label: {
                Label("Quit", systemImage: "power")
            }
            .buttonStyle(.plain)
        }
        .font(.caption)
        .foregroundColor(.secondary)
        .padding()
    }
}

// MARK: - Supporting Views

struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundColor(color)

            Text(value)
                .font(.title2.bold())
                .foregroundColor(.primary)

            Text(title)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct PendingRequestRow: View {
    let request: PendingRequest
    @EnvironmentObject var guardState: GuardState
    @State private var isHovering = false

    var body: some View {
        HStack(spacing: 10) {
            // Risk indicator
            Circle()
                .fill(request.riskColor)
                .frame(width: 8, height: 8)

            // Icon
            Image(systemName: request.actionIcon)
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 20)

            // Info
            VStack(alignment: .leading, spacing: 2) {
                Text(request.resource)
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text(request.agentId)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            Spacer()

            // Quick actions (show on hover)
            if isHovering {
                HStack(spacing: 4) {
                    Button {
                        Task { await guardState.denyRequest(requestId: request.id) }
                    } label: {
                        Image(systemName: "xmark")
                            .font(.caption)
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)

                    Button {
                        Task { await guardState.approveRequest(requestId: request.id) }
                    } label: {
                        Image(systemName: "checkmark")
                            .font(.caption)
                    }
                    .buttonStyle(.bordered)
                    .tint(.green)
                }
            }
        }
        .padding(8)
        .background(isHovering ? Color(NSColor.controlBackgroundColor) : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.15)) {
                isHovering = hovering
            }
        }
    }
}

struct AuditLogRow: View {
    let entry: AuditEntry

    var decisionColor: Color {
        switch entry.decision {
        case "allow": return .green
        case "deny": return .red
        default: return .gray
        }
    }

    var body: some View {
        HStack(spacing: 8) {
            // Decision indicator
            Image(systemName: entry.decision == "allow" ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.caption)
                .foregroundColor(decisionColor)

            // Info
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.resource)
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack(spacing: 4) {
                    Text(entry.decidedBy)
                        .font(.caption2)
                        .foregroundColor(.secondary)

                    Text("•")
                        .font(.caption2)
                        .foregroundColor(.secondary)

                    Text(entry.timestamp, style: .relative)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Preview

#Preview {
    MenuBarView()
        .environmentObject(GuardState.shared)
}
