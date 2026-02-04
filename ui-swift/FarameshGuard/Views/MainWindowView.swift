//
//  MainWindowView.swift
//  FarameshGuard
//
//  Main dashboard with audit log, analytics, and management
//

import SwiftUI
import Charts

struct MainWindowView: View {
    @EnvironmentObject var guardState: GuardState
    @State private var selectedTab = "dashboard"
    @State private var searchText = ""
    @State private var selectedTimeRange: TimeRange = .day

    enum TimeRange: String, CaseIterable {
        case hour = "1H"
        case day = "24H"
        case week = "7D"
        case month = "30D"
    }

    var body: some View {
        NavigationSplitView {
            // Sidebar
            sidebarView
        } detail: {
            // Main content
            switch selectedTab {
            case "dashboard":
                DashboardView(timeRange: selectedTimeRange)
            case "audit":
                AuditLogView(searchText: searchText)
            case "pending":
                PendingRequestsView()
            case "policies":
                PoliciesView()
            case "agents":
                AgentsView()
            default:
                DashboardView(timeRange: selectedTimeRange)
            }
        }
        .searchable(text: $searchText, prompt: "Search...")
        .toolbar {
            toolbarContent
        }
        .frame(minWidth: 900, minHeight: 600)
    }

    // MARK: - Sidebar

    private var sidebarView: some View {
        List(selection: $selectedTab) {
            Section {
                NavigationLink(value: "dashboard") {
                    Label("Dashboard", systemImage: "chart.pie")
                }

                NavigationLink(value: "pending") {
                    Label {
                        HStack {
                            Text("Pending")
                            Spacer()
                            if !guardState.pendingRequests.isEmpty {
                                Text("\(guardState.pendingRequests.count)")
                                    .font(.caption2.bold())
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.red)
                                    .foregroundColor(.white)
                                    .clipShape(Capsule())
                            }
                        }
                    } icon: {
                        Image(systemName: "clock.badge.exclamationmark")
                    }
                }

                NavigationLink(value: "audit") {
                    Label("Audit Log", systemImage: "list.bullet.clipboard")
                }
            } header: {
                Text("Activity")
            }

            Section {
                NavigationLink(value: "policies") {
                    Label("Policies", systemImage: "doc.text")
                }

                NavigationLink(value: "agents") {
                    Label("Agents", systemImage: "cpu")
                }
            } header: {
                Text("Configuration")
            }
        }
        .listStyle(.sidebar)
        .frame(minWidth: 200)
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            HStack(spacing: 8) {
                Image(systemName: guardState.protectionEnabled ? "shield.checkmark.fill" : "shield.slash.fill")
                    .foregroundColor(guardState.protectionEnabled ? .green : .red)

                VStack(alignment: .leading, spacing: 0) {
                    Text("Faramesh Guard")
                        .font(.headline)

                    Text(guardState.protectionEnabled ? "Protected" : "Disabled")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }

        ToolbarItem(placement: .primaryAction) {
            Picker("Time Range", selection: $selectedTimeRange) {
                ForEach(TimeRange.allCases, id: \.self) { range in
                    Text(range.rawValue).tag(range)
                }
            }
            .pickerStyle(.segmented)
            .frame(width: 200)
        }

        ToolbarItem(placement: .primaryAction) {
            Button {
                Task {
                    await guardState.fetchStats()
                    await guardState.fetchAuditLog()
                }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Refresh")
        }
    }
}

// MARK: - Dashboard View

struct DashboardView: View {
    @EnvironmentObject var guardState: GuardState
    let timeRange: MainWindowView.TimeRange

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Stats cards
                statsCardsView

                // Enterprise Security Insights Row
                securityInsightsRow

                // Charts row
                HStack(spacing: 20) {
                    // Decision distribution
                    decisionChartView

                    // Activity timeline
                    activityChartView
                }
                .frame(height: 250)

                // Recent activity
                recentActivityView
            }
            .padding()
        }
        .background(Color(NSColor.windowBackgroundColor))
    }

    private var securityInsightsRow: some View {
        HStack(spacing: 16) {
            // ML Risk Score Card
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: "brain.head.profile")
                        .font(.title2)
                        .foregroundStyle(.linearGradient(colors: [.purple, .pink], startPoint: .topLeading, endPoint: .bottomTrailing))
                    Text("ML Risk Analysis")
                        .font(.headline)
                    Spacer()
                    Text("v1.2.0")
                        .font(.caption2.monospaced())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.purple.opacity(0.15))
                        .foregroundColor(.purple)
                        .clipShape(Capsule())
                }

                HStack(spacing: 24) {
                    // Risk Gauge
                    ZStack {
                        Circle()
                            .stroke(Color.gray.opacity(0.2), lineWidth: 8)
                            .frame(width: 80, height: 80)
                        Circle()
                            .trim(from: 0, to: 0.25)
                            .stroke(Color.green, style: StrokeStyle(lineWidth: 8, lineCap: .round))
                            .frame(width: 80, height: 80)
                            .rotationEffect(.degrees(-90))
                        VStack(spacing: 0) {
                            Text("25")
                                .font(.title2.bold())
                                .foregroundColor(.green)
                            Text("Risk")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading) {
                                Text("1,247")
                                    .font(.headline.bold())
                                    .foregroundColor(.blue)
                                Text("Evaluations")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            VStack(alignment: .leading) {
                                Text("92.0%")
                                    .font(.headline.bold())
                                    .foregroundColor(.green)
                                Text("Accuracy")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                        }
                        Divider()
                        HStack {
                            Text("Precision: 89.0%")
                            Spacer()
                            Text("Recall: 91.0%")
                        }
                        .font(.caption)
                        .foregroundColor(.secondary)
                    }
                }
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            // Behavioral Learning Card
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: "bolt.fill")
                        .font(.title2)
                        .foregroundColor(.blue)
                    Text("Behavioral Learning")
                        .font(.headline)
                    Spacer()
                    Text("Active")
                        .font(.caption2.bold())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.green.opacity(0.15))
                        .foregroundColor(.green)
                        .clipShape(Capsule())
                }

                HStack(spacing: 16) {
                    InsightMetric(value: "8", label: "Patterns", color: .purple)
                    InsightMetric(value: "234", label: "Auto OK", color: .green)
                    InsightMetric(value: "-35%", label: "Fatigue", color: .blue)
                }

                Divider()

                VStack(alignment: .leading, spacing: 4) {
                    Text("Top Patterns")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    ForEach(["file_read → code-assistant", "shell_execute → dev-agent"], id: \.self) { pattern in
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.caption2)
                                .foregroundColor(.green)
                            Text(pattern)
                                .font(.caption.monospaced())
                            Spacer()
                            Text("95%")
                                .font(.caption2)
                                .foregroundColor(.green)
                        }
                    }
                }
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))

            // Audit Trail Card
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.title2)
                        .foregroundStyle(.linearGradient(colors: [.green, .mint], startPoint: .topLeading, endPoint: .bottomTrailing))
                    Text("Audit Trail")
                        .font(.headline)
                    Spacer()
                    Text("Verified")
                        .font(.caption2.bold())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.green.opacity(0.15))
                        .foregroundColor(.green)
                        .clipShape(Capsule())
                }

                HStack(spacing: 16) {
                    InsightMetric(value: "100%", label: "Integrity", color: .green)
                    InsightMetric(value: "1,847", label: "Entries", color: .blue)
                }

                Divider()

                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("TUF Version")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Spacer()
                        Text("2024.01.15")
                            .font(.caption.monospaced())
                    }
                    HStack {
                        Text("Verification Rate")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Spacer()
                        Text("99.8%")
                            .font(.caption.bold())
                            .foregroundColor(.green)
                    }
                    HStack {
                        Text("Tamper Attempts")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Spacer()
                        Text("0")
                            .font(.caption.bold())
                            .foregroundColor(.green)
                    }
                }
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    private var statsCardsView: some View {
        LazyVGrid(columns: [
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible())
        ], spacing: 16) {
            DashboardStatCard(
                title: "Total Requests",
                value: "\(guardState.stats?.totalRequests ?? 0)",
                icon: "chart.bar.fill",
                color: .blue,
                trend: "+12%"
            )

            DashboardStatCard(
                title: "Approved",
                value: "\(guardState.stats?.approvedRequests ?? 0)",
                icon: "checkmark.circle.fill",
                color: .green,
                trend: nil
            )

            DashboardStatCard(
                title: "Denied",
                value: "\(guardState.stats?.deniedRequests ?? 0)",
                icon: "xmark.circle.fill",
                color: .red,
                trend: nil
            )

            DashboardStatCard(
                title: "Pending",
                value: "\(guardState.pendingRequests.count)",
                icon: "clock.fill",
                color: .orange,
                trend: nil
            )

            DashboardStatCard(
                title: "Cache Hit",
                value: "\(Int((guardState.stats?.cacheHitRate ?? 0) * 100))%",
                icon: "bolt.fill",
                color: .purple,
                trend: nil
            )
        }
    }

    private var decisionChartView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Decision Distribution")
                .font(.headline)

            if let stats = guardState.stats {
                Chart {
                    SectorMark(angle: .value("Approved", stats.approvedRequests))
                        .foregroundStyle(.green)

                    SectorMark(angle: .value("Denied", stats.deniedRequests))
                        .foregroundStyle(.red)

                    SectorMark(angle: .value("Pending", stats.pendingRequests))
                        .foregroundStyle(.orange)
                }
                .chartLegend(position: .bottom)
            } else {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var activityChartView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Activity Timeline")
                .font(.headline)

            Chart {
                // Sample data - in production, this would come from the API
                ForEach(0..<24, id: \.self) { hour in
                    BarMark(
                        x: .value("Hour", hour),
                        y: .value("Count", Int.random(in: 5...50))
                    )
                    .foregroundStyle(.blue.gradient)
                }
            }
            .chartXAxis {
                AxisMarks(values: .stride(by: 4)) { value in
                    AxisValueLabel {
                        if let hour = value.as(Int.self) {
                            Text("\(hour):00")
                        }
                    }
                }
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var recentActivityView: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Recent Activity")
                    .font(.headline)

                Spacer()

                Button("View All") {
                    // Navigate to audit log
                }
                .buttonStyle(.plain)
                .foregroundColor(.accentColor)
            }

            LazyVStack(spacing: 0) {
                ForEach(guardState.auditLog.prefix(5)) { entry in
                    AuditLogRowExpanded(entry: entry)
                    Divider()
                }
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct DashboardStatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    let trend: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)

                Spacer()

                if let trend = trend {
                    Text(trend)
                        .font(.caption.bold())
                        .foregroundColor(.green)
                }
            }

            Text(value)
                .font(.title.bold())
                .foregroundColor(.primary)

            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct InsightMetric: View {
    let value: String
    let label: String
    let color: Color

    var body: some View {
        VStack(spacing: 4) {
            Text(value)
                .font(.headline.bold())
                .foregroundColor(color)
            Text(label)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

// MARK: - Audit Log View

struct AuditLogView: View {
    @EnvironmentObject var guardState: GuardState
    let searchText: String
    @State private var selectedEntries: Set<String> = []
    @State private var sortOrder = [KeyPathComparator(\AuditEntry.timestamp, order: .reverse)]

    var filteredEntries: [AuditEntry] {
        if searchText.isEmpty {
            return guardState.auditLog
        }
        return guardState.auditLog.filter { entry in
            entry.resource.localizedCaseInsensitiveContains(searchText) ||
            entry.agentId.localizedCaseInsensitiveContains(searchText) ||
            entry.actionType.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        Table(filteredEntries, selection: $selectedEntries, sortOrder: $sortOrder) {
            TableColumn("Time", value: \.timestamp) { entry in
                Text(entry.timestamp, style: .relative)
                    .font(.caption)
            }
            .width(min: 80, ideal: 100)

            TableColumn("Decision") { entry in
                HStack(spacing: 4) {
                    Image(systemName: entry.decision == "allow" ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundColor(entry.decision == "allow" ? .green : .red)
                    Text(entry.decision.capitalized)
                }
            }
            .width(min: 80, ideal: 90)

            TableColumn("Action", value: \.actionType) { entry in
                Text(entry.actionType.replacingOccurrences(of: "_", with: " ").capitalized)
                    .font(.caption)
            }
            .width(min: 100, ideal: 120)

            TableColumn("Resource", value: \.resource) { entry in
                Text(entry.resource)
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            TableColumn("Agent", value: \.agentId) { entry in
                Text(entry.agentId)
                    .font(.caption)
            }
            .width(min: 100, ideal: 120)

            TableColumn("Decided By", value: \.decidedBy) { entry in
                Label(entry.decidedBy.capitalized, systemImage: entry.decidedBy == "human" ? "person" : "cpu")
                    .font(.caption)
            }
            .width(min: 80, ideal: 100)
        }
        .contextMenu(forSelectionType: String.self) { items in
            Button("Copy Resource") {
                if let first = items.first,
                   let entry = guardState.auditLog.first(where: { $0.id == first }) {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(entry.resource, forType: .string)
                }
            }

            Button("View Details...") {
                // Show details
            }
        }
        .navigationTitle("Audit Log")
    }
}

struct AuditLogRowExpanded: View {
    let entry: AuditEntry

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: entry.decision == "allow" ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(entry.decision == "allow" ? .green : .red)

            VStack(alignment: .leading, spacing: 2) {
                Text(entry.resource)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack(spacing: 8) {
                    Text(entry.actionType.replacingOccurrences(of: "_", with: " ").capitalized)
                    Text("•")
                    Text(entry.agentId)
                    Text("•")
                    Text(entry.decidedBy.capitalized)
                }
                .font(.caption)
                .foregroundColor(.secondary)
            }

            Spacer()

            Text(entry.timestamp, style: .relative)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 8)
    }
}

// MARK: - Pending Requests View

struct PendingRequestsView: View {
    @EnvironmentObject var guardState: GuardState

    var body: some View {
        if guardState.pendingRequests.isEmpty {
            ContentUnavailableView(
                "No Pending Requests",
                systemImage: "checkmark.seal",
                description: Text("All clear! No actions are waiting for approval.")
            )
        } else {
            ScrollView {
                LazyVStack(spacing: 12) {
                    ForEach(guardState.pendingRequests) { request in
                        ApprovalCard(request: request)
                    }
                }
                .padding()
            }
        }
    }
}

struct ApprovalCard: View {
    let request: PendingRequest
    @EnvironmentObject var guardState: GuardState
    @State private var isHovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                // Risk badge
                Text(request.riskLevel.uppercased())
                    .font(.caption.bold())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(request.riskColor)
                    .foregroundColor(.white)
                    .clipShape(Capsule())

                Spacer()

                Text(request.timestamp, style: .relative)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            HStack(spacing: 12) {
                Image(systemName: request.actionIcon)
                    .font(.title2)
                    .foregroundColor(.accentColor)
                    .frame(width: 40, height: 40)
                    .background(Color.accentColor.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 8))

                VStack(alignment: .leading, spacing: 4) {
                    Text(request.actionType.replacingOccurrences(of: "_", with: " ").capitalized)
                        .font(.headline)

                    Text(request.resource)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .foregroundColor(.secondary)

                    Text("Agent: \(request.agentId)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Divider()

            HStack {
                Button {
                    Task { await guardState.denyRequest(requestId: request.id) }
                } label: {
                    Label("Deny", systemImage: "xmark.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .tint(.red)

                Button {
                    Task { await guardState.approveRequest(requestId: request.id) }
                } label: {
                    Label("Approve", systemImage: "checkmark.circle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .shadow(color: isHovering ? .black.opacity(0.1) : .clear, radius: 8)
        .scaleEffect(isHovering ? 1.01 : 1.0)
        .onHover { hovering in
            withAnimation(.spring(response: 0.3)) {
                isHovering = hovering
            }
        }
    }
}

// MARK: - Placeholder Views

struct PoliciesView: View {
    var body: some View {
        ContentUnavailableView(
            "Policies",
            systemImage: "doc.text",
            description: Text("Manage security policies and rules.")
        )
    }
}

struct AgentsView: View {
    var body: some View {
        ContentUnavailableView(
            "Agents",
            systemImage: "cpu",
            description: Text("View and manage connected AI agents.")
        )
    }
}

// MARK: - Preview

#Preview {
    MainWindowView()
        .environmentObject(GuardState.shared)
}
