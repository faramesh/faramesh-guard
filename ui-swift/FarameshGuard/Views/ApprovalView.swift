//
//  ApprovalView.swift
//  FarameshGuard
//
//  The approval dialog shown when an action needs user consent
//

import SwiftUI

struct ApprovalView: View {
    let request: PendingRequest
    @EnvironmentObject var guardState: GuardState
    @State private var rememberChoice = false
    @State private var showDetails = false
    @State private var isProcessing = false
    @State private var pulseAnimation = false

    var body: some View {
        VStack(spacing: 0) {
            // Header with risk indicator
            headerView

            Divider()

            // Main content
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Action summary
                    actionSummaryView

                    // Resource details
                    resourceView

                    // Risk assessment
                    riskView

                    // Context (expandable)
                    if let context = request.context, !context.isEmpty {
                        contextView(context)
                    }
                }
                .padding()
            }
            .frame(maxHeight: 300)

            Divider()

            // Action buttons
            actionButtonsView
        }
        .frame(width: 440)
        .background(Color(NSColor.windowBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .shadow(color: .black.opacity(0.2), radius: 20, x: 0, y: 10)
        .onAppear {
            withAnimation(.easeInOut(duration: 1.5).repeatForever(autoreverses: true)) {
                pulseAnimation = true
            }
        }
    }

    // MARK: - Header

    private var headerView: some View {
        HStack(spacing: 12) {
            // Risk indicator with pulse
            ZStack {
                Circle()
                    .fill(request.riskColor.opacity(0.2))
                    .frame(width: 50, height: 50)
                    .scaleEffect(pulseAnimation ? 1.2 : 1.0)

                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.title2)
                    .foregroundColor(request.riskColor)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text("Action Approval Required")
                    .font(.headline)
                    .foregroundColor(.primary)

                Text("An AI agent is requesting to perform an action")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Spacer()

            // Timestamp
            Text(request.timestamp, style: .relative)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(request.riskColor.opacity(0.05))
    }

    // MARK: - Action Summary

    private var actionSummaryView: some View {
        HStack(spacing: 12) {
            // Action icon
            Image(systemName: request.actionIcon)
                .font(.title2)
                .foregroundColor(.accentColor)
                .frame(width: 40, height: 40)
                .background(Color.accentColor.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 4) {
                Text(formatActionType(request.actionType))
                    .font(.headline)

                Text("Agent: \(request.agentId)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - Resource View

    private var resourceView: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Resource", systemImage: "folder")
                .font(.caption)
                .foregroundColor(.secondary)

            HStack {
                Text(request.resource)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(.primary)
                    .lineLimit(3)
                    .truncationMode(.middle)

                Spacer()

                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(request.resource, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .help("Copy to clipboard")
            }
            .padding(12)
            .background(Color(NSColor.textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    // MARK: - Risk View

    private var riskView: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Risk Assessment", systemImage: "chart.bar")
                .font(.caption)
                .foregroundColor(.secondary)

            HStack(spacing: 16) {
                // Risk level badge
                Text(request.riskLevel.uppercased())
                    .font(.caption.bold())
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(request.riskColor)
                    .foregroundColor(.white)
                    .clipShape(Capsule())

                // Risk score bar
                VStack(alignment: .leading, spacing: 4) {
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            RoundedRectangle(cornerRadius: 4)
                                .fill(Color.gray.opacity(0.2))

                            RoundedRectangle(cornerRadius: 4)
                                .fill(request.riskColor)
                                .frame(width: geo.size.width * request.riskScore)
                        }
                    }
                    .frame(height: 8)

                    Text("\(Int(request.riskScore * 100))% risk score")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
            .padding(12)
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    // MARK: - Context View

    private func contextView(_ context: [String: String]) -> some View {
        DisclosureGroup(
            isExpanded: $showDetails,
            content: {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Array(context.keys.sorted()), id: \.self) { key in
                        HStack(alignment: .top) {
                            Text(formatKey(key))
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .frame(width: 100, alignment: .trailing)

                            Text(context[key] ?? "")
                                .font(.caption)
                                .foregroundColor(.primary)
                        }
                    }
                }
                .padding(.top, 8)
            },
            label: {
                Label("Additional Context", systemImage: "info.circle")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        )
    }

    // MARK: - Action Buttons

    private var actionButtonsView: some View {
        VStack(spacing: 12) {
            // Remember toggle
            Toggle(isOn: $rememberChoice) {
                Label("Remember this choice", systemImage: "bookmark")
                    .font(.caption)
            }
            .toggleStyle(.checkbox)

            HStack(spacing: 12) {
                // Deny button
                Button {
                    handleDeny()
                } label: {
                    HStack {
                        Image(systemName: "xmark.circle.fill")
                        Text("Deny")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)
                .tint(.red)
                .disabled(isProcessing)
                .keyboardShortcut(.escape, modifiers: [])

                // Approve button
                Button {
                    handleApprove()
                } label: {
                    HStack {
                        if isProcessing {
                            ProgressView()
                                .scaleEffect(0.7)
                                .progressViewStyle(.circular)
                        } else {
                            Image(systemName: "checkmark.circle.fill")
                        }
                        Text("Approve")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .disabled(isProcessing)
                .keyboardShortcut(.return, modifiers: [])
            }
        }
        .padding()
    }

    // MARK: - Actions

    private func handleApprove() {
        withAnimation {
            isProcessing = true
        }

        Task {
            await guardState.approveRequest(requestId: request.id, remember: rememberChoice)

            await MainActor.run {
                isProcessing = false
                closeWindow()
            }
        }
    }

    private func handleDeny() {
        withAnimation {
            isProcessing = true
        }

        Task {
            await guardState.denyRequest(requestId: request.id, remember: rememberChoice)

            await MainActor.run {
                isProcessing = false
                closeWindow()
            }
        }
    }

    private func closeWindow() {
        NSApp.keyWindow?.close()
    }

    // MARK: - Helpers

    private func formatActionType(_ type: String) -> String {
        type.split(separator: "_")
            .map { $0.capitalized }
            .joined(separator: " ")
    }

    private func formatKey(_ key: String) -> String {
        key.split(separator: "_")
            .map { $0.capitalized }
            .joined(separator: " ") + ":"
    }
}

// MARK: - Preview

#Preview {
    ApprovalView(request: PendingRequest(
        id: "test-123",
        actionType: "shell_execute",
        resource: "rm -rf /tmp/cache/*.log",
        agentId: "claude-agent-1",
        riskLevel: "high",
        riskScore: 0.75,
        timestamp: Date(),
        context: [
            "working_dir": "/Users/dev/project",
            "session_id": "abc123"
        ]
    ))
    .environmentObject(GuardState.shared)
    .frame(width: 440, height: 500)
}
