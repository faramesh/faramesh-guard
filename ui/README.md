# Faramesh Guard Desktop UI

A native desktop application for monitoring and controlling the Faramesh Guard AI safety daemon.

## Features

- **Real-time Protection Status**: Monitor Guard daemon health and connection
- **Safety Mode Selector**: Switch between Strict, Balanced, and Permissive modes
- **Activity Feed**: Live stream of all AI agent actions
- **Approval Modal**: Review and approve/deny pending high-risk actions
- **Trust Management**: Configure trust profiles for agents and tools
- **History View**: Browse and search historical actions
- **System Tray**: Runs in background with quick access menu

## Tech Stack

- **Tauri**: Native desktop app framework (Rust backend)
- **React 18**: UI framework
- **TypeScript**: Type-safe JavaScript
- **Vite**: Build tool
- **Lucide Icons**: Icon library

## Development

### Prerequisites

- Node.js 18+
- Rust (for Tauri)
- Guard daemon running on localhost:8765

### Setup

```bash
# Install dependencies
npm install

# Run in development mode
npm run tauri:dev

# Build for production
npm run tauri:build
```

### Project Structure

```
ui/
├── src/
│   ├── components/
│   │   ├── ProtectionStatus.tsx    # Protection status card
│   │   ├── SafetyModeSelector.tsx  # Mode toggle
│   │   ├── ActivityFeed.tsx        # Live activity stream
│   │   ├── ApprovalModal.tsx       # Approval dialog
│   │   ├── TrustManagement.tsx     # Trust profiles
│   │   └── HistoryView.tsx         # Historical actions
│   ├── App.tsx                     # Main application
│   ├── main.tsx                    # Entry point
│   ├── types.ts                    # TypeScript types
│   └── styles.css                  # Global styles
├── src-tauri/
│   ├── src/main.rs                 # Tauri main process
│   ├── tauri.conf.json             # Tauri configuration
│   └── Cargo.toml                  # Rust dependencies
├── index.html                      # HTML entry
├── package.json                    # Node dependencies
└── vite.config.ts                  # Vite configuration
```

## Building for Distribution

```bash
# Build for current platform
npm run tauri:build

# Built apps will be in:
# - macOS: src-tauri/target/release/bundle/macos/
# - Windows: src-tauri/target/release/bundle/msi/
# - Linux: src-tauri/target/release/bundle/deb/
```

## API Integration

The UI connects to the Guard daemon API at `http://localhost:8765`:

- `GET /health` - Check daemon health
- `GET /pending` - Fetch pending approvals
- `GET /history` - Fetch action history
- `POST /approve` - Submit approval decision

## System Tray

The app runs in the system tray by default. Click the tray icon to:
- Open the main window
- Toggle protection pause
- Quit the application

Closing the window hides it to the tray instead of quitting.
