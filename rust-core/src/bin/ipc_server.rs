//! Guard Core IPC Server Binary
//!
//! This is the main entry point for the Guard security kernel.
//! Run as a daemon process that the Python control plane connects to.

use guard_core::ipc::{run_server, IpcServerConfig};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "guard_core=info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Guard Core v{}", guard_core::VERSION);

    // Load configuration from environment
    let socket_path = std::env::var("GUARD_SOCKET_PATH")
        .unwrap_or_else(|_| guard_core::DEFAULT_SOCKET_PATH.to_string());

    let hmac_secret = std::env::var("GUARD_HMAC_SECRET")
        .map(|s| s.into_bytes())
        .unwrap_or_else(|_| {
            tracing::warn!("GUARD_HMAC_SECRET not set, using default (insecure!)");
            b"default-secret-change-in-production".to_vec()
        });

    let config = IpcServerConfig {
        socket_path,
        hmac_secret,
    };

    tracing::info!("IPC socket: {}", config.socket_path);

    // Run the server
    run_server(config).await?;

    Ok(())
}
