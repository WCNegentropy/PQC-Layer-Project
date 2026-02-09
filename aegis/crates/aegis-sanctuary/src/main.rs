//! Aegis Sanctuary Server — PQ-WireGuard Termination Node
//!
//! The Sanctuary is the server-side component of the Aegis PQ-WG tunnel.
//! It accepts connections from Aegis Gateway clients, performs post-quantum
//! handshakes, and forwards decrypted traffic (with NAT for internet access).
//!
//! # Usage
//!
//! ```bash
//! # Generate server keypair (if not exists)
//! aegis-sanctuary --config sanctuary.toml
//! ```
//!
//! # Configuration File (sanctuary.toml)
//!
//! ```toml
//! [server]
//! listen_addr = "0.0.0.0:51820"
//! keypair_file = "/etc/aegis/sanctuary.key"
//! log_level = "info"
//! # authorized_peers_dir = "/etc/aegis/peers"  # Optional
//! ```

use clap::Parser;
use tokio::signal;
use tracing::{error, info};

use aegis_sanctuary::{config::ServerConfig, server::SanctuaryServer};

#[derive(Parser, Debug)]
#[command(name = "aegis-sanctuary")]
#[command(about = "Aegis Sanctuary Server — PQ-WG Termination Node", long_about = None)]
struct Args {
    /// Path to the configuration file (TOML format).
    #[arg(short, long, default_value = "sanctuary.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_sanctuary=info".into()),
        )
        .with_target(false)
        .init();

    info!("🏰 Aegis Sanctuary Server v0.1.0");

    // Load configuration
    let config = match ServerConfig::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from '{}': {}", args.config, e);
            error!("Make sure the config file exists and is valid TOML.");
            error!("Example config:");
            error!("");
            error!("[server]");
            error!("listen_addr = \"0.0.0.0:51820\"");
            error!("keypair_file = \"sanctuary.key\"");
            error!("log_level = \"info\"");
            error!("");
            std::process::exit(1);
        }
    };

    // Apply log level from config
    // (Note: In a real app, we'd reinitialize the subscriber with the config's log level.
    // For simplicity, we'll use the env var or default for now.)

    // Bind server
    let server = SanctuaryServer::bind(&config).await?;

    // Setup Ctrl+C handler
    let server_clone = server.clone_for_shutdown();
    tokio::spawn(async move {
        if let Err(e) = signal::ctrl_c().await {
            error!("Failed to listen for Ctrl+C: {}", e);
        } else {
            info!("🛑 Shutdown signal received. Stopping server...");
            server_clone.stop();
        }
    });

    // Run the server
    match server.run().await {
        Ok(_) => {
            info!("✅ Sanctuary server terminated gracefully");
        }
        Err(e) => {
            error!("Server error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
