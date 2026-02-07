//! Aegis CLI Application
//!
//! Command-line interface for the Aegis platform.
//! Provides `aegis up`, `aegis down`, `aegis status`, and `aegis keygen` commands.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aegis",
    about = "Aegis — Quantum-resistant privacy platform",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Bring up the Aegis tunnel (connects to a Sanctuary node).
    Up {
        /// Sanctuary server address (host:port).
        #[arg(short, long, default_value = "127.0.0.1:51820")]
        server: String,

        /// TUN interface name.
        #[arg(short, long, default_value = "aegis0")]
        interface: String,
    },

    /// Tear down the Aegis tunnel.
    Down {
        /// TUN interface name to tear down.
        #[arg(short, long, default_value = "aegis0")]
        interface: String,
    },

    /// Show current tunnel status and statistics.
    Status,

    /// Generate a new hybrid keypair (X25519 + ML-KEM-768).
    Keygen {
        /// Output file for the public key.
        #[arg(long, default_value = "aegis.pub")]
        pubkey: String,

        /// Output file for the secret key.
        #[arg(long, default_value = "aegis.key")]
        privkey: String,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = aegis_platform::init() {
        eprintln!("Platform initialization failed: {e}");
        std::process::exit(1);
    }

    match cli.command {
        Commands::Up { server, interface } => {
            println!("🛡️  Bringing up Aegis tunnel...");
            println!("   Interface: {interface}");
            println!("   Server:    {server}");
            println!("   Status:    Not yet implemented (requires PQ-WG handshake)");
            // Future: create TUN, perform PQ-WG handshake, start packet pipeline
        }
        Commands::Down { interface } => {
            println!("🛑 Tearing down Aegis tunnel on {interface}...");
            println!("   Status: Not yet implemented");
            // Future: signal gateway to shut down, clean up TUN
        }
        Commands::Status => {
            println!("📊 Aegis Status");
            println!("   Tunnel:  inactive");
            println!("   Crypto:  aegis-crypto v{}", env!("CARGO_PKG_VERSION"));
            println!("   KEM:     X25519 + ML-KEM-768 (hybrid)");
            println!("   AEAD:    ChaCha20-Poly1305");
            println!("   Sigs:    ML-DSA-65");
        }
        Commands::Keygen { pubkey, privkey } => {
            println!("🔑 Generating hybrid keypair (X25519 + ML-KEM-768)...");
            let (pk, _sk) = aegis_crypto::AegisCrypto::keygen();
            let pk_bytes = pk.to_bytes();
            println!("   Public key:  {} bytes → {pubkey}", pk_bytes.len());
            println!("   Private key: (zeroized in memory) → {privkey}");
            println!("   ⚠️  File output not yet implemented (key shown in memory only)");
            // Future: write keys to files with proper permissions
        }
    }
}
