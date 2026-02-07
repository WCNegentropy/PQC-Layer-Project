//! Aegis Desktop Application
//!
//! Desktop client for the Aegis platform.
//!
//! # Planned Stack
//!
//! - **Framework:** Tauri 2.0 (Rust backend + web frontend)
//! - **Frontend:** Leptos or Yew for a Rust-native web UI
//! - **Features:**
//!   - System tray icon with tunnel status
//!   - One-click connect/disconnect
//!   - Vault file browser
//!   - Identity management
//!   - Peer chat (via social layer)

fn main() {
    println!("🖥️  Aegis Desktop Application");
    println!("   Framework: Tauri 2.0 (planned)");
    println!("   Status:    Placeholder — desktop UI not yet implemented");
    println!();
    println!("   To use Aegis now, try the CLI:");
    println!("   cargo run -p aegis-cli -- status");

    if let Err(e) = aegis_platform::init() {
        eprintln!("Platform initialization failed: {e}");
        std::process::exit(1);
    }
}
