//! Aegis Web Application
//!
//! Web-based interface for the Aegis platform.
//!
//! # Planned Stack
//!
//! - **Server:** Axum or Actix-web
//! - **Frontend:** Leptos SSR or static SPA
//! - **Features:**
//!   - `check.aegis.dev` — public verification endpoint
//!   - Vault web file manager
//!   - Identity dashboard
//!   - Sanctuary node status panel

fn main() {
    println!("🌐 Aegis Web Server");
    println!("   Framework: Axum (planned)");
    println!("   Status:    Placeholder — web server not yet implemented");
    println!();
    println!("   Planned endpoints:");
    println!("   GET /health         — server health check");
    println!("   GET /api/v1/status  — tunnel and identity status");
    println!("   GET /check          — public IP verification");

    if let Err(e) = aegis_platform::init() {
        eprintln!("Platform initialization failed: {e}");
        std::process::exit(1);
    }
}
