//! Aegis Gateway
//!
//! The gateway service for the Aegis platform, handling routing and access control.

use aegis_crypto::init;

fn main() {
    println!("Starting Aegis Gateway...");
    init();
    println!("Aegis Gateway initialized successfully");
}
