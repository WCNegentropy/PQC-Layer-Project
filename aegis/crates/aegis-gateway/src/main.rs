//! Aegis Gateway
//!
//! The gateway service for the Aegis platform, handling routing and access control.

use aegis_crypto;

fn main() {
    println!("Starting Aegis Gateway...");
    aegis_crypto::init();
    println!("Aegis Gateway initialized successfully");
}
