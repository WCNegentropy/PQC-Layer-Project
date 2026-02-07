//! Aegis Web Application
//!
//! Web-based interface for the Aegis platform.

use aegis_crypto;
use aegis_platform;

fn main() {
    println!("Starting Aegis Web Server...");
    aegis_crypto::init();
    aegis_platform::init();
    println!("Aegis Web Server running");
}
