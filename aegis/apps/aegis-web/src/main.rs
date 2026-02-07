//! Aegis Web Application
//!
//! Web-based interface for the Aegis platform.

use aegis_crypto::init as crypto_init;
use aegis_platform::init as platform_init;

fn main() {
    println!("Starting Aegis Web Server...");
    crypto_init();
    platform_init();
    println!("Aegis Web Server running");
}
