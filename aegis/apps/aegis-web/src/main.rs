//! Aegis Web Application
//!
//! Web-based interface for the Aegis platform.

use aegis_platform::init as platform_init;

fn main() {
    println!("Starting Aegis Web Server...");
    platform_init();
    println!("Aegis Web Server running");
}
