//! Aegis CLI Application
//!
//! Command-line interface for the Aegis platform.

use aegis_platform::init as platform_init;

fn main() {
    println!("Aegis CLI");
    platform_init();
    println!("Ready for commands");
}
