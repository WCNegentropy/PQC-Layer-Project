//! Aegis CLI Application
//!
//! Command-line interface for the Aegis platform.

use aegis_crypto;
use aegis_platform;

fn main() {
    println!("Aegis CLI");
    aegis_crypto::init();
    aegis_platform::init();
    println!("Ready for commands");
}
