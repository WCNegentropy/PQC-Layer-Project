//! Aegis CLI Application
//!
//! Command-line interface for the Aegis platform.

use aegis_crypto::init as crypto_init;
use aegis_platform::init as platform_init;

fn main() {
    println!("Aegis CLI");
    crypto_init();
    platform_init();
    println!("Ready for commands");
}
