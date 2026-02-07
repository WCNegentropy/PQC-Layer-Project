//! Aegis Desktop Application
//!
//! Desktop client for the Aegis platform.

use aegis_crypto::init as crypto_init;
use aegis_platform::init as platform_init;

fn main() {
    println!("Starting Aegis Desktop Application...");
    crypto_init();
    platform_init();
    println!("Aegis Desktop ready");
}
