//! Aegis Desktop Application
//!
//! Desktop client for the Aegis platform.

use aegis_crypto;
use aegis_platform;

fn main() {
    println!("Starting Aegis Desktop Application...");
    aegis_crypto::init();
    aegis_platform::init();
    println!("Aegis Desktop ready");
}
