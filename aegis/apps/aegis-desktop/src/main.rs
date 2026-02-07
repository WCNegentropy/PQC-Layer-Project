//! Aegis Desktop Application
//!
//! Desktop client for the Aegis platform.

use aegis_platform::init as platform_init;

fn main() {
    println!("Starting Aegis Desktop Application...");
    platform_init();
    println!("Aegis Desktop ready");
}
