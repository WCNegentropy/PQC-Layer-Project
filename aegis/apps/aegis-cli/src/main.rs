//! Aegis CLI Application
//!
//! Command-line interface for the Aegis platform.
//! Provides tunnel commands plus identity and vault bootstrap flows.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aegis",
    about = "Aegis — Quantum-resistant privacy platform",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Bring up the Aegis tunnel (connects to a Sanctuary node).
    Up {
        /// Sanctuary server address (host:port).
        #[arg(short, long, default_value = "127.0.0.1:51820")]
        server: String,

        /// TUN interface name.
        #[arg(short, long, default_value = "aegis0")]
        interface: String,
    },

    /// Tear down the Aegis tunnel.
    Down {
        /// TUN interface name to tear down.
        #[arg(short, long, default_value = "aegis0")]
        interface: String,
    },

    /// Show current tunnel status and statistics.
    Status,

    /// Generate a new hybrid keypair (X25519 + ML-KEM-768).
    Keygen {
        /// Output file for the public key.
        #[arg(long, default_value = "aegis.pub")]
        pubkey: String,

        /// Output file for the secret key.
        #[arg(long, default_value = "aegis.key")]
        privkey: String,
    },

    /// Manage local DID identity material.
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },

    /// Manage the local encrypted vault.
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Create a new local root identity, DID document, and primary device.
    New {
        /// Directory where identity files should be stored.
        #[arg(long, default_value = ".aegis/identity")]
        identity_dir: String,

        /// Name for the initial device record.
        #[arg(long, default_value = "default-device")]
        device_name: String,

        /// Discovery endpoints to publish in the DID document.
        #[arg(long = "endpoint")]
        endpoints: Vec<String>,
    },

    /// Show the current DID document and primary device attestation.
    Show {
        /// Directory containing identity files.
        #[arg(long, default_value = ".aegis/identity")]
        identity_dir: String,
    },
}

#[derive(Subcommand)]
enum VaultCommands {
    /// Initialize a new encrypted vault and bootstrap the social layout.
    Init {
        /// Directory where the vault should be created.
        #[arg(long, default_value = "vault")]
        vault_dir: String,

        /// Identity directory to read the owner DID from when --owner-did is omitted.
        #[arg(long, default_value = ".aegis/identity")]
        identity_dir: String,

        /// Explicit DID to use as the vault owner.
        #[arg(long)]
        owner_did: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = aegis_platform::init() {
        eprintln!("Platform initialization failed: {e}");
        std::process::exit(1);
    }

    match cli.command {
        Commands::Up { server, interface } => {
            println!("🛡️  Bringing up Aegis tunnel...");
            println!("   Interface: {interface}");
            println!("   Server:    {server}");

            // Check for an existing running gateway
            if let Some(pid) = read_pid_file() {
                if is_process_running(pid) {
                    println!("   ⚠️  Gateway already running (PID {pid})");
                    println!("   Use 'aegis down' first to tear down the existing tunnel");
                    std::process::exit(1);
                }
                // Stale PID file — remove it
                let _ = std::fs::remove_file(pid_file_path());
            }

            // Resolve the gateway binary path (same directory as aegis-cli or on PATH)
            let gateway_bin = resolve_gateway_binary();

            // Build command arguments
            let mut cmd = std::process::Command::new(&gateway_bin);
            cmd.arg("--tun-name")
                .arg(&interface)
                .arg("--sanctuary-addr")
                .arg(&server);

            // Detach the process from the terminal
            cmd.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());

            match cmd.spawn() {
                Ok(child) => {
                    let pid = child.id();
                    write_pid_file(pid);
                    println!("   PID:       {pid}");
                    println!("   PID file:  {}", pid_file_path());
                    println!("   ✅ Gateway launched");
                }
                Err(e) => {
                    eprintln!("Failed to spawn gateway process: {e}");
                    eprintln!("   Tried: {gateway_bin}");
                    eprintln!(
                        "   Make sure 'aegis-gateway' is built and accessible. \
                         Run with root privileges (sudo)."
                    );
                    std::process::exit(1);
                }
            }
        }
        Commands::Down { interface } => {
            println!("🛑 Tearing down Aegis tunnel on {interface}...");

            match read_pid_file() {
                Some(pid) => {
                    if is_process_running(pid) {
                        println!("   Sending SIGTERM to gateway (PID {pid})...");
                        signal_process(pid);
                        // Wait briefly for the process to exit
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        if is_process_running(pid) {
                            println!(
                                "   ⚠️  Process still running; it may take a moment to shut down"
                            );
                        } else {
                            println!("   ✅ Gateway stopped");
                        }
                    } else {
                        println!("   Gateway not running (stale PID file)");
                    }
                    let _ = std::fs::remove_file(pid_file_path());
                }
                None => {
                    println!("   No PID file found — is the gateway running?");
                    println!("   PID file expected at: {}", pid_file_path());
                }
            }
        }
        Commands::Status => {
            println!("📊 Aegis Status");
            if let Some(pid) = read_pid_file() {
                if is_process_running(pid) {
                    println!("   Tunnel:  active (PID {pid})");
                } else {
                    println!("   Tunnel:  inactive (stale PID file)");
                }
            } else {
                println!("   Tunnel:  inactive");
            }
            println!("   Crypto:  aegis-crypto v{}", env!("CARGO_PKG_VERSION"));
            println!("   KEM:     X25519 + ML-KEM-768 (hybrid)");
            println!("   AEAD:    ChaCha20-Poly1305");
            println!("   Sigs:    ML-DSA-65");
        }
        Commands::Keygen { pubkey, privkey } => {
            println!("🔑 Generating hybrid keypair (X25519 + ML-KEM-768)...");
            let (pk, sk) = aegis_crypto::AegisCrypto::keygen();
            let pk_bytes = pk.to_bytes();
            let sk_bytes = sk.to_bytes();

            // Write secret key with restrictive permissions
            if let Err(e) = std::fs::write(&privkey, sk_bytes.as_slice()) {
                eprintln!("Failed to write secret key to '{}': {}", privkey, e);
                std::process::exit(1);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) =
                    std::fs::set_permissions(&privkey, std::fs::Permissions::from_mode(0o600))
                {
                    eprintln!("Failed to set permissions on '{}': {}", privkey, e);
                    std::process::exit(1);
                }
            }

            // Write public key
            if let Err(e) = std::fs::write(&pubkey, &pk_bytes) {
                eprintln!("Failed to write public key to '{}': {}", pubkey, e);
                std::process::exit(1);
            }

            println!("   Public key:  {} bytes → {}", pk_bytes.len(), pubkey);
            println!("   Private key: {} bytes → {}", sk_bytes.len(), privkey);
            println!("   ✅ Keypair written to disk");
        }
        Commands::Identity { command } => match command {
            IdentityCommands::New {
                identity_dir,
                device_name,
                endpoints,
            } => {
                if let Err(err) = run_identity_new(&identity_dir, &device_name, &endpoints) {
                    eprintln!("Failed to create identity: {err}");
                    std::process::exit(1);
                }
            }
            IdentityCommands::Show { identity_dir } => {
                if let Err(err) = run_identity_show(&identity_dir) {
                    eprintln!("Failed to show identity: {err}");
                    std::process::exit(1);
                }
            }
        },
        Commands::Vault { command } => match command {
            VaultCommands::Init {
                vault_dir,
                identity_dir,
                owner_did,
            } => {
                if let Err(err) = run_vault_init(&vault_dir, &identity_dir, owner_did.as_deref()) {
                    eprintln!("Failed to initialize vault: {err}");
                    std::process::exit(1);
                }
            }
        },
    }
}

// ─── PID File and Process Management ────────────────────────────────────────

/// Get the path to the gateway PID file.
fn pid_file_path() -> String {
    // Use /tmp/aegis for non-root, /run/aegis for root
    #[cfg(unix)]
    {
        let dir = if is_running_as_root() {
            "/run/aegis"
        } else {
            "/tmp/aegis"
        };
        let _ = std::fs::create_dir_all(dir);
        format!("{}/gateway.pid", dir)
    }
    #[cfg(not(unix))]
    {
        let dir = std::env::temp_dir().join("aegis");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("gateway.pid").to_string_lossy().to_string()
    }
}

/// Check if the current process is running as root.
#[cfg(unix)]
fn is_running_as_root() -> bool {
    // SAFETY: getuid() is a simple libc call with no preconditions.
    unsafe { libc::getuid() == 0 }
}

/// Write a PID to the PID file.
fn write_pid_file(pid: u32) {
    let path = pid_file_path();
    if let Err(e) = std::fs::write(&path, pid.to_string()) {
        eprintln!("Warning: failed to write PID file '{}': {}", path, e);
    }
}

/// Read a PID from the PID file. Returns `None` if the file doesn't exist
/// or doesn't contain a valid PID.
fn read_pid_file() -> Option<u32> {
    let path = pid_file_path();
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse().ok()
}

/// Check if a process with the given PID is still running.
#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    // kill(pid, 0) returns 0 if the process exists and we have permission
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    // On non-Unix, conservatively assume the process is not running
    false
}

/// Send SIGTERM to a process.
#[cfg(unix)]
fn signal_process(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
}

#[cfg(not(unix))]
fn signal_process(_pid: u32) {
    eprintln!("   Signal sending is not supported on this platform");
}

/// Resolve the gateway binary path.
///
/// First checks for the binary adjacent to the current executable,
/// then falls back to searching PATH.
fn resolve_gateway_binary() -> String {
    // Try adjacent to this binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("aegis-gateway");
            if candidate.exists() {
                return candidate.to_string_lossy().to_string();
            }
        }
    }

    // Fall back to PATH
    "aegis-gateway".to_string()
}

fn run_identity_new(
    identity_dir: &str,
    device_name: &str,
    endpoints: &[String],
) -> Result<(), String> {
    let services = if endpoints.is_empty() {
        vec![aegis_identity::did::ServiceEndpoint {
            id: "#primary-node".into(),
            service_type: "AegisNode".into(),
            endpoint: "udp://127.0.0.1:51820".into(),
        }]
    } else {
        endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoint)| aegis_identity::did::ServiceEndpoint {
                id: format!("#node-{}", index + 1),
                service_type: "AegisNode".into(),
                endpoint: endpoint.clone(),
            })
            .collect()
    };
    let identity_path = PathBuf::from(identity_dir);
    let identity_store = aegis_identity::storage::IdentityDirectory::new(&identity_path);
    let stored = identity_store
        .initialize(device_name, &services)
        .map_err(|err| err.to_string())?;

    println!("🪪 Created local Aegis identity");
    println!("   DID:        {}", stored.metadata.owner_did);
    println!("   Identity:   {}", identity_path.display());
    println!("   Device DID: {}", stored.active_device.device_did);
    println!(
        "   ✅ Contract v{} DID document and device credential written",
        stored.metadata.contract_version
    );
    Ok(())
}

fn run_identity_show(identity_dir: &str) -> Result<(), String> {
    let identity_store = aegis_identity::storage::IdentityDirectory::new(identity_dir);
    let stored = identity_store.load().map_err(|err| err.to_string())?;
    stored
        .device_credential
        .verify()
        .map_err(|err| err.to_string())?;

    println!("🪪 Aegis Identity");
    println!("   DID:        {}", stored.metadata.owner_did);
    println!("   Services:   {}", stored.did_document.service.len());
    for service in &stored.did_document.service {
        println!("   - {} → {}", service.service_type, service.endpoint);
    }
    println!("   Device:     {}", stored.active_device.name);
    println!("   Device VC:  verified");
    println!("   Subject:    {}", stored.device_credential.subject);
    Ok(())
}

fn run_vault_init(
    vault_dir: &str,
    identity_dir: &str,
    owner_did: Option<&str>,
) -> Result<(), String> {
    let owner_did = match owner_did {
        Some(owner_did) => owner_did.to_string(),
        None => read_owner_did(identity_dir)?,
    };
    let vault_path = PathBuf::from(vault_dir);
    let master_key = aegis_vault::store::VaultStore::generate_master_key();
    let vault = aegis_vault::store::VaultStore::init(&vault_path, &master_key)
        .map_err(|err| err.to_string())?;
    aegis_vault::store::VaultStore::write_master_key_file(&vault_path, &master_key)
        .map_err(|err| err.to_string())?;
    let created = vault
        .initialize_social_layout(&owner_did)
        .map_err(|err| err.to_string())?;

    println!("🗄️  Initialized encrypted Aegis vault");
    println!("   Owner DID:  {owner_did}");
    println!("   Vault:      {}", vault_path.display());
    println!("   Files:      {}", created.len());
    println!("   ✅ Social layout bootstrapped");
    Ok(())
}

fn read_owner_did(identity_dir: &str) -> Result<String, String> {
    aegis_identity::storage::IdentityDirectory::new(identity_dir)
        .read_owner_did()
        .map_err(|err| err.to_string())
}
