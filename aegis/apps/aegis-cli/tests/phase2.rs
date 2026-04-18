use std::process::Command;

use aegis_vault::store::VaultStore;
use tempfile::tempdir;

#[test]
fn identity_new_and_show_roundtrip() {
    let temp = tempdir().unwrap();
    let identity_dir = temp.path().join("identity");

    let output = Command::new(env!("CARGO_BIN_EXE_aegis-cli"))
        .args([
            "identity",
            "new",
            "--identity-dir",
            identity_dir.to_str().unwrap(),
            "--device-name",
            "test-device",
            "--endpoint",
            "udp://127.0.0.1:51820",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(identity_dir.join("did-document.json").exists());

    let show = Command::new(env!("CARGO_BIN_EXE_aegis-cli"))
        .args([
            "identity",
            "show",
            "--identity-dir",
            identity_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(show.status.success(), "{show:?}");
    assert!(String::from_utf8_lossy(&show.stdout).contains("did:aegis:"));
}

#[test]
fn vault_init_bootstraps_social_layout() {
    let temp = tempdir().unwrap();
    let identity_dir = temp.path().join("identity");
    let vault_dir = temp.path().join("vault");

    let identity = Command::new(env!("CARGO_BIN_EXE_aegis-cli"))
        .args([
            "identity",
            "new",
            "--identity-dir",
            identity_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(identity.status.success(), "{identity:?}");

    let vault = Command::new(env!("CARGO_BIN_EXE_aegis-cli"))
        .args([
            "vault",
            "init",
            "--vault-dir",
            vault_dir.to_str().unwrap(),
            "--identity-dir",
            identity_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(vault.status.success(), "{vault:?}");

    let master_key_path = vault_dir.join(".aegis/keys/master.key");
    let master_key_bytes = std::fs::read(master_key_path).unwrap();
    let master_key: [u8; 32] = master_key_bytes.try_into().unwrap();
    let store = VaultStore::open(&vault_dir, &master_key).unwrap();
    let profile = store.read("social/profile/profile.json").unwrap();
    assert!(String::from_utf8(profile).unwrap().contains("did:aegis:"));
}
