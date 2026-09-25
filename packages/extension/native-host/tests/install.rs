//! `install` and `uninstall` against a temporary home directory. Unix only:
//! on Windows they write to the user's real registry.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use warren_native_host::ids::{BUILD_CHANNEL, baked_ids};

fn run(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_warren-host"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap()
}

fn helper_dir(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Warren/Helper")
    } else {
        home.join(".local/share/warren/helper")
    }
}

fn chrome_manifest(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts/com.warrenbrowse.host.json")
    } else {
        home.join(".config/google-chrome/NativeMessagingHosts/com.warrenbrowse.host.json")
    }
}

fn firefox_profile(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Firefox")
    } else {
        home.join(".mozilla/firefox")
    }
}

fn firefox_manifest(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join(
            "Library/Application Support/Mozilla/NativeMessagingHosts/com.warrenbrowse.host.json",
        )
    } else {
        home.join(".mozilla/native-messaging-hosts/com.warrenbrowse.host.json")
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn installs_for_the_browsers_in_use_then_uninstalls_everything() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    std::fs::create_dir_all(firefox_profile(home)).unwrap();
    let dev_id = "abcdefghijklmnopabcdefghijklmnop";

    let out = run(
        home,
        &[
            "install",
            "--extension-id",
            dev_id,
            "--gecko-id",
            "dev@example.com",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("installed for: Firefox."), "{text}");

    let binary = helper_dir(home).join("warren-host");
    let version = Command::new(&binary).arg("--version").output().unwrap();
    assert!(version.status.success(), "the installed copy runs");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&binary).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    let manifest = read_json(&firefox_manifest(home));
    assert_eq!(manifest["path"], binary.to_string_lossy().as_ref());
    assert_eq!(manifest["type"], "stdio");
    let allowed: Vec<&str> = manifest["allowed_extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        allowed,
        [baked_ids(BUILD_CHANNEL).gecko[0], "dev@example.com"]
    );
    assert!(!chrome_manifest(home).exists(), "Chrome is not in use here");

    // A second install (an update) keeps the ids recorded by the first.
    let out = run(home, &["install"]);
    assert!(out.status.success());
    let record = read_json(&helper_dir(home).join("warren-host.json"));
    assert_eq!(record["extensionIds"][0], dev_id);

    let out = run(home, &["uninstall"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!firefox_manifest(home).exists());
    assert!(!helper_dir(home).exists());
}

#[test]
fn registers_with_every_browser_when_none_is_in_use() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let out = run(home, &[]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("No browser was found yet"));
    let manifest = read_json(&chrome_manifest(home));
    let origin = format!(
        "chrome-extension://{}/",
        baked_ids(BUILD_CHANNEL).chromium[0]
    );
    assert_eq!(manifest["allowed_origins"][0], origin.as_str());
    assert!(firefox_manifest(home).exists());
}

#[test]
fn refuses_a_malformed_id_and_writes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let out = run(home.path(), &["install", "--extension-id", "../../etc"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!helper_dir(home.path()).exists());
}
