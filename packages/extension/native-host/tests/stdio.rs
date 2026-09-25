//! The built binary, driven over real stdio framing the way a browser starts
//! it. Offline: nothing here reaches the network.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use warren_native_host::ids::{BUILD_CHANNEL, baked_ids};

fn frame(message: &Value) -> Vec<u8> {
    let json = serde_json::to_vec(message).unwrap();
    let mut frame = (json.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&json);
    frame
}

fn read_frames(mut bytes: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        out.push(serde_json::from_slice(&bytes[4..4 + len]).unwrap());
        bytes = &bytes[4 + len..];
    }
    out
}

fn helper(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_warren-host"));
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("LOCALAPPDATA", home.join("local"))
        .env("XDG_DATA_HOME", home.join("data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
fn a_chromium_launch_of_the_builds_extension_is_served_until_the_pipe_closes() {
    let home = tempfile::tempdir().unwrap();
    let id = baked_ids(BUILD_CHANNEL).chromium[0];
    let mut child = helper(home.path())
        .arg(format!("chrome-extension://{id}/"))
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&frame(
            &json!({ "id": 1, "type": "hello", "protocol": 3, "channel": "beta" }),
        ))
        .unwrap();
    stdin
        .write_all(&frame(&json!({ "id": 2, "type": "status" })))
        .unwrap();
    drop(stdin);
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());
    let answers = read_frames(&stdout);
    assert_eq!(
        answers[0],
        json!({ "id": 1, "ok": true, "type": "hello", "protocol": 3, "datapath": "ready" })
    );
    assert_eq!(
        answers[1],
        json!({ "id": 2, "ok": true, "type": "status", "state": "disconnected" })
    );
}

#[test]
fn a_firefox_launch_of_the_builds_add_on_is_served() {
    let home = tempfile::tempdir().unwrap();
    let id = baked_ids(BUILD_CHANNEL).gecko[0];
    let mut child = helper(home.path())
        .args(["/tmp/com.warrenbrowse.host.json", id])
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&frame(&json!({ "id": 7, "type": "hello", "protocol": 3 })))
        .unwrap();
    drop(stdin);
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(read_frames(&stdout)[0]["ok"], true);
}

#[test]
fn refuses_an_extension_it_does_not_know_without_a_word_on_stdout() {
    let home = tempfile::tempdir().unwrap();
    let output = helper(home.path())
        .arg("chrome-extension://abcdefghijklmnopabcdefghijklmnop/")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not allowed"));
}

#[test]
fn a_corrupt_frame_ends_the_process_with_an_error() {
    let home = tempfile::tempdir().unwrap();
    let id = baked_ids(BUILD_CHANNEL).chromium[0];
    let mut child = helper(home.path())
        .arg(format!("chrome-extension://{id}/"))
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&u32::MAX.to_le_bytes()).unwrap();
    let status = child.wait().unwrap();
    drop(stdin);
    assert_eq!(status.code(), Some(1));
}

#[test]
fn prints_its_version_and_channel() {
    let output = Command::new(env!("CARGO_BIN_EXE_warren-host"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!(
            "warren-host {} ({} channel)",
            env!("CARGO_PKG_VERSION"),
            BUILD_CHANNEL.name()
        )
    );
}
