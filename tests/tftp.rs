mod fixtures;
mod utils;

use fixtures::{tftp_server, TestServerTftp, BIN_FILE};
use rstest::rstest;
use serde_json::json;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// A minimal RRQ client. It understands ERROR, OACK (blksize) and DATA; the
/// tests only need the download direction.
fn tftp_get(addr: SocketAddr, name: &str, blksize: Option<u16>) -> Result<Vec<u8>, (u16, String)> {
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|err| (0, err.to_string()))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| (0, err.to_string()))?;

    let mut packet = vec![0u8, 1];
    packet.extend_from_slice(name.as_bytes());
    packet.push(0);
    packet.extend_from_slice(b"octet");
    packet.push(0);
    if let Some(size) = blksize {
        for (key, value) in [("blksize", size.to_string()), ("tsize", "0".to_string())] {
            packet.extend_from_slice(key.as_bytes());
            packet.push(0);
            packet.extend_from_slice(value.as_bytes());
            packet.push(0);
        }
    }
    socket
        .send_to(&packet, addr)
        .map_err(|err| (0, err.to_string()))?;

    let mut block_size = blksize.unwrap_or(512) as usize;
    let mut expected = 1u16;
    let mut data = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let (len, from) = match socket.recv_from(&mut buf) {
            Ok(value) => value,
            Err(err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut =>
            {
                return Err((0, "timeout".to_string()));
            }
            Err(err) => return Err((0, err.to_string())),
        };
        if len < 4 {
            continue;
        }
        match u16::from_be_bytes([buf[0], buf[1]]) {
            5 => {
                let code = u16::from_be_bytes([buf[2], buf[3]]);
                let end = buf[4..len]
                    .iter()
                    .position(|value| *value == 0)
                    .map(|index| index + 4)
                    .unwrap_or(len);
                return Err((code, String::from_utf8_lossy(&buf[4..end]).to_string()));
            }
            6 => {
                let text = String::from_utf8_lossy(&buf[2..len]);
                let parts: Vec<&str> = text.split('\0').collect();
                if let Some(index) = parts.iter().position(|value| *value == "blksize") {
                    if let Some(size) = parts.get(index + 1).and_then(|value| value.parse().ok()) {
                        block_size = size;
                    }
                }
                socket.send_to(&[0, 4, 0, 0], from).ok();
            }
            3 => {
                let block = u16::from_be_bytes([buf[2], buf[3]]);
                let chunk = &buf[4..len];
                if block == expected {
                    data.extend_from_slice(chunk);
                    expected = expected.wrapping_add(1);
                }
                socket
                    .send_to(&[0u8, 4, (block >> 8) as u8, block as u8], from)
                    .ok();
                if chunk.len() < block_size {
                    return Ok(data);
                }
            }
            _ => {}
        }
    }
}

fn acl_url(server: &TestServerTftp, path: &str) -> String {
    format!(
        "{}__dufs__/acl?path={}",
        server.url(),
        urlencoding::encode(path)
    )
}

fn acl_get(
    server: &TestServerTftp,
    path: &str,
    auth: Option<(&str, &str)>,
) -> anyhow::Result<serde_json::Value> {
    let mut request = reqwest::blocking::Client::new().get(acl_url(server, path));
    if let Some((user, pass)) = auth {
        request = request.basic_auth(user, Some(pass));
    }
    Ok(request.send()?.error_for_status()?.json()?)
}

fn acl_put(
    server: &TestServerTftp,
    path: &str,
    body: serde_json::Value,
    auth: Option<(&str, &str)>,
) -> anyhow::Result<reqwest::blocking::Response> {
    let mut request = reqwest::blocking::Client::new()
        .put(acl_url(server, path))
        .json(&body);
    if let Some((user, pass)) = auth {
        request = request.basic_auth(user, Some(pass));
    }
    Ok(request.send()?)
}

#[rstest]
fn tftp_serves_only_enabled_files(
    #[with(&["--allow-all"])] tftp_server: TestServerTftp,
) -> anyhow::Result<()> {
    // default: off
    let data = acl_get(&tftp_server, "/test.txt", None)?;
    assert_eq!(data["enable_tftp"], false);
    assert_eq!(data["guest_readable"], true);
    assert!(data["own_enable_tftp"].is_null());

    let resp = acl_put(
        &tftp_server,
        "/test.txt",
        json!({"allow_read": ["guest"], "allow_write": [], "deny_read": [], "enable_tftp": true}),
        None,
    )?;
    assert_eq!(resp.status(), 204);

    let downloaded = tftp_get(tftp_server.tftp_addr(), "test.txt", None)
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;
    assert_eq!(downloaded, b"This is test.txt");

    // a directory rule enables its subtree, an explicit child false wins
    let resp = acl_put(
        &tftp_server,
        "/dir1",
        json!({"allow_read": ["guest"], "allow_write": [], "deny_read": [], "enable_tftp": true}),
        None,
    )?;
    assert_eq!(resp.status(), 204);
    let downloaded = tftp_get(tftp_server.tftp_addr(), "dir1/test.txt", None)
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;
    assert_eq!(downloaded, b"This is dir1/test.txt");
    let resp = acl_put(
        &tftp_server,
        "/dir1/test.html",
        json!({"allow_read": ["guest"], "allow_write": [], "deny_read": [], "enable_tftp": false}),
        None,
    )?;
    assert_eq!(resp.status(), 204);
    let err = tftp_get(tftp_server.tftp_addr(), "dir1/test.html", None).unwrap_err();
    assert_eq!(err.0, 2);

    for (name, code) in [
        ("test.html", 2u16),
        ("dir1", 1),
        ("__dufs__/health", 1),
        ("../test.txt", 1),
        ("favicon.ico", 1),
        ("test.txt?json", 1),
    ] {
        let err = tftp_get(tftp_server.tftp_addr(), name, None).unwrap_err();
        assert_eq!(err.0, code, "{name}: {err:?}");
    }
    Ok(())
}

#[rstest]
fn tftp_only_save_does_not_create_an_acl_rule(
    #[with(&["--allow-all"])] tftp_server: TestServerTftp,
) -> anyhow::Result<()> {
    // This is the payload the WebUI sends when only the tftp switch changes
    // on a path without an own rule: no user lists, so no "deny everyone".
    let resp = acl_put(
        &tftp_server,
        "/test.txt",
        json!({"enable_tftp": true}),
        None,
    )?;
    assert_eq!(resp.status(), 204);
    let data = acl_get(&tftp_server, "/test.txt", None)?;
    assert_eq!(data["enable_tftp"], true);
    assert!(data["allow_read"].is_null());
    assert!(data["own"].as_object().unwrap().is_empty());
    let downloaded = tftp_get(tftp_server.tftp_addr(), "test.txt", None)
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;
    assert_eq!(downloaded, b"This is test.txt");
    Ok(())
}

#[rstest]
fn tftp_handles_non_ascii_names(
    #[with(&["--allow-all"])] tftp_server: TestServerTftp,
) -> anyhow::Result<()> {
    let resp = acl_put(
        &tftp_server,
        &format!("/{BIN_FILE}"),
        json!({"enable_tftp": true}),
        None,
    )?;
    assert_eq!(resp.status(), 204);
    let downloaded = tftp_get(tftp_server.tftp_addr(), BIN_FILE, None)
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;
    assert_eq!(downloaded, b"bin\0\x00123");
    Ok(())
}

#[rstest]
fn tftp_options_and_multiblock_file(
    #[with(&["--allow-all"])] tftp_server: TestServerTftp,
) -> anyhow::Result<()> {
    let content: Vec<u8> = (0..300_000).map(|index| (index % 251) as u8).collect();
    std::fs::write(tftp_server.path().join("big.bin"), &content)?;
    let resp = acl_put(
        &tftp_server,
        "/big.bin",
        json!({"allow_read": ["guest"], "allow_write": [], "deny_read": [], "enable_tftp": true}),
        None,
    )?;
    assert_eq!(resp.status(), 204);

    let downloaded = tftp_get(tftp_server.tftp_addr(), "big.bin", Some(1468))
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;
    assert_eq!(downloaded, content);
    Ok(())
}

#[rstest]
fn tftp_requires_guest_read(
    #[with(&[
        "--allow-all",
        "--auth",
        "admin:pass@/:rwx",
        "--auth",
        "guest:pass@/:r",
    ])]
    tftp_server: TestServerTftp,
) -> anyhow::Result<()> {
    let admin = Some(("admin", "pass"));
    let resp = acl_put(
        &tftp_server,
        "/test.txt",
        json!({"allow_read": ["guest"], "allow_write": [], "deny_read": [], "enable_tftp": true}),
        admin,
    )?;
    assert_eq!(resp.status(), 204);
    let downloaded = tftp_get(tftp_server.tftp_addr(), "test.txt", None)
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;
    assert_eq!(downloaded, b"This is test.txt");

    // Removing guest read forces the tftp switch off and denies the transfer.
    let resp = acl_put(
        &tftp_server,
        "/test.txt",
        json!({"allow_read": [], "allow_write": [], "deny_read": ["guest"]}),
        admin,
    )?;
    assert_eq!(resp.status(), 204);
    let data = acl_get(&tftp_server, "/test.txt", admin)?;
    assert_eq!(data["guest_readable"], false);
    assert_eq!(data["enable_tftp"], false);
    let err = tftp_get(tftp_server.tftp_addr(), "test.txt", None).unwrap_err();
    assert_eq!(err.0, 2);

    // It cannot be enabled while guest is denied.
    let resp = acl_put(
        &tftp_server,
        "/test.txt",
        json!({"allow_read": [], "allow_write": [], "deny_read": ["guest"], "enable_tftp": true}),
        admin,
    )?;
    assert_eq!(resp.status(), 400);
    Ok(())
}

#[rstest]
fn tftp_respects_ip_whitelist(
    #[with(&["--allow-all", "--ip-whitelist", "203.0.113.9@/test.txt"])]
    tftp_server: TestServerTftp,
) -> anyhow::Result<()> {
    // Omit ips so the initial whitelist is preserved.
    let resp = acl_put(
        &tftp_server,
        "/test.txt",
        json!({"allow_read": ["guest"], "allow_write": [], "deny_read": [], "enable_tftp": true}),
        None,
    )?;
    assert_eq!(resp.status(), 204);
    let err = tftp_get(tftp_server.tftp_addr(), "test.txt", None).unwrap_err();
    assert_eq!(err.0, 2);
    Ok(())
}

#[rstest]
fn tftp_with_path_prefix(
    #[with(&["--allow-all", "--path-prefix", "files"])] tftp_server: TestServerTftp,
) -> anyhow::Result<()> {
    // TestServer::url() points at the server root; the management api lives
    // below the configured path prefix.
    let resp = reqwest::blocking::Client::new()
        .put(format!(
            "{}files/__dufs__/acl?path=%2Ftest.txt",
            tftp_server.url()
        ))
        .json(&json!({"allow_read": ["guest"], "allow_write": [], "deny_read": [], "enable_tftp": true}))
        .send()?;
    assert_eq!(resp.status(), 204);
    let downloaded = tftp_get(tftp_server.tftp_addr(), "test.txt", None)
        .map_err(|err| anyhow::anyhow!("{err:?}"))?;
    assert_eq!(downloaded, b"This is test.txt");
    Ok(())
}

#[rstest]
fn tftp_delete_removes_the_switch(
    #[with(&["--allow-all"])] tftp_server: TestServerTftp,
) -> anyhow::Result<()> {
    let resp = acl_put(
        &tftp_server,
        "/test.txt",
        json!({"allow_read": ["guest"], "allow_write": [], "deny_read": [], "enable_tftp": true}),
        None,
    )?;
    assert_eq!(resp.status(), 204);
    let resp = reqwest::blocking::Client::new()
        .delete(acl_url(&tftp_server, "/test.txt"))
        .send()?;
    assert_eq!(resp.status(), 204);
    let data = acl_get(&tftp_server, "/test.txt", None)?;
    assert_eq!(data["enable_tftp"], false);
    assert!(data["own_enable_tftp"].is_null());
    let err = tftp_get(tftp_server.tftp_addr(), "test.txt", None).unwrap_err();
    assert_eq!(err.0, 2);
    Ok(())
}
