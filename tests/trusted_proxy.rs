mod fixtures;
mod utils;

use assert_fs::fixture::TempDir;
use fixtures::{port, server, tmpdir, wait_for_port, Error, Port, TestServer};
use rstest::rstest;
use std::io::Read;
use std::process::{Command, Stdio};

fn request(
    server: &TestServer,
    header: Option<(&str, &str)>,
) -> Result<reqwest::blocking::Response, Error> {
    let url = format!("{}dir1/test.txt", server.url());
    let builder = fetch!(b"GET", &url);
    let builder = match header {
        Some((name, value)) => builder.header(name, value),
        None => builder,
    };
    Ok(builder.send()?)
}

#[rstest]
fn forwarded_header_ignored_without_trusted_proxy(
    #[with(&["--ip-whitelist", "203.0.113.9@/dir1"])] server: TestServer,
) -> Result<(), Error> {
    assert_eq!(request(&server, None)?.status(), 403);
    assert_eq!(
        request(&server, Some(("X-Forwarded-For", "203.0.113.9")))?.status(),
        403
    );
    Ok(())
}

#[rstest]
fn trusted_proxy_uses_forwarded_ip(
    #[with(&[
        "--ip-whitelist",
        "203.0.113.9@/dir1",
        "--trusted-proxy",
        "127.0.0.1,::1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    // without the header the socket peer is not whitelisted
    assert_eq!(request(&server, None)?.status(), 403);
    // the trusted proxy's forwarded header identifies the client
    assert_eq!(
        request(&server, Some(("X-Forwarded-For", "203.0.113.9")))?.status(),
        200
    );
    Ok(())
}

#[rstest]
fn forwarded_chain_skips_trusted_hops(
    #[with(&[
        "--ip-whitelist",
        "203.0.113.9@/dir1",
        "--trusted-proxy",
        "127.0.0.1,::1,10.0.0.0/8",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let resp = request(&server, Some(("X-Forwarded-For", "203.0.113.9, 10.1.2.3")))?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn x_real_ip_is_fallback(
    #[with(&[
        "--ip-whitelist",
        "203.0.113.9@/dir1",
        "--trusted-proxy",
        "127.0.0.1,::1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    assert_eq!(
        request(&server, Some(("X-Real-IP", "203.0.113.9")))?.status(),
        200
    );
    Ok(())
}

#[rstest]
fn untrusted_peer_cannot_spoof(
    #[with(&[
        "--ip-whitelist",
        "203.0.113.9@/dir1",
        "--trusted-proxy",
        "10.0.0.0/8",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    // the peer is localhost, which is not in the trusted list, so the header
    // must be ignored
    assert_eq!(
        request(&server, Some(("X-Forwarded-For", "203.0.113.9")))?.status(),
        403
    );
    Ok(())
}

#[rstest]
fn log_uses_the_forwarded_ip(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .args([
            "--ip-whitelist",
            "203.0.113.9@/",
            "--trusted-proxy",
            "127.0.0.1,::1",
            "--log-format",
            "$remote_addr",
        ])
        .stdout(Stdio::piped())
        .spawn()?;

    wait_for_port(&port);

    let resp = fetch!(b"GET", &format!("http://localhost:{port}/"))
        .header("X-Forwarded-For", "203.0.113.9")
        .send()?;
    assert_eq!(resp.status(), 200);

    let stdout = child.stdout.as_mut().expect("Failed to get stdout");
    let mut buf = [0; 2048];
    let len = stdout.read(&mut buf)?;
    let output = std::str::from_utf8(&buf[..len])?;
    assert!(output.contains("203.0.113.9"), "log was: {output}");

    child.kill()?;
    Ok(())
}
