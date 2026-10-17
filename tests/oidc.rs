mod fixtures;
mod utils;

use assert_fs::fixture::TempDir;
use fixtures::{port, tmpdir, wait_for_port, Error, Port};
use rstest::rstest;
use std::process::{Command, Stdio};

fn start_oidc(tmpdir: &TempDir, port: &Port) -> Result<std::process::Child, Error> {
    let redirect = format!("http://localhost:{port}/__dufs__/oidc/callback");
    Ok(Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("--auth-type")
        .arg("oidc")
        .arg("--auth")
        .arg("user:pass@/:rw")
        .env_remove("DUFS_OIDC_ISSUER")
        .env("DUFS_OIDC_ISSUER", "http://127.0.0.1:1/")
        .env("DUFS_OIDC_CLIENT_ID", "dufs")
        .env("DUFS_OIDC_CLIENT_SECRET", "secret")
        .env("DUFS_OIDC_REDIRECT_URI", redirect)
        .stdout(Stdio::null())
        .spawn()?)
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

#[rstest]
fn unauthenticated_redirects_to_login(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    let mut child = start_oidc(&tmpdir, &port)?;
    wait_for_port(&port);
    let resp = client().get(format!("http://localhost:{port}/")).send()?;
    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("location").unwrap().to_str()?;
    assert!(
        location.starts_with("/__dufs__/oidc/login?next="),
        "{location}"
    );
    child.kill()?;
    Ok(())
}

#[rstest]
fn login_endpoint_reports_unavailable_provider(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    let mut child = start_oidc(&tmpdir, &port)?;
    wait_for_port(&port);
    let resp = client()
        .get(format!("http://localhost:{port}/__dufs__/oidc/login"))
        .send()?;
    assert_eq!(resp.status(), 502);
    child.kill()?;
    Ok(())
}

#[rstest]
fn logout_clears_session_cookie(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    let mut child = start_oidc(&tmpdir, &port)?;
    wait_for_port(&port);
    let resp = client()
        .get(format!("http://localhost:{port}/__dufs__/oidc/logout"))
        .send()?;
    assert_eq!(resp.status(), 302);
    let cookie = resp.headers().get("set-cookie").unwrap().to_str()?;
    assert!(cookie.contains("dufs_oidc_session=;"), "{cookie}");
    assert!(cookie.contains("Max-Age=0"), "{cookie}");
    child.kill()?;
    Ok(())
}

#[test]
fn oidc_requires_configuration() -> Result<(), Error> {
    let tmpdir = assert_fs::TempDir::new()?;
    let output = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("--auth-type")
        .arg("oidc")
        .arg("--auth")
        .arg("user:pass@/:rw")
        .env_remove("DUFS_OIDC_ISSUER")
        .env_remove("DUFS_OIDC_CLIENT_ID")
        .env_remove("DUFS_OIDC_REDIRECT_URI")
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("DUFS_OIDC_ISSUER"), "stderr: {stderr}");
    Ok(())
}

#[test]
fn oidc_requires_auth_users() -> Result<(), Error> {
    let tmpdir = assert_fs::TempDir::new()?;
    let output = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("--auth-type")
        .arg("oidc")
        .env("DUFS_OIDC_ISSUER", "http://127.0.0.1:1/")
        .env("DUFS_OIDC_CLIENT_ID", "dufs")
        .env("DUFS_OIDC_REDIRECT_URI", "http://localhost/cb")
        .env_remove("DUFS_AUTH")
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires at least one --auth rule"),
        "stderr: {stderr}"
    );
    Ok(())
}
