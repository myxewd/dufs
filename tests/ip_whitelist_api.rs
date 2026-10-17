mod fixtures;
mod utils;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use fixtures::{server, Error, TestServer};
use rstest::rstest;

fn api_url(server: &TestServer) -> String {
    format!("{}__dufs__/ip-whitelist", server.url())
}

fn get_api(server: &TestServer) -> Result<serde_json::Value, Error> {
    let resp = fetch!(b"GET", &api_url(server)).send()?;
    assert_eq!(resp.status(), 200);
    Ok(serde_json::from_str(&resp.text()?)?)
}

#[rstest]
fn webui_exposes_the_manager(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    assert_eq!(resp.status(), 200);
    let text = resp.text()?;
    assert!(text.contains("id=\"whitelistModal\""));
    assert!(text.contains("ip-whitelist-btn"));

    // the embedded index data advertises the flag to the ui
    let marker = "<template id=\"index-data\">";
    let start = text.find(marker).expect("index data") + marker.len();
    let end = start + text[start..].find("</template>").expect("index data end");
    let decoded = String::from_utf8(STANDARD.decode(&text[start..end])?)?;
    assert!(decoded.contains("\"allow_ip_whitelist\":true"));
    Ok(())
}

#[rstest]
fn webui_manager_hidden_without_flag(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    let text = resp.text()?;
    let marker = "<template id=\"index-data\">";
    let start = text.find(marker).expect("index data") + marker.len();
    let end = start + text[start..].find("</template>").expect("index data end");
    let decoded = String::from_utf8(STANDARD.decode(&text[start..end])?)?;
    assert!(decoded.contains("\"allow_ip_whitelist\":false"));
    Ok(())
}
#[rstest]
fn api_disabled_without_flag(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", &api_url(&server)).send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn api_get_empty(#[with(&["--allow-ip-whitelist"])] server: TestServer) -> Result<(), Error> {
    let data = get_api(&server)?;
    assert_eq!(data["rules"], serde_json::json!({}));
    Ok(())
}

#[rstest]
fn api_put_applies_and_persists(
    #[with(&["--allow-ip-whitelist"])] server: TestServer,
) -> Result<(), Error> {
    let body = serde_json::json!({ "version": 1, "rules": { "/dir1": [] } });
    let resp = fetch!(b"PUT", &api_url(&server))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()?;
    assert_eq!(resp.status(), 204);

    // persisted under .dufs
    assert!(server.path().join(".dufs/ip-whitelist.json").is_file());

    // enforced immediately, without a restart; the ip whitelist is the
    // highest layer, so even a manager cannot browse the denied directory
    assert_eq!(
        reqwest::blocking::get(format!("{}dir1/", server.url()))?.status(),
        403
    );
    // ... and its files stay inaccessible
    assert_eq!(
        reqwest::blocking::get(format!("{}dir1/test.txt", server.url()))?.status(),
        403
    );
    assert_eq!(
        reqwest::blocking::get(format!("{}dir2/", server.url()))?.status(),
        200
    );

    // readable back
    let data = get_api(&server)?;
    assert_eq!(data["rules"]["/dir1"], serde_json::json!([]));
    Ok(())
}

#[rstest]
fn api_put_rejects_invalid_ip(
    #[with(&["--allow-ip-whitelist"])] server: TestServer,
) -> Result<(), Error> {
    let body = serde_json::json!({ "version": 1, "rules": { "/dir1": ["not-an-ip"] } });
    let resp = fetch!(b"PUT", &api_url(&server))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()?;
    assert_eq!(resp.status(), 400);
    Ok(())
}

#[rstest]
fn api_delete_clears_rules(
    #[with(&["--allow-ip-whitelist"])] server: TestServer,
) -> Result<(), Error> {
    let body = serde_json::json!({ "version": 1, "rules": { "/dir1": [] } });
    fetch!(b"PUT", &api_url(&server))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()?;
    assert_eq!(
        reqwest::blocking::get(format!("{}dir1/test.txt", server.url()))?.status(),
        403
    );

    let resp = fetch!(b"DELETE", &api_url(&server)).send()?;
    assert_eq!(resp.status(), 204);
    assert_eq!(
        reqwest::blocking::get(format!("{}dir1/test.txt", server.url()))?.status(),
        200
    );
    assert_eq!(get_api(&server)?["rules"], serde_json::json!({}));
    Ok(())
}

#[rstest]
fn api_requires_write_permission(
    #[with(&["--allow-ip-whitelist", "-a", "@/"])] server: TestServer,
) -> Result<(), Error> {
    let resp = fetch!(b"GET", &api_url(&server)).send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn api_requires_auth_when_configured(
    #[with(&["--allow-ip-whitelist", "-a", "user:pass@/:rw"])] server: TestServer,
) -> Result<(), Error> {
    let resp = fetch!(b"GET", &api_url(&server)).send()?;
    assert_eq!(resp.status(), 401);
    Ok(())
}

#[rstest]
fn cli_rules_seed_the_store(
    #[with(&[
        "--ip-whitelist",
        "127.0.0.1,::1@/dir1",
        "--allow-ip-whitelist",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    assert!(server.path().join(".dufs/ip-whitelist.json").is_file());
    let data = get_api(&server)?;
    assert_eq!(data["rules"]["/dir1"][0], "127.0.0.1");
    assert_eq!(data["rules"]["/dir1"][1], "::1");
    Ok(())
}

#[rstest]
fn metadata_dir_is_never_served(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    // create the store through the api
    let body = serde_json::json!({ "version": 1, "rules": {} });
    fetch!(b"PUT", &api_url(&server))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()?;
    assert!(server.path().join(".dufs/ip-whitelist.json").is_file());

    for path in [".dufs/", ".dufs/ip-whitelist.json"] {
        let resp = reqwest::blocking::get(format!("{}{}", server.url(), path))?;
        assert_eq!(resp.status(), 404, "{path}");
    }

    let resp = reqwest::blocking::get(format!("{}?simple", server.url()))?;
    let text = resp.text()?;
    assert!(!text.contains(".dufs"));
    Ok(())
}

fn put_rules(server: &TestServer, rules: serde_json::Value) -> Result<(), Error> {
    let body = serde_json::json!({ "version": 1, "rules": rules });
    let resp = fetch!(b"PUT", &api_url(server))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()?;
    assert_eq!(resp.status(), 204);
    Ok(())
}

fn find_path(server: &TestServer, name: &str) -> serde_json::Value {
    let resp = reqwest::blocking::get(format!("{}?json", server.url())).unwrap();
    let data: serde_json::Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    data["paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .cloned()
        .unwrap()
}

#[rstest]
fn manager_is_ip_limited(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    put_rules(&server, serde_json::json!({ "/dir1": [] }))?;

    // the ip whitelist is the highest layer: a blocked path is hidden even
    // from an acl manager
    let resp = reqwest::blocking::get(format!("{}?json", server.url()))?;
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert!(!data["paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["name"] == "dir1"));
    assert_eq!(
        reqwest::blocking::get(format!("{}dir1/", server.url()))?.status(),
        403
    );
    Ok(())
}

#[rstest]
fn whitelist_column_values(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    put_rules(
        &server,
        serde_json::json!({ "/dir1": ["127.0.0.1", "10.0.0.0/8"], "/dir2": ["0.0.0.0/0", "::/0"] }),
    )?;

    assert_eq!(
        find_path(&server, "dir1")["whitelist"],
        "127.0.0.1, 10.0.0.0/8"
    );
    // an allow-all rule renders as unrestricted
    assert_eq!(find_path(&server, "dir2")["whitelist"], "");
    Ok(())
}

#[rstest]
fn api_reports_effective_whitelist(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    put_rules(&server, serde_json::json!({ "/dir1": [] }))?;

    let effective = |path: &str| -> Result<serde_json::Value, Error> {
        let url = format!("{}?path={}", api_url(&server), urlencoding::encode(path));
        let data: serde_json::Value = serde_json::from_str(&fetch!(b"GET", &url).send()?.text()?)?;
        Ok(data["effective"].clone())
    };

    // an explicit empty rule is blocked
    assert_eq!(effective("/dir1")?, serde_json::json!([]));
    // a path with no rule of its own is unrestricted (null)
    assert_eq!(effective("/dir2")?, serde_json::Value::Null);
    // a path below a blocked directory inherits the block
    assert_eq!(effective("/dir1/test.txt")?, serde_json::json!([]));
    Ok(())
}
