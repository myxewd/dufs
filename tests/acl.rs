mod digest_auth_util;
mod fixtures;
mod utils;

use assert_fs::fixture::TempDir;
use digest_auth_util::send_with_digest_auth;
use fixtures::{port, tmpdir, wait_for_port, Error, Port};
use rstest::rstest;
use std::process::{Child, Command, Stdio};

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

fn start_acl(tmpdir: &TempDir, port: &Port, guest: &str) -> Result<Child, Error> {
    Ok(Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("-A")
        .arg("--auth")
        .arg(guest)
        .arg("--auth")
        .arg("admin:admin@/:rwx")
        .stdout(Stdio::null())
        .spawn()?)
}

fn names(data: &serde_json::Value) -> Vec<String> {
    data["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap().to_string())
        .collect()
}

#[rstest]
fn acl_controls_read_write_and_x(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    let base = format!("http://localhost:{port}");
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("-A")
        .arg("--allow-ip-whitelist")
        .arg("--auth")
        .arg("guest:guest@/:ro")
        .arg("--auth")
        .arg("alice:alice@/dir2:ro")
        .arg("--auth")
        .arg("bob:bob@/dir2:ro")
        .arg("--auth")
        .arg("admin:admin@/:rwx")
        .stdout(Stdio::null())
        .spawn()?;
    wait_for_port(&port);

    // without x the acl is not editable
    let resp = client()
        .put(format!("{base}/__dufs__/acl?path=/dir1"))
        .basic_auth("alice", Some("alice"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(
            &serde_json::json!({ "allow_read": ["alice"] }),
        )?)
        .send()?;
    assert!(resp.status().is_client_error(), "{}", resp.status());

    // admin has x and can set the read/deny lists
    let resp = client()
        .put(format!("{base}/__dufs__/acl?path=/dir1"))
        .basic_auth("admin", Some("admin"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&serde_json::json!({
            "allow_read": ["alice"],
            "deny_read": ["guest"],
        }))?)
        .send()?;
    assert_eq!(resp.status(), 204);

    // write implies read; bob may upload into /dir3
    let resp = client()
        .put(format!("{base}/__dufs__/acl?path=/dir3"))
        .basic_auth("admin", Some("admin"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(
            &serde_json::json!({ "allow_write": ["bob"] }),
        )?)
        .send()?;
    assert_eq!(resp.status(), 204);

    // alice gains read access to /dir1 even though --auth only grants /dir2
    let resp = client()
        .get(format!("{base}/dir1/test.txt"))
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 200);

    // the acl denies guest on /dir1
    let resp = client().get(format!("{base}/dir1/test.txt")).send()?;
    assert_eq!(resp.status(), 403);

    // bob may write and, because write implies read, read it back
    let resp = client()
        .put(format!("{base}/dir3/new.txt"))
        .basic_auth("bob", Some("bob"))
        .body("new")
        .send()?;
    assert_eq!(resp.status(), 201);
    let resp = client()
        .get(format!("{base}/dir3/new.txt"))
        .basic_auth("bob", Some("bob"))
        .send()?;
    assert_eq!(resp.status(), 200);

    // alice is not mentioned on /dir3
    let resp = client()
        .get(format!("{base}/dir3/new.txt"))
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 403);

    // listing: alice sees /dir1 (acl) and /dir2 (native); guest does not see /dir1
    let resp = client()
        .get(format!("{base}/?json"))
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    let alice_names = names(&data);
    assert!(alice_names.contains(&"dir1".to_string()), "{alice_names:?}");
    assert!(alice_names.contains(&"dir2".to_string()), "{alice_names:?}");
    assert!(
        !alice_names.contains(&"dir3".to_string()),
        "{alice_names:?}"
    );

    let resp = client().get(format!("{base}/?json")).send()?;
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    let guest_names = names(&data);
    assert!(
        !guest_names.contains(&"dir1".to_string()),
        "{guest_names:?}"
    );

    // the acl deny also keeps the path out of search results
    let resp = client().get(format!("{base}/?q=test&json")).send()?;
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    let guest_search = names(&data);
    assert!(
        !guest_search.iter().any(|n| n.starts_with("dir1/")),
        "{guest_search:?}"
    );

    // the listing exposes the user acl summary; x users are marked with *
    let resp = client()
        .get(format!("{base}/?json"))
        .basic_auth("admin", Some("admin"))
        .send()?;
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    let dir1 = data["paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "dir1")
        .unwrap();
    assert!(
        dir1["allow_read"].as_str().unwrap().contains("alice"),
        "{dir1}"
    );
    assert!(
        !dir1["allow_read"].as_str().unwrap().contains("admin*"),
        "{dir1}"
    );
    assert!(
        dir1["allow_write"].as_str().unwrap().contains("admin*"),
        "{dir1}"
    );

    // the combined acl api reports the effective lists
    let resp = client()
        .get(format!("{base}/__dufs__/acl?path=/dir1"))
        .basic_auth("admin", Some("admin"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert_eq!(data["allow_read"], serde_json::json!(["alice"]));
    assert_eq!(data["deny_read"], serde_json::json!(["guest"]));
    assert!(data["ips"].is_null());
    assert_eq!(data["x_users"], serde_json::json!(["admin"]));
    let version = data["version"].as_str().unwrap().to_string();

    let acl_url = format!("{base}/__dufs__/acl?path=/dir1");
    let put = |body: serde_json::Value| -> Result<reqwest::blocking::Response, Error> {
        Ok(client()
            .put(&acl_url)
            .basic_auth("admin", Some("admin"))
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body)?)
            .send()?)
    };

    // stale version is rejected
    let resp = put(serde_json::json!({ "version": "stale" }))?;
    assert_eq!(resp.status(), 409);

    // allow and deny may not contain the same user
    let resp = put(serde_json::json!({
        "version": version.clone(),
        "allow_read": ["alice"],
        "deny_read": ["alice"],
    }))?;
    assert_eq!(resp.status(), 400);

    // x users always win and may not be denied
    let resp = put(serde_json::json!({
        "version": version.clone(),
        "deny_read": ["admin"],
    }))?;
    assert_eq!(resp.status(), 400);

    // allow_write auto-completes allow_read
    let resp = put(serde_json::json!({
        "version": version,
        "allow_write": ["carol"],
    }))?;
    assert_eq!(resp.status(), 204);
    let resp = client()
        .get(&acl_url)
        .basic_auth("admin", Some("admin"))
        .send()?;
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert!(data["allow_read"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "carol"));
    assert_eq!(data["allow_write"], serde_json::json!(["carol"]));

    // removing the rule falls back to --auth
    let resp = client()
        .delete(format!("{base}/__dufs__/acl?path=/dir1"))
        .basic_auth("admin", Some("admin"))
        .send()?;
    assert_eq!(resp.status(), 204);
    let resp = client()
        .get(format!("{base}/dir1/test.txt"))
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 403);

    child.kill()?;
    Ok(())
}
#[rstest]
fn acl_rules_follow_a_move(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    // carol may write the tree but is denied /team/secret: renaming /team must
    // carry the deny along, otherwise the content lands in an area she may read
    std::fs::create_dir_all(tmpdir.path().join(".dufs"))?;
    std::fs::create_dir_all(tmpdir.path().join("team/secret"))?;
    std::fs::write(tmpdir.path().join("team/secret/leak.txt"), "leaked")?;
    std::fs::write(
        tmpdir.path().join(".dufs/user-acl.json"),
        r#"{ "version": 1, "rules": {
            "/": { "allow_write": ["carol"] },
            "/team/secret": { "deny_read": ["carol"] }
        } }"#,
    )?;
    std::fs::write(
        tmpdir.path().join(".dufs/ip-whitelist.json"),
        r#"{ "version": 1, "rules": { "/team/secret": ["127.0.0.1"] } }"#,
    )?;
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("-A")
        .arg("--allow-ip-whitelist")
        .arg("--auth")
        .arg("guest:guest@/:ro")
        .arg("--auth")
        .arg("carol:carol@/:rw")
        .arg("--auth")
        .arg("admin:admin@/:rwx")
        .stdout(Stdio::null())
        .spawn()?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();
    let get = |as_user: &str, path: &str| -> Result<reqwest::blocking::Response, Error> {
        Ok(client
            .get(format!("{base}{path}"))
            .basic_auth(as_user, Some(as_user))
            .send()?)
    };

    assert_eq!(get("carol", "/team/secret/leak.txt")?.status(), 403);
    let resp = client
        .request(
            reqwest::Method::from_bytes(b"MOVE")?,
            format!("{base}/team"),
        )
        .basic_auth("carol", Some("carol"))
        .header("destination", format!("http://localhost:{port}/team2"))
        .send()?;
    assert_eq!(resp.status(), 204);
    // the deny moved with the content: still no access at the new path
    assert_eq!(get("carol", "/team2/secret/leak.txt")?.status(), 403);
    // the admin sees the file where it now is
    let resp = get("admin", "/team2/secret/leak.txt")?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "leaked");

    // both stores report the rule at its new path and nothing at the old one
    let acl = |path: &str| -> Result<serde_json::Value, Error> {
        let resp = get("admin", &format!("/__dufs__/acl?path={path}"))?;
        assert_eq!(resp.status(), 200);
        Ok(serde_json::from_str(&resp.text()?)?)
    };
    assert_eq!(
        acl("/team2/secret")?["deny_read"],
        serde_json::json!(["carol"])
    );
    assert!(acl("/team/secret")?["deny_read"].is_null());
    let resp = get("admin", "/__dufs__/ip-whitelist")?;
    let ips: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert_eq!(
        ips["rules"]["/team2/secret"],
        serde_json::json!(["127.0.0.1"])
    );
    assert!(ips["rules"]["/team/secret"].is_null());

    // a destination that already carries rules is refused instead of merging
    let resp = client
        .put(format!("{base}/__dufs__/acl?path=/blocked"))
        .basic_auth("admin", Some("admin"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(
            &serde_json::json!({ "allow_read": ["bob"] }),
        )?)
        .send()?;
    assert_eq!(resp.status(), 204);
    let resp = client
        .request(
            reqwest::Method::from_bytes(b"MOVE")?,
            format!("{base}/team2"),
        )
        .basic_auth("carol", Some("carol"))
        .header("destination", format!("http://localhost:{port}/blocked"))
        .send()?;
    assert_eq!(resp.status(), 409);
    // nothing moved on disk either
    assert_eq!(get("admin", "/team2/secret/leak.txt")?.status(), 200);
    assert_eq!(get("carol", "/team2/secret/leak.txt")?.status(), 403);

    child.kill()?;
    Ok(())
}

#[rstest]
fn acl_rules_are_dropped_with_the_content(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    // deleting a path has to drop the rules that describe it, otherwise a new
    // entry created at the same path silently inherits them
    std::fs::create_dir_all(tmpdir.path().join(".dufs"))?;
    std::fs::create_dir_all(tmpdir.path().join("team/secret"))?;
    std::fs::write(tmpdir.path().join("team/secret/old.txt"), "old")?;
    std::fs::write(
        tmpdir.path().join(".dufs/user-acl.json"),
        r#"{ "version": 1, "rules": {
            "/": { "allow_write": ["carol"] },
            "/team/secret": { "deny_read": ["carol"] },
            "/team2": { "allow_read": ["bob"] }
        } }"#,
    )?;
    std::fs::write(
        tmpdir.path().join(".dufs/ip-whitelist.json"),
        r#"{ "version": 1, "rules": { "/team/secret": [] } }"#,
    )?;
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("-A")
        .arg("--allow-ip-whitelist")
        .arg("--auth")
        .arg("guest:guest@/:ro")
        .arg("--auth")
        .arg("carol:carol@/:rw")
        .arg("--auth")
        .arg("admin:admin@/:rwx")
        .stdout(Stdio::null())
        .spawn()?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();

    let resp = client
        .delete(format!("{base}/team"))
        .basic_auth("carol", Some("carol"))
        .send()?;
    assert_eq!(resp.status(), 204);

    let get = |as_user: &str, path: &str| -> Result<reqwest::blocking::Response, Error> {
        Ok(client
            .get(format!("{base}{path}"))
            .basic_auth(as_user, Some(as_user))
            .send()?)
    };
    // both stores forgot the deleted subtree
    let acl: serde_json::Value =
        serde_json::from_str(&get("admin", "/__dufs__/acl?path=/team/secret")?.text()?)?;
    assert!(acl["deny_read"].is_null(), "{acl}");
    let ips: serde_json::Value =
        serde_json::from_str(&get("admin", "/__dufs__/ip-whitelist")?.text()?)?;
    assert!(ips["rules"]["/team/secret"].is_null(), "{ips}");
    // a rule on a sibling is untouched
    let acl: serde_json::Value =
        serde_json::from_str(&get("admin", "/__dufs__/acl?path=/team2")?.text()?)?;
    assert_eq!(acl["allow_read"], serde_json::json!(["bob"]));

    // recreating the path starts from the inherited rule, not from the stale one
    let mkdir = |path: &str| -> Result<reqwest::blocking::Response, Error> {
        Ok(client
            .request(
                reqwest::Method::from_bytes(b"MKCOL")?,
                format!("{base}{path}"),
            )
            .basic_auth("carol", Some("carol"))
            .send()?)
    };
    assert_eq!(mkdir("/team")?.status(), 201);
    assert_eq!(mkdir("/team/secret")?.status(), 201);
    let resp = client
        .put(format!("{base}/team/secret/new.txt"))
        .basic_auth("carol", Some("carol"))
        .body("new")
        .send()?;
    assert_eq!(resp.status(), 201);
    let resp = get("carol", "/team/secret/new.txt")?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "new");

    child.kill()?;
    Ok(())
}

#[rstest]
fn acl_traverse_works_without_ancestor_rules(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    // Only the granted path carries a rule: nothing covers / or the
    // intermediate directories, so --auth refuses them (a user that is not in
    // the --auth tree, or an index-only root). The grant still has to be
    // reachable from the file list.
    std::fs::create_dir_all(tmpdir.path().join(".dufs"))?;
    std::fs::create_dir_all(tmpdir.path().join("data/team/reports"))?;
    std::fs::write(tmpdir.path().join("data/team/reports/q3.pdf"), "q3")?;
    std::fs::write(tmpdir.path().join("data/team/other.txt"), "other")?;
    std::fs::write(
        tmpdir.path().join(".dufs/user-acl.json"),
        r#"{ "version": 1, "rules": { "/data/team/reports": { "allow_read": ["alice"] } } }"#,
    )?;
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("-A")
        .arg("--auth")
        // index-only root, like a guest that may only see the landing page
        .arg("guest:guest@/dir-no-found")
        .arg("--auth")
        // a real user with no access path of its own
        .arg("alice:alice@/dir-no-found")
        .arg("--auth")
        .arg("admin:admin@/:rwx")
        .stdout(Stdio::null())
        .spawn()?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();
    let get = |as_user: &str, path: &str| -> Result<reqwest::blocking::Response, Error> {
        Ok(client
            .get(format!("{base}{path}"))
            .basic_auth(as_user, Some(as_user))
            .send()?)
    };
    let names_of = |as_user: &str, path: &str| -> Result<Vec<String>, Error> {
        let resp = get(as_user, path)?;
        assert_eq!(resp.status(), 200, "{path}");
        let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
        Ok(names(&data))
    };

    // the whole ancestor chain is walkable, step by step
    assert_eq!(names_of("alice", "/?json")?, vec!["data".to_string()]);
    assert_eq!(names_of("alice", "/data/?json")?, vec!["team".to_string()]);
    assert_eq!(
        names_of("alice", "/data/team/?json")?,
        vec!["reports".to_string()]
    );
    assert_eq!(
        names_of("alice", "/data/team/reports/?json")?,
        vec!["q3.pdf".to_string()]
    );
    let resp = get("alice", "/data/team/reports/q3.pdf")?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "q3");
    // a sibling that is not granted is still hidden and refused
    assert_eq!(get("alice", "/data/team/other.txt")?.status(), 403);

    // walking never allows writing
    let resp = client
        .put(format!("{base}/data/new.txt"))
        .basic_auth("alice", Some("alice"))
        .body("x")
        .send()?;
    assert_eq!(resp.status(), 403);
    let resp = client
        .request(
            reqwest::Method::from_bytes(b"MKCOL")?,
            format!("{base}/data/newdir"),
        )
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 403);
    // search reaches through the unmanaged ancestors as well
    let resp = get("alice", "/?q=q3&json")?;
    assert_eq!(resp.status(), 200);
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert_eq!(names(&data), vec!["data/team/reports/q3.pdf".to_string()]);

    // an anonymous visitor is unchanged: the landing page lists nothing
    assert_eq!(names_of("guest", "/?json")?, Vec::<String>::new());

    child.kill()?;
    Ok(())
}

#[rstest]
fn acl_traverse_with_render_index(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    // /a has an index page the user may not read, but she must still be able to
    // walk to /a/b where she is granted
    std::fs::create_dir_all(tmpdir.path().join(".dufs"))?;
    std::fs::create_dir_all(tmpdir.path().join("a/b"))?;
    std::fs::write(tmpdir.path().join("a/index.html"), "a index")?;
    std::fs::write(tmpdir.path().join("a/b/target.txt"), "target")?;
    std::fs::write(
        tmpdir.path().join(".dufs/user-acl.json"),
        r#"{ "version": 1, "rules": {
            "/": { "allow_read": ["bob"] },
            "/a/b": { "allow_read": ["alice"] }
        } }"#,
    )?;
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("--render-try-index")
        .arg("--auth")
        .arg("guest:guest@/:ro")
        .arg("--auth")
        .arg("bob:bob@/:ro")
        .arg("--auth")
        .arg("alice:alice@/:ro")
        .arg("--auth")
        .arg("admin:admin@/:rwx")
        .stdout(Stdio::null())
        .spawn()?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();

    let resp = client
        .get(format!("{base}/a/?json"))
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert_eq!(names(&data), vec!["b".to_string()]);
    // the page itself stays private
    let resp = client
        .get(format!("{base}/a/index.html"))
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 403);
    // a user that may read the directory keeps getting the index page
    let resp = client
        .get(format!("{base}/a/"))
        .basic_auth("bob", Some("bob"))
        .send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "a index");
    // the root is only walkable, so it is listed instead of its index page
    let resp = client
        .get(format!("{base}/?json"))
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert_eq!(names(&data), vec!["a".to_string()]);

    child.kill()?;
    Ok(())
}

#[rstest]
fn acl_traverse_reaches_granted_child(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    // alice is granted one nested directory while the root only lists bob, so
    // the ancestors have to stay walkable or the grant is unreachable
    std::fs::create_dir_all(tmpdir.path().join(".dufs"))?;
    std::fs::create_dir_all(tmpdir.path().join("a/b/c"))?;
    std::fs::write(tmpdir.path().join("a/b/c/target.txt"), "target")?;
    std::fs::write(tmpdir.path().join("a/b/sibling.txt"), "sibling")?;
    std::fs::write(
        tmpdir.path().join(".dufs/user-acl.json"),
        r#"{ "version": 1, "rules": {
            "/": { "allow_read": ["bob"] },
            "/a/b/c": { "allow_read": ["alice"] },
            "/test.txt/sub": { "allow_read": ["alice"] }
        } }"#,
    )?;
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("-A")
        .arg("--auth")
        .arg("guest:guest@/:ro")
        .arg("--auth")
        .arg("bob:bob@/:ro")
        .arg("--auth")
        .arg("alice:alice@/:ro")
        .arg("--auth")
        .arg("admin:admin@/:rwx")
        .stdout(Stdio::null())
        .spawn()?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();
    let get = |path: &str| -> Result<reqwest::blocking::Response, Error> {
        Ok(client
            .get(format!("{base}{path}"))
            .basic_auth("alice", Some("alice"))
            .send()?)
    };
    let list = |path: &str| -> Result<Vec<String>, Error> {
        let resp = get(path)?;
        assert_eq!(resp.status(), 200, "{path}");
        let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
        Ok(names(&data))
    };

    // only the ancestor chain is listed, never the root's other entries
    assert_eq!(list("/?json")?, vec!["a".to_string()]);
    assert_eq!(list("/a/?json")?, vec!["b".to_string()]);
    assert_eq!(list("/a/b/?json")?, vec!["c".to_string()]);
    assert_eq!(list("/a/b/c/?json")?, vec!["target.txt".to_string()]);
    // the grant itself stays readable
    let resp = get("/a/b/c/target.txt")?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "target");
    // a sibling without a grant is still hidden and still refused
    assert_eq!(get("/a/b/sibling.txt")?.status(), 403);
    // a rule below a *file* path must not turn the file itself readable
    assert_eq!(get("/test.txt")?.status(), 403);

    // a traversed directory is a listing only: it never allows writing
    let resp = client
        .put(format!("{base}/a/new.txt"))
        .basic_auth("alice", Some("alice"))
        .body("new")
        .send()?;
    assert_eq!(resp.status(), 403);
    let resp = client
        .put(format!("{base}/a/b/new.txt"))
        .basic_auth("alice", Some("alice"))
        .body("new")
        .send()?;
    assert_eq!(resp.status(), 403);
    let resp = client
        .request(
            reqwest::Method::from_bytes(b"MKCOL")?,
            format!("{base}/a/newdir"),
        )
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 403);
    // deleting the grant still needs write on its parent, which alice lacks
    let resp = client
        .delete(format!("{base}/a/b/c/target.txt"))
        .basic_auth("alice", Some("alice"))
        .send()?;
    assert_eq!(resp.status(), 403);
    let data: serde_json::Value = serde_json::from_str(
        &client
            .get(format!("{base}/a/?json"))
            .basic_auth("alice", Some("alice"))
            .send()?
            .text()?,
    )?;
    assert_eq!(data["allow_upload"], false);
    assert_eq!(data["allow_delete"], false);

    // search reaches through a traversed directory
    let searched = list("/?q=target&json")?;
    assert_eq!(searched, vec!["a/b/c/target.txt".to_string()]);

    // bob keeps full read of the managed tree
    let bob = |path: &str| -> Result<Vec<String>, Error> {
        let resp = client
            .get(format!("{base}{path}"))
            .basic_auth("bob", Some("bob"))
            .send()?;
        assert_eq!(resp.status(), 200, "{path}");
        let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
        Ok(names(&data))
    };
    assert!(bob("/?json")?.contains(&"a".to_string()));
    assert_eq!(
        bob("/a/b/?json")?,
        vec!["c".to_string(), "sibling.txt".to_string()]
    );

    child.kill()?;
    Ok(())
}

#[rstest]
fn acl_api_and_login_challenge(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    let mut child = start_acl(&tmpdir, &port, "guest:guest@/:ro")?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();
    let acl = format!("{base}/__dufs__/acl?path=/");

    // unauthenticated guest: challenge, not 403
    let resp = client.get(&acl).send()?;
    assert_eq!(resp.status(), 401);

    // basic and digest admin both work
    let resp = client.get(&acl).basic_auth("admin", Some("admin")).send()?;
    assert_eq!(resp.status(), 200);
    let resp = send_with_digest_auth(client.get(&acl), "admin", "admin")?;
    assert_eq!(resp.status(), 200);

    // the login button forces a fresh challenge for the guest identity
    let resp = client.get(format!("{base}/?login")).send()?;
    assert_eq!(resp.status(), 401);
    let resp = client
        .get(format!("{base}/?login"))
        .basic_auth("guest", Some("guest"))
        .send()?;
    assert_eq!(resp.status(), 401);
    // a successful login drops the marker and returns to the page itself
    let resp = client
        .get(format!("{base}/?login"))
        .basic_auth("admin", Some("admin"))
        .send()?;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/"
    );

    // a subdirectory login returns to that directory
    let resp = client
        .get(format!("{base}/dir1/?login"))
        .basic_auth("admin", Some("admin"))
        .send()?;
    assert_eq!(resp.status(), 302);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/dir1/"
    );

    child.kill()?;
    Ok(())
}

#[rstest]
fn guest_without_auth_paths_is_acl_only(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    // a dummy child path gives the guest an index-only root instead of root read
    let mut child = start_acl(&tmpdir, &port, "guest:guest@/.dufs")?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();
    let resp = client
        .put(format!("{base}/__dufs__/acl?path=/dir1"))
        .basic_auth("admin", Some("admin"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(
            &serde_json::json!({ "allow_read": ["guest"] }),
        )?)
        .send()?;
    assert_eq!(resp.status(), 204);

    // the guest only sees what the acl grants, not the root's native files
    let resp = client.get(format!("{base}/?json")).send()?;
    assert_eq!(resp.status(), 200);
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    let names = names(&data);
    assert!(names.contains(&"dir1".to_string()), "{names:?}");
    assert!(!names.contains(&"test.txt".to_string()), "{names:?}");

    let resp = client.get(format!("{base}/test.txt")).send()?;
    assert!(!resp.status().is_success(), "{}", resp.status());
    let resp = client.get(format!("{base}/dir1/test.txt")).send()?;
    assert_eq!(resp.status(), 200);

    child.kill()?;
    Ok(())
}
#[rstest]
fn acl_api_accepts_digest_writes(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    let mut child = start_acl(&tmpdir, &port, "guest:guest@/:ro")?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();
    let acl = format!("{base}/__dufs__/acl?path=/dir1");

    // a digest hash is bound to the real request method: PUT and DELETE must
    // validate against PUT/DELETE even though the permission check uses GET
    let resp = send_with_digest_auth(
        client
            .put(&acl)
            .header("content-type", "application/json")
            .body(serde_json::to_string(
                &serde_json::json!({ "allow_read": ["guest"] }),
            )?),
        "admin",
        "admin",
    )?;
    assert_eq!(resp.status(), 204);

    let resp = send_with_digest_auth(client.delete(&acl), "admin", "admin")?;
    assert_eq!(resp.status(), 204);

    child.kill()?;
    Ok(())
}
#[rstest]
fn admin_x_sees_acl_denied_entry(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    std::fs::create_dir_all(tmpdir.path().join(".dufs"))?;
    std::fs::write(
        tmpdir.path().join(".dufs/user-acl.json"),
        r#"{ "version": 1, "rules": { "/test.txt": { "allow_read": ["bob"] } } }"#,
    )?;
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("--auth")
        .arg("guest:guest@/:ro")
        .arg("--auth")
        .arg("admin:admin@/:rwx")
        .stdout(Stdio::null())
        .spawn()?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();

    // the x admin sees and reads a file whose acl lists only bob
    let resp = client
        .get(format!("{base}/?json"))
        .basic_auth("admin", Some("admin"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert!(names(&data).contains(&"test.txt".to_string()), "{data}");
    let admin_item = data["paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "test.txt")
        .unwrap();
    assert_eq!(admin_item["allow_write"], "admin*");
    assert_eq!(
        client
            .get(format!("{base}/test.txt"))
            .basic_auth("admin", Some("admin"))
            .send()?
            .status(),
        200
    );

    // the guest is not listed by the managed rule
    let resp = client.get(format!("{base}/?json")).send()?;
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert!(!names(&data).contains(&"test.txt".to_string()), "{data}");
    assert_eq!(client.get(format!("{base}/test.txt")).send()?.status(), 403);
    // a viewer without x gets neither the read nor the write list
    let guest_item = data["paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "index.html")
        .unwrap();
    assert_eq!(guest_item["allow_read"], "");
    assert_eq!(guest_item["allow_write"], "");

    child.kill()?;
    Ok(())
}
#[rstest]
fn admin_x_sees_ip_blocked_entry(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    std::fs::create_dir_all(tmpdir.path().join(".dufs"))?;
    std::fs::write(
        tmpdir.path().join(".dufs/ip-whitelist.json"),
        r#"{ "version": 1, "rules": { "/test.txt": [] } }"#,
    )?;
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!())
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .arg("-A")
        .arg("--auth")
        .arg("guest:guest@/:ro")
        .arg("--auth")
        .arg("admin:admin@/:rwx")
        .stdout(Stdio::null())
        .spawn()?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();

    // the x admin still sees the ip-blocked entry, marked blocked
    let resp = client
        .get(format!("{base}/?json"))
        .basic_auth("admin", Some("admin"))
        .send()?;
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    let item = data["paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "test.txt")
        .expect("the x admin must see the blocked entry");
    assert_eq!(item["whitelist"], "blocked");

    // the content is still refused by the ip whitelist
    assert_eq!(
        client
            .get(format!("{base}/test.txt"))
            .basic_auth("admin", Some("admin"))
            .send()?
            .status(),
        403
    );

    // a guest without x does not see it
    let resp = client.get(format!("{base}/?json")).send()?;
    let data: serde_json::Value = serde_json::from_str(&resp.text()?)?;
    assert!(!names(&data).contains(&"test.txt".to_string()), "{data}");

    child.kill()?;
    Ok(())
}

#[rstest]
fn metadata_dir_is_never_exposed(tmpdir: TempDir, port: Port) -> Result<(), Error> {
    let mut child = start_acl(&tmpdir, &port, "guest:guest@/:ro")?;
    wait_for_port(&port);
    let base = format!("http://localhost:{port}");
    let client = client();

    // create the store through the management api
    let resp = client
        .put(format!("{base}/__dufs__/acl?path=/dir1"))
        .basic_auth("admin", Some("admin"))
        .body(r#"{"allow_read":["guest"],"allow_write":[],"deny_read":[]}"#)
        .send()?;
    assert_eq!(resp.status(), 204);

    for path in [
        "/.dufs/user-acl.json",
        "/.DUFS/user-acl.json",
        "/.dufs/",
        "/.dufs",
    ] {
        let resp = client
            .get(format!("{base}{path}"))
            .basic_auth("admin", Some("admin"))
            .send()?;
        assert_eq!(resp.status(), 404, "{path}");
    }

    // the root archive must not contain the metadata dir
    let resp = client
        .get(format!("{base}/?zip"))
        .basic_auth("admin", Some("admin"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let bytes = resp.bytes()?;
    assert!(
        !bytes.windows(5).any(|w| w == b".dufs"),
        "archive leaks the metadata dir"
    );

    let resp = client
        .get(format!("{base}/.dufs/?zip"))
        .basic_auth("admin", Some("admin"))
        .send()?;
    assert_eq!(resp.status(), 404);

    // a guest whose only auth path is the metadata dir must not archive it
    child.kill()?;
    let mut child = start_acl(&tmpdir, &port, "guest:guest@/.dufs")?;
    wait_for_port(&port);
    let resp = client
        .get(format!("{base}/?zip"))
        .basic_auth("guest", Some("guest"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let bytes = resp.bytes()?;
    assert!(
        !bytes.windows(5).any(|w| w == b".dufs"),
        "guest archive leaks the metadata dir"
    );

    child.kill()?;
    Ok(())
}
