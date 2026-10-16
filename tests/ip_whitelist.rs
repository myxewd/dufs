mod fixtures;
mod utils;

use fixtures::{server, Error, TestServer};
use rstest::rstest;

fn get(url: &str) -> Result<reqwest::blocking::Response, Error> {
    Ok(reqwest::blocking::get(url)?)
}

#[rstest]
fn unconfigured_allows_everyone(server: TestServer) -> Result<(), Error> {
    let resp = get(&format!("{}dir1/test.txt", server.url()))?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn deny_all_for_directory(
    #[with(&["--ip-whitelist", "@/dir1"])] server: TestServer,
) -> Result<(), Error> {
    // the directory itself and everything below it are denied
    assert_eq!(get(&format!("{}dir1/", server.url()))?.status(), 403);
    assert_eq!(
        get(&format!("{}dir1/test.txt", server.url()))?.status(),
        403
    );
    // a request below the directory is denied even when the path does not exist
    assert_eq!(
        get(&format!("{}dir1/nope.txt", server.url()))?.status(),
        403
    );
    // a sibling directory keeps the default
    assert_eq!(get(&format!("{}dir2/", server.url()))?.status(), 200);
    assert_eq!(get(&format!("{}test.txt", server.url()))?.status(), 200);
    Ok(())
}

#[rstest]
fn allow_matching_ip_and_cidr(
    #[with(&["--ip-whitelist", "127.0.0.0/8,::1@/dir1"])] server: TestServer,
) -> Result<(), Error> {
    let resp = get(&format!("{}dir1/test.txt", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "This is dir1/test.txt");
    Ok(())
}

#[rstest]
fn deny_non_matching_ip(
    #[with(&["--ip-whitelist", "10.0.0.0/8@/dir1"])] server: TestServer,
) -> Result<(), Error> {
    assert_eq!(get(&format!("{}dir1/", server.url()))?.status(), 403);
    assert_eq!(
        get(&format!("{}dir1/test.txt", server.url()))?.status(),
        403
    );
    Ok(())
}

#[rstest]
fn file_rule_overrides_directory(
    #[with(&[
        "--ip-whitelist",
        "127.0.0.1,::1@/dir1",
        "--ip-whitelist",
        "@/dir1/test.txt",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    assert_eq!(
        get(&format!("{}dir1/test.html", server.url()))?.status(),
        200
    );
    assert_eq!(
        get(&format!("{}dir1/test.txt", server.url()))?.status(),
        403
    );

    // the denied file is hidden from the directory listing
    let resp = get(&format!("{}dir1/?simple", server.url()))?;
    assert_eq!(resp.status(), 200);
    let text = resp.text()?;
    assert!(text.contains("test.html"));
    assert!(!text.contains("test.txt"));
    Ok(())
}

#[rstest]
fn nearest_configured_parent_wins(
    #[with(&[
        "--ip-whitelist",
        "@/dir1",
        "--ip-whitelist",
        "127.0.0.1,::1@/dir1/nested",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    std::fs::create_dir_all(server.path().join("dir1/nested"))?;
    std::fs::write(server.path().join("dir1/nested/a.txt"), b"x")?;
    // inherited denial from /dir1
    assert_eq!(
        get(&format!("{}dir1/test.txt", server.url()))?.status(),
        403
    );
    // explicit rule on the deeper directory restores access
    assert_eq!(
        get(&format!("{}dir1/nested/a.txt", server.url()))?.status(),
        200
    );
    Ok(())
}

#[rstest]
fn root_rule_applies_to_everything(
    #[with(&["--ip-whitelist", "127.0.0.1,::1@/"])] server: TestServer,
) -> Result<(), Error> {
    assert_eq!(get(&format!("{}test.txt", server.url()))?.status(), 200);
    assert_eq!(
        get(&format!("{}dir1/test.txt", server.url()))?.status(),
        200
    );
    Ok(())
}

#[rstest]
fn listing_hides_denied_entries(
    #[with(&[
        "--ip-whitelist",
        "127.0.0.1,::1@/",
        "--ip-whitelist",
        "@/dir1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let resp = get(&format!("{}?simple", server.url()))?;
    assert_eq!(resp.status(), 200);
    let text = resp.text()?;
    assert!(text.contains("dir2/"));
    assert!(!text.contains("dir1/"));
    Ok(())
}

#[rstest]
fn archive_excludes_denied_entries(
    #[with(&[
        "--ip-whitelist",
        "127.0.0.1,::1@/",
        "--ip-whitelist",
        "@/dir1",
        "-A",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let resp = get(&format!("{}?zip", server.url()))?;
    assert_eq!(resp.status(), 200);
    let bytes = resp.bytes()?;
    let contains = |needle: &str| {
        let needle = needle.as_bytes();
        bytes.windows(needle.len()).any(|w| w == needle)
    };
    assert!(contains("dir2/test.txt"));
    assert!(!contains("dir1/test.txt"));
    Ok(())
}

#[rstest]
fn write_is_denied_too(
    #[with(&["--ip-whitelist", "@/dir1", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}dir1/new.txt", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn write_allowed_for_whitelisted_ip(
    #[with(&["--ip-whitelist", "127.0.0.1,::1@/dir1", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}dir1/new.txt", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 201);
    Ok(())
}

#[rstest]
fn webdav_propfind_is_filtered(
    #[with(&[
        "--ip-whitelist",
        "127.0.0.1,::1@/",
        "--ip-whitelist",
        "@/dir1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let url = server.url().to_string();
    let resp = fetch!(b"PROPFIND", &url).header("Depth", "1").send()?;
    assert_eq!(resp.status(), 207);
    let text = resp.text()?;
    assert!(text.contains("dir2"));
    assert!(!text.contains("dir1"));
    Ok(())
}

#[rstest]
fn search_excludes_denied_entries(
    #[with(&[
        "--allow-search",
        "--ip-whitelist",
        "127.0.0.1,::1@/",
        "--ip-whitelist",
        "@/dir1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let resp = get(&format!("{}?q=test.txt", server.url()))?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert!(!paths.is_empty());
    assert!(paths.iter().any(|p| p.starts_with("dir2")));
    assert!(paths.iter().all(|p| !p.starts_with("dir1")));
    Ok(())
}
