use crate::ip_whitelist::IpWhitelist;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Directory at the served root that holds dufs metadata. It is never served.
pub const METADATA_DIR: &str = ".dufs";
/// File inside the metadata directory that stores the per-path ip whitelist.
pub const WHITELIST_FILE: &str = "ip-whitelist.json";

const STORE_VERSION: u32 = 1;

fn store_version() -> u32 {
    STORE_VERSION
}

/// On-disk representation of the ip whitelist.
///
/// The rules map a URL path to the list of allowed addresses. A path with no
/// rule inherits the closest configured ancestor; see [`IpWhitelist`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreFile {
    #[serde(default = "store_version")]
    pub version: u32,
    #[serde(default)]
    pub rules: BTreeMap<String, Vec<String>>,
}

impl StoreFile {
    pub fn from_whitelist(whitelist: &IpWhitelist) -> Self {
        Self {
            version: STORE_VERSION,
            rules: whitelist.rules().into_iter().collect(),
        }
    }

    pub fn to_whitelist(&self) -> Result<IpWhitelist> {
        let mut whitelist = IpWhitelist::default();
        for (path, ips) in &self.rules {
            whitelist
                .insert_ips(path, ips)
                .with_context(|| format!("Invalid ip-whitelist for '{path}'"))?;
        }
        Ok(whitelist)
    }
}

pub fn metadata_dir(serve_path: &Path) -> PathBuf {
    serve_path.join(METADATA_DIR)
}

pub fn store_path(serve_path: &Path) -> PathBuf {
    metadata_dir(serve_path).join(WHITELIST_FILE)
}

/// Whether a store file exists under the served root.
pub fn exists(serve_path: &Path) -> bool {
    store_path(serve_path).is_file()
}

/// Load the persisted whitelist. A missing store file yields an empty whitelist.
pub fn load(serve_path: &Path) -> Result<IpWhitelist> {
    let path = store_path(serve_path);
    if !path.is_file() {
        return Ok(IpWhitelist::default());
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let store: StoreFile = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    store
        .to_whitelist()
        .with_context(|| format!("Invalid ip-whitelist in {}", path.display()))
}

/// Persist the whitelist, creating the metadata directory if needed.
///
/// The file is written to a temporary sibling and then renamed so readers never
/// observe a partially written file.
pub fn save(serve_path: &Path, whitelist: &IpWhitelist) -> Result<()> {
    let dir = metadata_dir(serve_path);
    std::fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    let path = store_path(serve_path);
    let contents = serde_json::to_string_pretty(&StoreFile::from_whitelist(whitelist))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, contents).with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("Failed to update {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::prelude::*;

    #[test]
    fn test_roundtrip() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();
        assert!(!exists(root));
        assert!(load(root).unwrap().is_empty());

        let mut whitelist = IpWhitelist::default();
        whitelist
            .insert_ips("/dir1", &["127.0.0.1".into()])
            .unwrap();
        whitelist
            .insert_ips("/dir1/dir2", &["10.0.0.0/8".into(), "::1".into()])
            .unwrap();
        save(root, &whitelist).unwrap();

        assert!(exists(root));
        assert!(root.join(".dufs/ip-whitelist.json").is_file());
        let loaded = load(root).unwrap();
        assert_eq!(loaded.rules(), whitelist.rules());
    }

    #[test]
    fn test_load_rejects_invalid() {
        let dir = assert_fs::TempDir::new().unwrap();
        dir.child(".dufs/ip-whitelist.json")
            .write_str(r#"{ "version": 1, "rules": { "/a": ["not-an-ip"] } }"#)
            .unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn test_load_missing_version() {
        let dir = assert_fs::TempDir::new().unwrap();
        dir.child(".dufs/ip-whitelist.json")
            .write_str(r#"{ "rules": { "/a": ["127.0.0.1"] } }"#)
            .unwrap();
        let whitelist = load(dir.path()).unwrap();
        assert_eq!(whitelist.rules()[0].0, "/a");
    }
}
