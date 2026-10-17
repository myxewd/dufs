use crate::auth::find_child_alias;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

/// The explicit user acl of a single path. Each list is optional: `None`
/// inherits the nearest configured ancestor, `Some(empty)` means "nobody".
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UserRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_read: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_write: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_read: Option<Vec<String>>,
}

impl UserRule {
    pub fn is_empty(&self) -> bool {
        self.allow_read.is_none() && self.allow_write.is_none() && self.deny_read.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct UserNode {
    rule: Option<UserRule>,
    children: IndexMap<String, UserNode>,
}

/// The effective acl of a path after per-list inheritance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EffectiveRule {
    pub allow_read: Option<Vec<String>>,
    pub allow_write: Option<Vec<String>>,
    pub deny_read: Option<Vec<String>>,
}

impl EffectiveRule {
    fn contains(list: &Option<Vec<String>>, user: &str) -> bool {
        list.as_ref().is_some_and(|v| v.iter().any(|u| u == user))
    }
}

/// A user's effective acl permission at a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclPerm {
    Deny,
    Read,
    Write,
}

/// How a user relates to a path and its descendants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMemberKind {
    /// full access to the path and every descendant
    Full,
    /// allowed here, but a descendant denies the user
    Partial,
    /// not allowed here, but a descendant allows the user
    Exception,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclMember {
    pub user: String,
    pub kind: AclMemberKind,
    pub is_x: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AclSummary {
    pub allow_read: Vec<AclMember>,
    pub allow_write: Vec<AclMember>,
}

/// Per-path user acl. The nearest configured ancestor wins as a whole rule:
/// once a path is covered by a rule, users not listed in it are denied
/// instead of falling back to `--auth`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserAcl {
    root: UserNode,
}

impl UserAcl {
    pub fn insert(&mut self, path: &str, rule: UserRule) {
        if rule.is_empty() {
            self.remove(path);
            return;
        }
        let parts = split_path(path);
        let mut node = &mut self.root;
        for part in parts {
            node = node.children.entry(part.to_string()).or_default();
        }
        node.rule = Some(rule);
    }

    pub fn remove(&mut self, path: &str) {
        let parts = split_path(path);
        let mut node = &mut self.root;
        for part in &parts {
            match node.children.get_mut(*part) {
                Some(child) => node = child,
                None => return,
            }
        }
        node.rule = None;
    }

    /// The nearest rule covering the path, or `None` when the path is not
    /// managed by the acl and must fall back to `--auth`.
    pub async fn find_rule(&self, path: &str, root: Option<&Path>) -> Option<&UserRule> {
        let parts = split_path(path);
        let mut node = &self.root;
        let mut found = node.rule.as_ref();
        for (i, name) in parts.iter().enumerate() {
            let child = match node.children.get(*name) {
                Some(child) => child,
                None => match find_child_alias(&node.children, name, &parts[..i], root).await {
                    Some(child) => child,
                    None => break,
                },
            };
            node = child;
            if node.rule.is_some() {
                found = node.rule.as_ref();
            }
        }
        found
    }

    /// The target's own rule, i.e. only the entries configured on this exact
    /// path. Inherited entries are not included.
    pub async fn own(&self, path: &str, root: Option<&Path>) -> UserRule {
        self.find_node(path, root)
            .await
            .and_then(|node| node.rule.clone())
            .unwrap_or_default()
    }

    /// The nearest ancestor rule, excluding users overridden by the target's
    /// own rule. The editor shows these entries read-only.
    pub async fn inherited(&self, path: &str, root: Option<&Path>) -> UserRule {
        let own = self.own(path, root).await;
        let chain = self.chain(path, root).await;
        let skip = if own.is_empty() { 1 } else { 2 };
        let mut inherited = if chain.len() >= skip {
            chain[chain.len() - skip].1.clone()
        } else {
            UserRule::default()
        };
        for user in [&own.allow_read, &own.allow_write, &own.deny_read]
            .into_iter()
            .flatten()
            .flatten()
        {
            remove_member(&mut inherited.allow_read, user);
            remove_member(&mut inherited.allow_write, user);
            remove_member(&mut inherited.deny_read, user);
        }
        inherited
    }

    /// The rules on the path from the root to the target, used by the diff.
    pub async fn chain(&self, path: &str, root: Option<&Path>) -> Vec<(String, UserRule)> {
        let parts = split_path(path);
        let mut output = vec![];
        let mut node = &self.root;
        if let Some(rule) = &node.rule {
            output.push(("/".to_string(), rule.clone()));
        }
        let mut prefix = String::new();
        for (i, name) in parts.iter().enumerate() {
            let child = match node.children.get(*name) {
                Some(child) => child,
                None => match find_child_alias(&node.children, name, &parts[..i], root).await {
                    Some(child) => child,
                    None => break,
                },
            };
            node = child;
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(name);
            if let Some(rule) = &node.rule {
                output.push((format!("/{prefix}"), rule.clone()));
            }
        }
        output
    }

    /// The nearest rule's lists, used to pre-fill the editor.
    pub async fn effective(&self, path: &str, root: Option<&Path>) -> EffectiveRule {
        match self.find_rule(path, root).await {
            Some(rule) => EffectiveRule {
                allow_read: rule.allow_read.clone(),
                allow_write: rule.allow_write.clone(),
                deny_read: rule.deny_read.clone(),
            },
            None => EffectiveRule::default(),
        }
    }

    /// The user's acl decision. The nearest ancestor rule that mentions the
    /// user wins, so a child rule only needs to list the users it changes.
    /// `None` means no rule covers the path, so `--auth` applies; a path in a
    /// managed subtree that never mentions the user defaults to deny.
    pub async fn perm(&self, path: &str, user: &str, root: Option<&Path>) -> Option<AclPerm> {
        let parts = split_path(path);
        let mut node = &self.root;
        let mut managed = node.rule.is_some();
        let mut user_rule = node.rule.as_ref().filter(|rule| mentions(rule, user));
        for (i, name) in parts.iter().enumerate() {
            let child = match node.children.get(*name) {
                Some(child) => child,
                None => match find_child_alias(&node.children, name, &parts[..i], root).await {
                    Some(child) => child,
                    None => break,
                },
            };
            node = child;
            if node.rule.is_some() {
                managed = true;
            }
            if let Some(rule) = &node.rule {
                if mentions(rule, user) {
                    user_rule = Some(rule);
                }
            }
        }
        let Some(rule) = user_rule else {
            return if managed { Some(AclPerm::Deny) } else { None };
        };
        if EffectiveRule::contains(&rule.deny_read, user) {
            Some(AclPerm::Deny)
        } else if EffectiveRule::contains(&rule.allow_write, user) {
            Some(AclPerm::Write)
        } else if EffectiveRule::contains(&rule.allow_read, user) {
            Some(AclPerm::Read)
        } else {
            Some(AclPerm::Deny)
        }
    }

    /// The users that can read/write `path`, annotated with whether the
    /// grant is full, partial (a descendant denies) or an exception (only a
    /// descendant allows). `x_users` always count as full.
    pub async fn summary(&self, path: &str, x_users: &[String], root: Option<&Path>) -> AclSummary {
        let mut candidates: BTreeSet<String> = BTreeSet::new();
        for (_, rule) in self.chain(path, root).await {
            collect_rule_users(&rule, &mut candidates);
        }
        let node = self.find_node(path, root).await;
        if let Some(node) = node {
            collect_descendant_users(node, &mut candidates);
        }
        for user in x_users {
            candidates.insert(user.clone());
        }
        let mut summary = AclSummary::default();
        for user in candidates {
            let is_x = x_users.iter().any(|v| v == &user);
            if is_x {
                // full write implies read, so a full-write user only appears
                // in the write list
                summary.allow_write.push(AclMember {
                    user,
                    kind: AclMemberKind::Full,
                    is_x: true,
                });
                continue;
            }
            let perm = self.perm(path, &user, root).await;
            let (below_deny, below_write, below_read) = match node {
                Some(node) => descendant_mentions(node, &user),
                None => (false, false, false),
            };
            let read_kind = match perm {
                Some(AclPerm::Read) | Some(AclPerm::Write) => Some(if below_deny {
                    AclMemberKind::Partial
                } else {
                    AclMemberKind::Full
                }),
                _ => {
                    if below_read || below_write {
                        Some(AclMemberKind::Exception)
                    } else {
                        None
                    }
                }
            };
            let write_kind = match perm {
                Some(AclPerm::Write) => Some(if below_deny {
                    AclMemberKind::Partial
                } else {
                    AclMemberKind::Full
                }),
                _ => {
                    if below_write {
                        Some(AclMemberKind::Exception)
                    } else {
                        None
                    }
                }
            };
            if let Some(kind) = read_kind {
                if write_kind != Some(AclMemberKind::Full) {
                    summary.allow_read.push(AclMember {
                        user: user.clone(),
                        kind,
                        is_x: false,
                    });
                }
            }
            if let Some(kind) = write_kind {
                summary.allow_write.push(AclMember {
                    user,
                    kind,
                    is_x: false,
                });
            }
        }
        summary
    }

    async fn find_node<'a>(&'a self, path: &str, root: Option<&Path>) -> Option<&'a UserNode> {
        let parts = split_path(path);
        let mut node = &self.root;
        for (i, name) in parts.iter().enumerate() {
            node = match node.children.get(*name) {
                Some(child) => child,
                None => match find_child_alias(&node.children, name, &parts[..i], root).await {
                    Some(child) => child,
                    None => return None,
                },
            };
        }
        Some(node)
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.rules().is_empty()
    }

    /// All explicitly configured rules as `(path, rule)` pairs.
    pub fn rules(&self) -> Vec<(String, UserRule)> {
        let mut output = Vec::new();
        self.collect_rules(&self.root, String::new(), &mut output);
        output
    }

    fn collect_rules(&self, node: &UserNode, prefix: String, output: &mut Vec<(String, UserRule)>) {
        if let Some(rule) = &node.rule {
            let path = if prefix.is_empty() {
                "/".to_string()
            } else {
                format!("/{prefix}")
            };
            output.push((path, rule.clone()));
        }
        for (name, child) in &node.children {
            let next = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            self.collect_rules(child, next, output);
        }
    }
}

fn collect_rule_users(rule: &UserRule, out: &mut BTreeSet<String>) {
    for user in [&rule.allow_read, &rule.allow_write, &rule.deny_read]
        .into_iter()
        .flatten()
        .flatten()
    {
        out.insert(user.clone());
    }
}

fn collect_descendant_users(node: &UserNode, out: &mut BTreeSet<String>) {
    if let Some(rule) = &node.rule {
        collect_rule_users(rule, out);
    }
    for child in node.children.values() {
        collect_descendant_users(child, out);
    }
}

fn descendant_mentions(node: &UserNode, user: &str) -> (bool, bool, bool) {
    let mut deny = false;
    let mut write = false;
    let mut read = false;
    for child in node.children.values() {
        if let Some(rule) = &child.rule {
            if EffectiveRule::contains(&rule.deny_read, user) {
                deny = true;
            }
            if EffectiveRule::contains(&rule.allow_write, user) {
                write = true;
            }
            if EffectiveRule::contains(&rule.allow_read, user) {
                read = true;
            }
        }
        let (d, w, r) = descendant_mentions(child, user);
        deny |= d;
        write |= w;
        read |= r;
    }
    (deny, write, read)
}

fn remove_member(list: &mut Option<Vec<String>>, user: &str) {
    if let Some(users) = list {
        users.retain(|v| v != user);
    }
}

fn mentions(rule: &UserRule, user: &str) -> bool {
    EffectiveRule::contains(&rule.allow_read, user)
        || EffectiveRule::contains(&rule.allow_write, user)
        || EffectiveRule::contains(&rule.deny_read, user)
}

fn split_path(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|v| !v.is_empty())
        .collect()
}

/// File inside the metadata directory that stores the per-path user acl.
pub const USER_ACL_FILE: &str = "user-acl.json";

const STORE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreFile {
    #[serde(default = "store_version")]
    pub version: u32,
    #[serde(default)]
    pub rules: BTreeMap<String, UserRule>,
}

fn store_version() -> u32 {
    STORE_VERSION
}

impl StoreFile {
    pub fn from_acl(acl: &UserAcl) -> Self {
        Self {
            version: STORE_VERSION,
            rules: acl.rules().into_iter().collect(),
        }
    }

    pub fn to_acl(&self) -> UserAcl {
        let mut acl = UserAcl::default();
        for (path, rule) in &self.rules {
            acl.insert(path, rule.clone());
        }
        acl
    }
}

pub fn store_path(serve_path: &Path) -> std::path::PathBuf {
    crate::ip_whitelist_store::metadata_dir(serve_path).join(USER_ACL_FILE)
}

#[allow(dead_code)]
pub fn exists(serve_path: &Path) -> bool {
    store_path(serve_path).is_file()
}

pub fn load(serve_path: &Path) -> Result<UserAcl> {
    let path = store_path(serve_path);
    if !path.is_file() {
        return Ok(UserAcl::default());
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let store: StoreFile = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(store.to_acl())
}

pub fn save(serve_path: &Path, acl: &UserAcl) -> Result<()> {
    let dir = crate::ip_whitelist_store::metadata_dir(serve_path);
    std::fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    let path = store_path(serve_path);
    let contents = serde_json::to_string_pretty(&StoreFile::from_acl(acl))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, contents).with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("Failed to update {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::prelude::*;

    fn rule(read: &[&str], write: &[&str], deny: &[&str]) -> UserRule {
        UserRule {
            allow_read: Some(read.iter().map(|v| v.to_string()).collect()),
            allow_write: Some(write.iter().map(|v| v.to_string()).collect()),
            deny_read: Some(deny.iter().map(|v| v.to_string()).collect()),
        }
    }

    fn list(v: &[&str]) -> Vec<String> {
        v.iter().map(|v| v.to_string()).collect()
    }

    #[tokio::test]
    async fn test_per_user_nearest_and_default_deny() {
        let mut acl = UserAcl::default();
        acl.insert("/dir", rule(&["alice"], &["bob"], &[]));
        acl.insert(
            "/dir/secret",
            UserRule {
                allow_read: Some(list(&["alice"])),
                deny_read: Some(list(&["carol"])),
                ..Default::default()
            },
        );

        // the nearest rule replaces the parent instead of merging with it
        let eff = acl.effective("dir/secret/file.txt", None).await;
        assert_eq!(eff.allow_read, Some(list(&["alice"])));
        assert_eq!(eff.allow_write, None);
        assert_eq!(eff.deny_read, Some(list(&["carol"])));

        assert_eq!(
            acl.perm("dir/secret", "alice", None).await,
            Some(AclPerm::Read)
        );
        // a child rule only lists the users it changes: bob still comes from
        // the parent rule, while carol is denied by the child
        assert_eq!(
            acl.perm("dir/secret", "bob", None).await,
            Some(AclPerm::Write)
        );
        assert_eq!(
            acl.perm("dir/secret", "carol", None).await,
            Some(AclPerm::Deny)
        );
        // a user mentioned nowhere inside a managed subtree defaults to deny
        assert_eq!(
            acl.perm("dir/secret", "dave", None).await,
            Some(AclPerm::Deny)
        );

        // a path outside every rule falls back to --auth
        assert_eq!(acl.perm("elsewhere", "alice", None).await, None);
        // the parent rule still applies to its other children
        assert_eq!(
            acl.perm("dir/other", "bob", None).await,
            Some(AclPerm::Write)
        );
    }

    #[tokio::test]
    async fn test_write_implies_read_and_default_deny() {
        let mut acl = UserAcl::default();
        acl.insert(
            "/",
            UserRule {
                allow_write: Some(list(&["bob"])),
                ..Default::default()
            },
        );
        assert_eq!(
            acl.perm("anything", "bob", None).await,
            Some(AclPerm::Write)
        );
        // the root is managed, so alice defaults to deny
        assert_eq!(
            acl.perm("anything", "alice", None).await,
            Some(AclPerm::Deny)
        );

        acl.insert(
            "/public",
            UserRule {
                allow_read: Some(vec![]),
                allow_write: Some(vec![]),
                deny_read: Some(vec![]),
            },
        );
        assert_eq!(
            acl.perm("public/a", "alice", None).await,
            Some(AclPerm::Deny)
        );
        // an empty rule does not mention bob, so the root's allow_write wins
        assert_eq!(
            acl.perm("public/a", "bob", None).await,
            Some(AclPerm::Write)
        );
    }

    #[tokio::test]
    async fn test_remove_and_store_roundtrip() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();
        let mut acl = UserAcl::default();
        acl.insert("/dir/a", rule(&["alice"], &[], &["bob"]));
        save(root, &acl).unwrap();
        assert!(exists(root));
        let loaded = load(root).unwrap();
        assert_eq!(loaded.rules(), acl.rules());
        assert_eq!(
            loaded.perm("dir/a", "alice", None).await,
            Some(AclPerm::Read)
        );
        assert_eq!(loaded.perm("dir/a", "bob", None).await, Some(AclPerm::Deny));
        assert_eq!(
            loaded.perm("dir/a", "carol", None).await,
            Some(AclPerm::Deny)
        );

        acl.remove("/dir/a");
        assert!(acl.is_empty());
        save(root, &acl).unwrap();
        assert!(load(root).unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_alias_names() {
        let dir = assert_fs::TempDir::new().unwrap();
        dir.child("dir1/secret.txt").write_str("x").unwrap();
        let root = dir.path();
        let mut acl = UserAcl::default();
        acl.insert(
            "/DIR1",
            UserRule {
                deny_read: Some(list(&["alice"])),
                ..Default::default()
            },
        );
        let folds_case = root.join("dir1").is_dir();
        assert_eq!(
            acl.perm("dir1/secret.txt", "alice", Some(root)).await,
            if folds_case {
                Some(AclPerm::Deny)
            } else {
                None
            }
        );
        assert_eq!(
            acl.perm("DIR1/secret.txt", "alice", Some(root)).await,
            Some(AclPerm::Deny)
        );
    }

    #[tokio::test]
    async fn test_summary_kinds() {
        let mut acl = UserAcl::default();
        acl.insert("/", rule(&["alice"], &["bob"], &[]));
        acl.insert("/dir", rule(&["alice", "carol"], &[], &["bob"]));
        acl.insert(
            "/dir/sub",
            UserRule {
                allow_write: Some(list(&["dave"])),
                ..Default::default()
            },
        );

        let summary = acl.summary("/", &[], None).await;
        let read: Vec<(&str, AclMemberKind)> = summary
            .allow_read
            .iter()
            .map(|v| (v.user.as_str(), v.kind))
            .collect();
        assert_eq!(
            read,
            vec![
                ("alice", AclMemberKind::Full),
                ("bob", AclMemberKind::Partial),
                ("carol", AclMemberKind::Exception),
                ("dave", AclMemberKind::Exception),
            ]
        );
        let write: Vec<(&str, AclMemberKind)> = summary
            .allow_write
            .iter()
            .map(|v| (v.user.as_str(), v.kind))
            .collect();
        assert_eq!(
            write,
            vec![
                ("bob", AclMemberKind::Partial),
                ("dave", AclMemberKind::Exception),
            ]
        );

        let summary = acl.summary("/", &["admin".to_string()], None).await;
        // a full-write (x) user is not repeated in the read column
        assert!(!summary.allow_read.iter().any(|v| v.user == "admin"));
        assert!(summary
            .allow_write
            .iter()
            .any(|v| v.user == "admin" && v.is_x && v.kind == AclMemberKind::Full));
    }
    #[tokio::test]
    async fn test_permission_matrix_and_chain() {
        let mut acl = UserAcl::default();
        acl.insert("/", rule(&["alice"], &["bob"], &[]));
        acl.insert("/secret", rule(&[], &[], &["alice"]));
        acl.insert("/secret/open", rule(&["carol"], &[], &[]));
        acl.insert("/other", rule(&["dave"], &[], &[]));

        assert_eq!(acl.perm("/", "alice", None).await, Some(AclPerm::Read));
        assert_eq!(acl.perm("/", "bob", None).await, Some(AclPerm::Write));
        assert_eq!(acl.perm("/", "carol", None).await, Some(AclPerm::Deny));

        // alice is denied by the nearest rule that mentions her
        assert_eq!(
            acl.perm("/secret", "alice", None).await,
            Some(AclPerm::Deny)
        );
        // bob is not mentioned below the root, so the root write applies
        assert_eq!(acl.perm("/secret", "bob", None).await, Some(AclPerm::Write));
        // carol is only allowed on the open child
        assert_eq!(
            acl.perm("/secret/open", "carol", None).await,
            Some(AclPerm::Read)
        );
        assert_eq!(
            acl.perm("/secret/open", "alice", None).await,
            Some(AclPerm::Deny)
        );
        assert_eq!(
            acl.perm("/secret/open", "bob", None).await,
            Some(AclPerm::Write)
        );
        // dave is allowed on /other; alice falls back to the root
        assert_eq!(acl.perm("/other", "dave", None).await, Some(AclPerm::Read));
        assert_eq!(acl.perm("/other", "alice", None).await, Some(AclPerm::Read));
        assert_eq!(acl.perm("/other", "carol", None).await, Some(AclPerm::Deny));
        assert_eq!(acl.perm("/other", "erin", None).await, Some(AclPerm::Deny));

        // no rules at all -> --auth fallback
        assert_eq!(UserAcl::default().perm("/x", "alice", None).await, None);

        let chain = acl.chain("/secret/open", None).await;
        let paths: Vec<&str> = chain.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(paths, vec!["/", "/secret", "/secret/open"]);

        let eff = acl.effective("/secret/open", None).await;
        assert_eq!(eff.allow_read, Some(list(&["carol"])));
        assert_eq!(eff.allow_write, Some(vec![]));
        assert_eq!(eff.deny_read, Some(vec![]));
    }

    #[tokio::test]
    async fn test_own_and_inherited_rules() {
        let mut acl = UserAcl::default();
        acl.insert("/", rule(&["alice"], &[], &[]));
        acl.insert("/child", rule(&[], &[], &["bob"]));

        // the child's own rule only contains what was configured there
        let own = acl.own("/child", None).await;
        assert_eq!(own.allow_read, Some(vec![]));
        assert_eq!(own.deny_read, Some(list(&["bob"])));

        // the parent's alice entry is inherited, the child's bob is not
        let inherited = acl.inherited("/child", None).await;
        assert_eq!(inherited.allow_read, Some(list(&["alice"])));
        assert_eq!(inherited.deny_read, Some(vec![]));

        // overriding an inherited user with a child deny hides it from the
        // inherited view and wins for that user only
        acl.insert("/child", rule(&[], &[], &["bob", "alice"]));
        let inherited = acl.inherited("/child", None).await;
        assert_eq!(inherited.allow_read, Some(vec![]));
        assert_eq!(acl.perm("/child", "alice", None).await, Some(AclPerm::Deny));
        assert_eq!(acl.perm("/child", "bob", None).await, Some(AclPerm::Deny));
        assert_eq!(acl.perm("/", "alice", None).await, Some(AclPerm::Read));
    }
}
