use crate::auth::find_child_alias;

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer};
use std::{net::IpAddr, path::Path, str::FromStr};

/// A single allowed client address, either a plain IP or a CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    V4 { addr: u32, prefix: u8 },
    V6 { addr: u128, prefix: u8 },
}

impl IpNet {
    /// Whether the address falls inside this range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpNet::V4 { addr, prefix }, IpAddr::V4(ip)) => {
                u32::from(ip) & v4_mask(*prefix) == *addr
            }
            (IpNet::V6 { addr, prefix }, IpAddr::V6(ip)) => {
                u128::from(ip) & v6_mask(*prefix) == *addr
            }
            _ => false,
        }
    }

    /// Whether this range covers every address of its family.
    pub fn is_allow_all(&self) -> bool {
        match self {
            IpNet::V4 { prefix, .. } | IpNet::V6 { prefix, .. } => *prefix == 0,
        }
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpNet::V4 { addr, prefix } => {
                let ip = std::net::Ipv4Addr::from(*addr);
                if *prefix == 32 {
                    write!(f, "{ip}")
                } else {
                    write!(f, "{ip}/{prefix}")
                }
            }
            IpNet::V6 { addr, prefix } => {
                let ip = std::net::Ipv6Addr::from(*addr);
                if *prefix == 128 {
                    write!(f, "{ip}")
                } else {
                    write!(f, "{ip}/{prefix}")
                }
            }
        }
    }
}

impl FromStr for IpNet {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let (ip_str, prefix_str) = match s.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (s, None),
        };
        let ip: IpAddr = ip_str
            .trim()
            .parse()
            .with_context(|| format!("invalid ip address '{ip_str}'"))?;
        match ip {
            IpAddr::V4(ip) => {
                let prefix = match prefix_str {
                    Some(prefix) => prefix
                        .trim()
                        .parse::<u8>()
                        .with_context(|| format!("invalid ipv4 prefix '{prefix}'"))?,
                    None => 32,
                };
                if prefix > 32 {
                    bail!("invalid ipv4 prefix '{prefix}'");
                }
                Ok(IpNet::V4 {
                    addr: u32::from(ip) & v4_mask(prefix),
                    prefix,
                })
            }
            IpAddr::V6(ip) => {
                let prefix = match prefix_str {
                    Some(prefix) => prefix
                        .trim()
                        .parse::<u8>()
                        .with_context(|| format!("invalid ipv6 prefix '{prefix}'"))?,
                    None => 128,
                };
                if prefix > 128 {
                    bail!("invalid ipv6 prefix '{prefix}'");
                }
                Ok(IpNet::V6 {
                    addr: u128::from(ip) & v6_mask(prefix),
                    prefix,
                })
            }
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// One node of the whitelist tree. The address list is set only where the
/// configuration names this exact path; a path without an own entry inherits
/// the nearest configured ancestor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct IpNode {
    ips: Option<Vec<IpNet>>,
    children: IndexMap<String, IpNode>,
}

/// Per-path IP whitelist.
///
/// Rules map an allowed address list onto a file or directory. A file-level
/// rule takes precedence over a directory-level one, and any path without a
/// rule of its own inherits the closest configured ancestor. Paths with no
/// configured ancestor are unrestricted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpWhitelist {
    root: IpNode,
}

impl IpWhitelist {
    /// Build a whitelist from rule strings like 127.0.0.1,10.0.0.0/8@/dir1.
    ///
    /// The address list comes first and is separated from the path by '@'. Both
    /// the empty address list (@/dir1, denying the subtree) and a missing '@'
    /// (127.0.0.1, applying to the served root) are accepted. Multiple rules can
    /// be joined with '|'.
    pub fn new(rules: &[String]) -> Result<Self> {
        let mut whitelist = Self::default();
        for rule in rules {
            for part in rule.split('|') {
                whitelist.add_rule(part)?;
            }
        }
        Ok(whitelist)
    }

    fn add_rule(&mut self, rule: &str) -> Result<()> {
        let rule = rule.trim();
        if rule.is_empty() {
            return Ok(());
        }
        let (ips, path) = match rule.split_once('@') {
            Some((ips, path)) => (ips, path.trim()),
            None => (rule, "/"),
        };
        let path = if path.is_empty() { "/" } else { path };
        let ips: Vec<IpNet> = ips
            .split(',')
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(|v| {
                v.parse::<IpNet>()
                    .map_err(|e| anyhow::anyhow!("invalid ip-whitelist rule '{rule}': {e}"))
            })
            .collect::<Result<_>>()?;
        self.insert(path, ips);
        Ok(())
    }

    /// Parse and insert an address list for the given path.
    pub fn insert_ips(&mut self, path: &str, ips: &[String]) -> Result<()> {
        let ips = ips
            .iter()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(|v| v.parse::<IpNet>())
            .collect::<Result<Vec<_>>>()
            .with_context(|| format!("invalid ip-whitelist for '{path}'"))?;
        self.insert(path, ips);
        Ok(())
    }

    fn insert(&mut self, path: &str, ips: Vec<IpNet>) {
        let parts: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|v| !v.is_empty())
            .collect();
        let mut node = &mut self.root;
        for part in parts {
            node = node.children.entry(part.to_string()).or_default();
        }
        node.ips = Some(ips);
    }

    /// Whether any rule is configured at all.
    pub fn is_empty(&self) -> bool {
        self.root.ips.is_none() && self.root.children.is_empty()
    }

    /// Whether the client address may access the path.
    ///
    /// The root is the served directory, used to resolve filesystem aliases of
    /// configured names (case variants, short names, ...). A path with no
    /// configured ancestor is allowed. When an address list is configured but
    /// the client address is unknown (for example a unix socket), access is
    /// denied.
    pub async fn allows(&self, path: &str, ip: Option<IpAddr>, root: Option<&Path>) -> bool {
        match self.find(path, root).await {
            Some(ips) => ip.is_some_and(|ip| ips.iter().any(|net| net.contains(ip))),
            None => true,
        }
    }

    /// The effective address list for the path, i.e. the closest configured
    /// ancestor (or the path itself).
    pub async fn find(&self, path: &str, root: Option<&Path>) -> Option<&Vec<IpNet>> {
        if self.is_empty() {
            return None;
        }
        let parts: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|v| !v.is_empty())
            .collect();
        let mut node = &self.root;
        let mut effective = node.ips.as_ref();
        for (i, name) in parts.iter().enumerate() {
            let child = match node.children.get(*name) {
                Some(child) => child,
                None => match find_child_alias(&node.children, name, &parts[..i], root).await {
                    Some(child) => child,
                    None => break,
                },
            };
            node = child;
            if node.ips.is_some() {
                effective = node.ips.as_ref();
            }
        }
        effective
    }

    /// All explicitly configured rules as `(path, address strings)` pairs.
    pub fn rules(&self) -> Vec<(String, Vec<String>)> {
        let mut output = Vec::new();
        self.collect_rules(&self.root, String::new(), &mut output);
        output
    }

    fn collect_rules(
        &self,
        node: &IpNode,
        prefix: String,
        output: &mut Vec<(String, Vec<String>)>,
    ) {
        if let Some(ips) = &node.ips {
            let path = if prefix.is_empty() {
                "/".to_string()
            } else {
                format!("/{prefix}")
            };
            output.push((path, ips.iter().map(|v| v.to_string()).collect()));
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

/// Deserialize the ip-whitelist configuration value.
///
/// Accepts a single rule string, a list of rule strings, or a mapping from path
/// to an address (or list of addresses).
pub fn deserialize_ip_whitelist<'de, D>(deserializer: D) -> Result<IpWhitelist, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum IpList {
        One(String),
        Many(Vec<String>),
    }

    struct IpWhitelistVisitor;

    impl<'de> serde::de::Visitor<'de> for IpWhitelistVisitor {
        type Value = IpWhitelist;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter
                .write_str("a rule string, a list of rule strings, or a map of paths to ip lists")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            IpWhitelist::new(&[s.to_owned()]).map_err(serde::de::Error::custom)
        }

        fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let rules: Vec<String> =
                Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))?;
            IpWhitelist::new(&rules).map_err(serde::de::Error::custom)
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut whitelist = IpWhitelist::default();
            while let Some((path, value)) = map.next_entry::<String, IpList>()? {
                let ips = match value {
                    IpList::One(v) => vec![v],
                    IpList::Many(v) => v,
                };
                whitelist
                    .insert_ips(&path, &ips)
                    .map_err(serde::de::Error::custom)?;
            }
            Ok(whitelist)
        }
    }

    deserializer.deserialize_any(IpWhitelistVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_ip_net_parse() {
        let net: IpNet = "192.168.1.1".parse().unwrap();
        assert_eq!(
            net,
            IpNet::V4 {
                addr: u32::from("192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap()),
                prefix: 32
            }
        );
        assert!(net.contains(ip("192.168.1.1")));
        assert!(!net.contains(ip("192.168.1.2")));

        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains(ip("10.1.2.3")));
        assert!(!net.contains(ip("11.0.0.1")));

        // host bits are masked away
        let net: IpNet = "192.168.1.5/24".parse().unwrap();
        assert_eq!(
            net,
            IpNet::V4 {
                addr: u32::from("192.168.1.0".parse::<std::net::Ipv4Addr>().unwrap()),
                prefix: 24
            }
        );
        assert!(net.contains(ip("192.168.1.200")));

        let net: IpNet = "::1".parse().unwrap();
        assert!(net.contains(ip("::1")));
        assert!(!net.contains(ip("::2")));

        let net: IpNet = "fd00::/8".parse().unwrap();
        assert!(net.contains(ip("fd12::1")));
        assert!(!net.contains(ip("fe80::1")));

        // a v4 range never matches a v6 address and vice versa
        let net: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(!net.contains(ip("::1")));
        assert!(net.contains(ip("8.8.8.8")));

        assert!("10.0.0.0/33".parse::<IpNet>().is_err());
        assert!("::/129".parse::<IpNet>().is_err());
        assert!("not-an-ip".parse::<IpNet>().is_err());
    }

    #[tokio::test]
    async fn test_inheritance_and_precedence() {
        let rules = vec![
            "127.0.0.1,10.0.0.0/8@/dir1".to_owned(),
            "192.168.0.0/16@/dir1/dir2".to_owned(),
            "127.0.0.1@/dir1/dir2/file.txt".to_owned(),
        ];
        let whitelist = IpWhitelist::new(&rules).unwrap();

        // root and unknown branches are unrestricted
        assert!(whitelist.allows("", Some(ip("8.8.8.8")), None).await);
        assert!(whitelist.allows("other", Some(ip("8.8.8.8")), None).await);

        // /dir1 and everything below inherits unless overridden
        assert!(whitelist.allows("dir1", Some(ip("10.1.1.1")), None).await);
        assert!(
            whitelist
                .allows("dir1/anything/x.txt", Some(ip("10.1.1.1")), None)
                .await
        );
        assert!(!whitelist.allows("dir1", Some(ip("8.8.8.8")), None).await);

        // nearest configured ancestor wins
        assert!(
            whitelist
                .allows("dir1/dir2", Some(ip("192.168.5.5")), None)
                .await
        );
        assert!(
            !whitelist
                .allows("dir1/dir2", Some(ip("10.1.1.1")), None)
                .await
        );
        assert!(
            whitelist
                .allows("dir1/dir2/other.txt", Some(ip("192.168.5.5")), None)
                .await
        );
        assert!(
            !whitelist
                .allows("dir1/dir2", Some(ip("127.0.0.1")), None)
                .await
        );

        // file level beats directory level
        assert!(
            whitelist
                .allows("dir1/dir2/file.txt", Some(ip("127.0.0.1")), None)
                .await
        );
        assert!(
            !whitelist
                .allows("dir1/dir2/file.txt", Some(ip("192.168.5.5")), None)
                .await
        );

        // an unknown client address cannot satisfy a configured list
        assert!(!whitelist.allows("dir1", None, None).await);
    }

    #[tokio::test]
    async fn test_deny_all_and_root_rule() {
        let whitelist =
            IpWhitelist::new(&["127.0.0.1@/".to_owned(), "@/private".to_owned()]).unwrap();
        assert!(
            whitelist
                .allows("file.txt", Some(ip("127.0.0.1")), None)
                .await
        );
        assert!(
            !whitelist
                .allows("file.txt", Some(ip("10.0.0.1")), None)
                .await
        );
        assert!(
            !whitelist
                .allows("private/a.txt", Some(ip("127.0.0.1")), None)
                .await
        );

        // a bare ip list applies to the root
        let whitelist = IpWhitelist::new(&["127.0.0.1".to_owned()]).unwrap();
        assert!(
            whitelist
                .allows("dir/file", Some(ip("127.0.0.1")), None)
                .await
        );
        assert!(
            !whitelist
                .allows("dir/file", Some(ip("10.0.0.1")), None)
                .await
        );

        assert!(IpWhitelist::default().is_empty());
    }

    #[tokio::test]
    async fn test_alias_names() {
        let dir = assert_fs::TempDir::new().unwrap();
        dir.child("dir1/secret.txt").write_str("x").unwrap();
        let root = dir.path();
        let whitelist = IpWhitelist::new(&["127.0.0.1@/DIR1".to_owned()]).unwrap();

        let folds_case = root.join("dir1").is_dir();
        // dir1 and DIR1 are the same object only where the filesystem folds case
        assert_eq!(
            whitelist
                .allows("dir1/secret.txt", Some(ip("10.0.0.1")), Some(root))
                .await,
            !folds_case
        );
        // the configured spelling itself always resolves
        assert!(
            !whitelist
                .allows("DIR1/secret.txt", Some(ip("10.0.0.1")), Some(root))
                .await
        );
    }
}
