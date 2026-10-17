use crate::ip_whitelist::IpNet;

use anyhow::{Context, Result};
use headers::HeaderMap;
use serde::{Deserialize, Deserializer};
use std::net::{IpAddr, SocketAddr};

/// Addresses of reverse proxies whose forwarded headers are trusted.
///
/// Forwarded headers are only honored when the connecting peer is one of
/// these addresses, otherwise any client could spoof its address and bypass
/// the ip whitelist.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    /// Build from specs like `127.0.0.1` or `10.0.0.0/8`.
    ///
    /// Each spec may contain several addresses separated by commas or by
    /// whitespace, so all of these are equivalent:
    ///
    /// ```text
    /// --trusted-proxy 192.168.16.10,10.194.0.0/24
    /// --trusted-proxy "192.168.16.10 10.194.0.0/24"
    /// --trusted-proxy 192.168.16.10 --trusted-proxy 10.194.0.0/24
    /// ```
    pub fn new(specs: &[String]) -> Result<Self> {
        let mut nets = Vec::new();
        for spec in specs {
            for part in spec.split(|c: char| c == ',' || c.is_whitespace()) {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                nets.push(part.parse::<IpNet>().with_context(|| {
                    format!(
                        "invalid trusted proxy '{part}', expected an ip address or a cidr range such as 192.168.16.10 or 10.194.0.0/24"
                    )
                })?);
            }
        }
        Ok(Self { nets })
    }

    /// Whether the address is itself a trusted proxy.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(ip))
    }

    /// Resolve the client address for a connection from `peer`.
    ///
    /// Without trusted proxies, or when `peer` is not trusted, the peer address
    /// is returned and the forwarded headers are ignored.
    pub fn resolve(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if self.nets.is_empty() || !self.contains(peer) {
            return peer;
        }
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // The right-most entry was appended by the proxy closest to us, so
            // it is the first one worth considering. Skip our own trusted
            // proxies and take the first address that is not one of them, which
            // is the client a well-behaved proxy chain saw.
            for part in value.split(',').rev() {
                if let Some(ip) = parse_ip(part) {
                    if !self.contains(ip) {
                        return ip;
                    }
                }
            }
        }
        if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Some(ip) = parse_ip(value) {
                return ip;
            }
        }
        peer
    }
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    // "[::1]" without a port
    value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .and_then(|v| v.parse().ok())
}

/// Deserialize the `trusted-proxy` configuration value: a single address, a
/// comma separated string, or a list of them.
pub fn deserialize_trusted_proxies<'de, D>(deserializer: D) -> Result<TrustedProxies, D::Error>
where
    D: Deserializer<'de>,
{
    struct TrustedProxiesVisitor;

    impl<'de> serde::de::Visitor<'de> for TrustedProxiesVisitor {
        type Value = TrustedProxies;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an address or a list of addresses")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            TrustedProxies::new(&[s.to_owned()]).map_err(serde::de::Error::custom)
        }

        fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let specs: Vec<String> =
                Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))?;
            TrustedProxies::new(&specs).map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_any(TrustedProxiesVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_disabled_or_untrusted_peer() {
        let empty = TrustedProxies::default();
        assert_eq!(
            empty.resolve(ip("127.0.0.1"), &headers(&[("x-forwarded-for", "1.2.3.4")])),
            ip("127.0.0.1")
        );

        let proxies = TrustedProxies::new(&["10.0.0.0/8".to_owned()]).unwrap();
        assert_eq!(
            proxies.resolve(ip("127.0.0.1"), &headers(&[("x-forwarded-for", "1.2.3.4")])),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn test_forwarded_headers() {
        let proxies =
            TrustedProxies::new(&["127.0.0.1".to_owned(), "10.0.0.0/8".to_owned()]).unwrap();
        assert_eq!(
            proxies.resolve(
                ip("127.0.0.1"),
                &headers(&[("x-forwarded-for", "203.0.113.9")])
            ),
            ip("203.0.113.9")
        );
        // the right-most trusted hop is skipped
        assert_eq!(
            proxies.resolve(
                ip("127.0.0.1"),
                &headers(&[("x-forwarded-for", "203.0.113.9, 10.1.2.3")])
            ),
            ip("203.0.113.9")
        );
        // ports and bracketed ipv6 are accepted
        assert_eq!(
            proxies.resolve(
                ip("127.0.0.1"),
                &headers(&[("x-forwarded-for", "203.0.113.9:4567")])
            ),
            ip("203.0.113.9")
        );
        let v6 = TrustedProxies::new(&["::1".to_owned()]).unwrap();
        assert_eq!(
            v6.resolve(
                ip("::1"),
                &headers(&[("x-forwarded-for", "[2001:db8::1]:443")])
            ),
            ip("2001:db8::1")
        );
        // x-real-ip is the fallback when x-forwarded-for is unusable
        assert_eq!(
            proxies.resolve(ip("127.0.0.1"), &headers(&[("x-real-ip", "198.51.100.7")])),
            ip("198.51.100.7")
        );
        // a fully trusted chain falls back to the peer
        assert_eq!(
            proxies.resolve(
                ip("127.0.0.1"),
                &headers(&[("x-forwarded-for", "10.1.2.3")])
            ),
            ip("127.0.0.1")
        );
        // malformed entries are skipped
        assert_eq!(
            proxies.resolve(
                ip("127.0.0.1"),
                &headers(&[("x-forwarded-for", "garbage, 203.0.113.9")])
            ),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn test_parse_trusted_proxies() {
        let proxies =
            TrustedProxies::new(&["127.0.0.1, ::1".to_owned(), "10.0.0.0/8".to_owned()]).unwrap();
        assert!(proxies.contains(ip("127.0.0.1")));
        assert!(proxies.contains(ip("::1")));
        assert!(proxies.contains(ip("10.9.9.9")));
        assert!(!proxies.contains(ip("8.8.8.8")));

        // a single spec may hold a whitespace separated list
        let proxies = TrustedProxies::new(&["192.168.16.10 10.194.0.0/24".to_owned()]).unwrap();
        assert!(proxies.contains(ip("192.168.16.10")));
        assert!(proxies.contains(ip("10.194.0.7")));
        assert!(!proxies.contains(ip("10.195.0.1")));

        // one entry per spec, mixed families and plain/cidr forms
        let proxies = TrustedProxies::new(&[
            "192.168.16.10".to_owned(),
            "10.194.0.0/24".to_owned(),
            "::1".to_owned(),
        ])
        .unwrap();
        assert!(proxies.contains(ip("192.168.16.10")));
        assert!(proxies.contains(ip("10.194.0.7")));
        assert!(proxies.contains(ip("::1")));
        assert!(!proxies.contains(ip("10.194.1.7")));

        let err = TrustedProxies::new(&["not-an-ip".to_owned()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid trusted proxy 'not-an-ip'"), "{err}");
        assert!(err.contains("10.194.0.0/24"), "{err}");
    }
}
