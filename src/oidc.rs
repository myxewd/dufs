use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use headers::HeaderMap;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Name of the session cookie set after a successful OIDC login.
pub const SESSION_COOKIE: &str = "dufs_oidc_session";

const STATE_TTL: Duration = Duration::from_secs(600);

/// The concrete endpoint state produced by `CoreProviderMetadata::discover`.
type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// OIDC parameters, read from the environment.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub username_claim: String,
    pub session_ttl: Duration,
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

impl OidcConfig {
    pub fn from_env() -> Result<Self> {
        let issuer = env_var("DUFS_OIDC_ISSUER")
            .ok_or_else(|| anyhow!("DUFS_OIDC_ISSUER is required when the auth type is oidc"))?;
        let client_id = env_var("DUFS_OIDC_CLIENT_ID")
            .ok_or_else(|| anyhow!("DUFS_OIDC_CLIENT_ID is required when the auth type is oidc"))?;
        let redirect_uri = env_var("DUFS_OIDC_REDIRECT_URI").ok_or_else(|| {
            anyhow!("DUFS_OIDC_REDIRECT_URI is required when the auth type is oidc")
        })?;
        let scopes = env_var("DUFS_OIDC_SCOPES")
            .unwrap_or_else(|| "openid profile email".to_string())
            .split_whitespace()
            .map(|scope| scope.to_string())
            .collect();
        let username_claim =
            env_var("DUFS_OIDC_USERNAME_CLAIM").unwrap_or_else(|| "preferred_username".to_string());
        let session_hours = env_var("DUFS_OIDC_SESSION_HOURS")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(24 * 7);
        Ok(Self {
            issuer,
            client_id,
            client_secret: env_var("DUFS_OIDC_CLIENT_SECRET"),
            redirect_uri,
            scopes,
            username_claim,
            session_ttl: Duration::from_secs(session_hours.saturating_mul(3600)),
        })
    }
}

struct PendingLogin {
    nonce: String,
    pkce_verifier: String,
    next: String,
    expires: Instant,
}

struct Session {
    username: String,
    expires: Instant,
}

/// OIDC authorization code client with in-memory pending logins and sessions.
pub struct Oidc {
    config: OidcConfig,
    http: reqwest::Client,
    client: Mutex<Option<OidcClient>>,
    pending: Mutex<HashMap<String, PendingLogin>>,
    sessions: Mutex<HashMap<String, Session>>,
}

impl Oidc {
    pub fn new(config: OidcConfig) -> Result<Self> {
        // Validate the configured urls eagerly so a typo fails at startup.
        IssuerUrl::new(config.issuer.clone()).context("invalid DUFS_OIDC_ISSUER")?;
        RedirectUrl::new(config.redirect_uri.clone()).context("invalid DUFS_OIDC_REDIRECT_URI")?;
        let http = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to build the OIDC http client")?;
        Ok(Self {
            config,
            http,
            client: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub fn session_ttl(&self) -> Duration {
        self.config.session_ttl
    }

    async fn provider_client(&self) -> Result<OidcClient> {
        if let Some(client) = self.client.lock().unwrap().clone() {
            return Ok(client);
        }
        let issuer = IssuerUrl::new(self.config.issuer.clone())?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &self.http)
            .await
            .map_err(|err| anyhow!("OIDC discovery failed: {err}"))?;
        let client = OidcClient::from_provider_metadata(
            metadata,
            ClientId::new(self.config.client_id.clone()),
            self.config.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(RedirectUrl::new(self.config.redirect_uri.clone())?);
        *self.client.lock().unwrap() = Some(client.clone());
        Ok(client)
    }

    /// Build the provider authorization url and remember the request state.
    pub async fn begin_login(&self, next: &str) -> Result<String> {
        let client = self.provider_client().await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in &self.config.scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let (url, csrf, nonce) = request.url();
        let state = csrf.secret().to_string();
        self.pending.lock().unwrap().insert(
            state,
            PendingLogin {
                nonce: nonce.secret().to_string(),
                pkce_verifier: verifier.secret().to_string(),
                next: sanitize_next(next),
                expires: Instant::now() + STATE_TTL,
            },
        );
        Ok(url.as_str().to_string())
    }

    /// Exchange the authorization code and return the username and return path.
    pub async fn complete_login(&self, code: String, state: String) -> Result<(String, String)> {
        let pending = {
            let mut pending = self.pending.lock().unwrap();
            pending.retain(|_, value| value.expires > Instant::now());
            pending
                .remove(&state)
                .ok_or_else(|| anyhow!("invalid or expired OIDC state"))?
        };
        let client = self.provider_client().await?;
        let token_response = client
            .exchange_code(AuthorizationCode::new(code))?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
            .request_async(&self.http)
            .await
            .map_err(|err| anyhow!("OIDC token exchange failed: {err}"))?;
        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("the OIDC provider did not return an id_token"))?;
        let verifier = client.id_token_verifier();
        id_token
            .claims(&verifier, &Nonce::new(pending.nonce))
            .map_err(|err| anyhow!("OIDC id_token validation failed: {err}"))?;
        let raw = serde_json::to_value(id_token)
            .ok()
            .and_then(|value| value.as_str().map(|value| value.to_string()))
            .ok_or_else(|| anyhow!("failed to read the raw id_token"))?;
        let username = extract_username(&raw, &self.config.username_claim)?;
        Ok((username, pending.next))
    }

    pub fn create_session(&self, username: String) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| session.expires > Instant::now());
        sessions.insert(
            id.clone(),
            Session {
                username,
                expires: Instant::now() + self.config.session_ttl,
            },
        );
        id
    }

    pub fn session_user(&self, id: &str) -> Option<String> {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(id) {
            Some(session) if session.expires > Instant::now() => Some(session.username.clone()),
            Some(_) => {
                sessions.remove(id);
                None
            }
            None => None,
        }
    }

    pub fn remove_session(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }

    /// Read the session id from the request cookie header.
    pub fn session_id(headers: &HeaderMap) -> Option<String> {
        let value = headers.get("cookie")?.to_str().ok()?;
        for part in value.split(';') {
            if let Some(rest) = part.trim().strip_prefix(SESSION_COOKIE) {
                if let Some(id) = rest.strip_prefix('=') {
                    if !id.is_empty() {
                        return Some(id.to_string());
                    }
                }
            }
        }
        None
    }
}

fn sanitize_next(next: &str) -> String {
    let local = next.starts_with('/')
        && !next.starts_with("//")
        && !next.contains('\\')
        && !next.split('/').any(|part| part == "..");
    if local {
        next.to_string()
    } else {
        "/".to_string()
    }
}

/// Extract the configured username claim from an already validated id_token.
///
/// The standard `preferred_username` claim is the default; `name`/`nickname` are
/// deliberately not used unless explicitly configured.
fn extract_username(id_token: &str, claim: &str) -> Result<String> {
    let payload = id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow!("malformed id_token"))?;
    let payload = payload.trim_end_matches('=');
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .context("malformed id_token payload")?;
    let claims: serde_json::Value =
        serde_json::from_slice(&bytes).context("malformed id_token claims")?;
    match claims.get(claim).and_then(|value| value.as_str()) {
        Some(value) if !value.is_empty() => Ok(value.to_string()),
        _ => bail!("the id_token does not contain a non-empty '{claim}' claim"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn fake_jwt(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn test_extract_username_prefers_configured_claim() {
        let jwt = fake_jwt(serde_json::json!({
            "preferred_username": "alice",
            "nickname": "Ali",
            "name": "Alice Example"
        }));
        assert_eq!(
            extract_username(&jwt, "preferred_username").unwrap(),
            "alice"
        );
        // nickname is only used when explicitly configured
        assert_eq!(extract_username(&jwt, "nickname").unwrap(), "Ali");
        assert!(extract_username(&jwt, "username").is_err());

        let jwt = fake_jwt(serde_json::json!({ "username": "bob" }));
        assert_eq!(extract_username(&jwt, "username").unwrap(), "bob");
    }

    #[test]
    fn test_sanitize_next() {
        assert_eq!(sanitize_next("/dir/file"), "/dir/file");
        assert_eq!(sanitize_next("https://evil.example"), "/");
        assert_eq!(sanitize_next("//evil.example"), "/");
        assert_eq!(sanitize_next("/a\\b"), "/");
        assert_eq!(sanitize_next("/..//evil.example"), "/");
        assert_eq!(sanitize_next(""), "/");
    }

    #[test]
    fn test_session_id() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("a=1; dufs_oidc_session=abc; b=2"),
        );
        assert_eq!(Oidc::session_id(&headers), Some("abc".to_string()));
        headers.insert("cookie", HeaderValue::from_static("a=1"));
        assert_eq!(Oidc::session_id(&headers), None);
    }
}
