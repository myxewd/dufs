#![allow(clippy::too_many_arguments)]

use crate::args::AuthType;
use crate::auth::{is_readonly_method, www_authenticate, AccessPaths, AccessPerm};
use crate::http_utils::{body_full, IncomingStream, LengthLimitedStream};
use crate::ip_whitelist::{IpNet, IpWhitelist};
use crate::ip_whitelist_store;
use crate::noscript::{detect_noscript, generate_noscript_html};
use crate::oidc::{Oidc, OidcConfig, SESSION_COOKIE};
use crate::user_acl::{self, AclMember, AclMemberKind, AclPerm, UserAcl, UserRule};
use crate::utils::{
    decode_uri, encode_uri, get_file_name, glob, join_within, parse_range, try_get_file_name,
};
use crate::Args;

use anyhow::{anyhow, Result};
use async_deflate_zip::{CompressionLevel, ZipWriter};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use chrono::{LocalResult, TimeZone, Utc};
use futures_util::{pin_mut, TryStreamExt};
use headers::{
    AcceptRanges, AccessControlAllowCredentials, AccessControlAllowOrigin, CacheControl,
    ContentLength, ContentType, ETag, HeaderMap, HeaderMapExt, IfMatch, IfModifiedSince,
    IfNoneMatch, IfRange, IfUnmodifiedSince, LastModified, Range,
};
use http_body_util::{combinators::BoxBody, BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::{
    body::Incoming,
    header::{
        HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE,
        CONTENT_TYPE, RANGE,
    },
    Method, StatusCode, Uri,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::Metadata;
use std::io::SeekFrom;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf, MAIN_SEPARATOR};
use std::sync::atomic::{self, AtomicBool};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite};
use tokio::{fs, io};

use tokio_util::io::{ReaderStream, StreamReader};
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};
use xml::escape::escape_str_pcdata;

pub type Request = hyper::Request<Incoming>;
pub type Response = hyper::Response<BoxBody<Bytes, anyhow::Error>>;

const INDEX_HTML: &str = include_str!("../assets/index.html");
const INDEX_CSS: &str = include_str!("../assets/index.css");
const INDEX_JS: &str = include_str!("../assets/index.js");
const FAVICON_ICO: &[u8] = include_bytes!("../assets/favicon.ico");
const INDEX_NAME: &str = "index.html";
const BUF_SIZE: usize = 65536;
const EDITABLE_TEXT_MAX_SIZE: u64 = 4194304; // 4M
const RESUMABLE_UPLOAD_MIN_SIZE: u64 = 20971520; // 20M
const HEALTH_CHECK_PATH: &str = "__dufs__/health";
const IP_WHITELIST_API_PATH: &str = "__dufs__/ip-whitelist";
const ACL_API_PATH: &str = "__dufs__/acl";
const OIDC_PREFIX: &str = "__dufs__/oidc/";
pub const MAX_SUBPATHS_COUNT: u64 = 1000;

pub struct Server {
    args: Args,
    assets_prefix: String,
    html: Cow<'static, str>,
    single_file_req_paths: Vec<String>,
    ip_whitelist: RwLock<Arc<IpWhitelist>>,
    user_acl: RwLock<Arc<UserAcl>>,
    oidc: Option<Oidc>,
    running: Arc<AtomicBool>,
}

impl Server {
    pub fn init(mut args: Args, running: Arc<AtomicBool>) -> Result<Self> {
        // Include a hash of the embedded assets so browsers pick up a changed
        // index.js/index.css even when the crate version did not change.
        let assets_hash = {
            let mut hasher = Sha256::new();
            match args.assets.as_ref() {
                // An overridden assets directory may be edited between runs;
                // hash what is actually served so the browser cache-busting
                // prefix follows the files on disk.
                Some(dir) => {
                    for name in ["index.html", "index.css", "index.js"] {
                        if let Ok(bytes) = std::fs::read(dir.join(name)) {
                            hasher.update(&bytes);
                        }
                    }
                }
                None => {
                    hasher.update(INDEX_HTML.as_bytes());
                    hasher.update(INDEX_CSS.as_bytes());
                    hasher.update(INDEX_JS.as_bytes());
                }
            }
            hex::encode(&hasher.finalize()[..4])
        };
        let assets_prefix = format!("__dufs_v{}_{}__/", env!("CARGO_PKG_VERSION"), assets_hash);
        let single_file_req_paths = if args.path_is_file {
            vec![
                args.uri_prefix.to_string(),
                args.uri_prefix[0..args.uri_prefix.len() - 1].to_string(),
                encode_uri(&format!(
                    "{}{}",
                    args.uri_prefix,
                    get_file_name(&args.serve_path)
                )),
            ]
        } else {
            vec![]
        };
        let html = match args.assets.as_ref() {
            Some(path) => Cow::Owned(std::fs::read_to_string(path.join("index.html"))?),
            None => Cow::Borrowed(INDEX_HTML),
        };

        if !args
            .hidden
            .iter()
            .any(|v| v == ip_whitelist_store::METADATA_DIR)
        {
            args.hidden
                .push(ip_whitelist_store::METADATA_DIR.to_string());
        }

        // A persisted store is authoritative. When management is enabled and no
        // store exists yet, the --ip-whitelist rules seed it so the WebUI can edit
        // them. A CLI-only run keeps the rules in memory instead.
        let ip_whitelist = if args.path_is_file {
            Arc::new(IpWhitelist::default())
        } else if ip_whitelist_store::exists(&args.serve_path) {
            Arc::new(ip_whitelist_store::load(&args.serve_path)?)
        } else {
            if args.allow_ip_whitelist && !args.ip_whitelist.is_empty() {
                if let Err(err) = ip_whitelist_store::save(&args.serve_path, &args.ip_whitelist) {
                    warn!("Failed to persist the --ip-whitelist rules, {err}");
                }
            }
            Arc::new(args.ip_whitelist.clone())
        };

        let user_acl = if args.path_is_file {
            Arc::new(UserAcl::default())
        } else {
            Arc::new(user_acl::load(&args.serve_path)?)
        };

        let oidc = match args.auth_type {
            AuthType::Oidc => {
                if !args.auth.has_users() {
                    return Err(anyhow!(
                        "--auth-type oidc requires at least one --auth rule, e.g. --auth 'user:pass@/:rw'"
                    ));
                }
                Some(Oidc::new(OidcConfig::from_env()?)?)
            }
            AuthType::Builtin => None,
        };

        Ok(Self {
            args,
            running,
            single_file_req_paths,
            assets_prefix,
            html,
            ip_whitelist: RwLock::new(ip_whitelist),
            user_acl: RwLock::new(user_acl),
            oidc,
        })
    }

    pub async fn call(
        self: Arc<Self>,
        req: Request,
        addr: Option<SocketAddr>,
    ) -> Result<Response, hyper::Error> {
        let uri = req.uri().clone();
        let assets_prefix = &self.assets_prefix;
        let enable_cors = self.args.enable_cors;
        let mut http_log_data = self.args.http_logger.data(&req);
        // Behind a trusted proxy the forwarded header identifies the client;
        // otherwise only the socket peer is trusted.
        let client_ip = addr.map(|addr| self.args.trusted_proxy.resolve(addr.ip(), req.headers()));
        if let Some(ip) = client_ip {
            http_log_data.insert("remote_addr".to_string(), ip.to_string());
        }

        let mut res = match self.clone().handle(req, client_ip).await {
            Ok(res) => {
                http_log_data.insert("status".to_string(), res.status().as_u16().to_string());
                if !uri.path().starts_with(assets_prefix) {
                    self.args.http_logger.log(&http_log_data, None);
                }
                res
            }
            Err(err) => {
                let mut res = Response::default();
                let status = StatusCode::INTERNAL_SERVER_ERROR;
                *res.status_mut() = status;
                http_log_data.insert("status".to_string(), status.as_u16().to_string());
                self.args
                    .http_logger
                    .log(&http_log_data, Some(err.to_string()));
                res
            }
        };

        // Expose the address the server actually used for its ip-whitelist
        // decisions. Behind a proxy this makes a missing or wrong
        // --trusted-proxy visible immediately: without it every request
        // silently looks like it came from the proxy itself.
        if let Some(ip) = client_ip {
            if let Ok(value) = HeaderValue::from_str(&ip.to_string()) {
                res.headers_mut().insert("x-client-ip", value);
            }
        }

        if enable_cors {
            add_cors(&mut res);
        }
        Ok(res)
    }

    pub async fn handle(self: Arc<Self>, req: Request, ip: Option<IpAddr>) -> Result<Response> {
        let mut res = Response::default();

        let req_path = req.uri().path().to_string();
        let method = req.method().clone();

        let relative_path = match self.resolve_path(&req_path) {
            Some(v) => v,
            None => {
                status_bad_request(&mut res, "Invalid Path");
                return Ok(res);
            }
        };

        // The metadata directory is internal: never served, listed, searched
        // or archived, even for an x user. Match case-insensitively so a
        // case-insensitive filesystem cannot be used to bypass it.
        let lower_path = relative_path.to_ascii_lowercase();
        if lower_path == ip_whitelist_store::METADATA_DIR
            || lower_path.starts_with(&format!("{}/", ip_whitelist_store::METADATA_DIR))
        {
            status_not_found(&mut res);
            return Ok(res);
        }

        if (method == Method::GET || method == Method::HEAD)
            && self
                .handle_internal(
                    &relative_path,
                    method == Method::HEAD,
                    req.headers(),
                    &mut res,
                )
                .await?
        {
            return Ok(res);
        }

        // The management API is guarded by authentication rather than the ip
        // whitelist, so an administrator is never locked out of fixing a rule.
        // It must be dispatched before the ip check: otherwise a wrong rule
        // makes the api itself unreachable and the only fix is editing the
        // json on disk.
        if relative_path == IP_WHITELIST_API_PATH {
            return self.handle_ip_whitelist(req, method).await;
        }
        if relative_path == ACL_API_PATH {
            return self.handle_acl(req, method).await;
        }

        let ip_ok = self.ip_allowed(&relative_path, ip).await;
        // The ip whitelist is the highest layer for content: it applies to
        // guests, users and acl managers alike, including the acl browsing view.
        if !ip_ok {
            status_forbid(&mut res);
            return Ok(res);
        }

        let headers = req.headers();

        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase())
            .unwrap_or_default();

        let is_microsoft_webdav = user_agent.starts_with("microsoft-webdav-miniredir/");

        if is_microsoft_webdav {
            // microsoft webdav requires this.
            res.headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }

        let authorization = headers.get(AUTHORIZATION);

        let query = req.uri().query().unwrap_or_default();
        let mut query_params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if let Some(oidc) = &self.oidc {
            if let Some(action) = relative_path.strip_prefix(OIDC_PREFIX) {
                if !ip_ok {
                    status_forbid(&mut res);
                    return Ok(res);
                }
                return self.handle_oidc(oidc, action, &req).await;
            }
        }

        let (user, access_paths, via_token) = if let Some(oidc) = &self.oidc {
            self.guard_oidc(oidc, headers, &relative_path, &method)
                .await
        } else {
            self.args
                .auth
                .guard(
                    &relative_path,
                    &method,
                    authorization,
                    query_params.get("token"),
                    is_microsoft_webdav,
                    &self.args.serve_path,
                )
                .await
        };

        // The top-right Login button navigates to `?login`. Challenge unless a
        // real user is authenticated, even when the browser still has cached
        // guest credentials, so the login always starts a fresh authentication.
        if has_query_flag(&query_params, "login") {
            if self.oidc.is_some() {
                let next = urlencoding::encode(req_path.as_str());
                let location = format!("{}__dufs__/oidc/login?next={next}", self.args.uri_prefix);
                redirect(&mut res, &location);
                return Ok(res);
            }
            let is_guest = user.as_deref().is_none_or(|user| user == "guest");
            if self.args.auth.has_users() && is_guest {
                self.auth_reject(&mut res)?;
                return Ok(res);
            }
            // Authenticated: drop the `?login` marker and return to the
            // page that started the login (the root for `/?login`).
            redirect(&mut res, &req_path);
            return Ok(res);
        }

        let acl_user = user.as_deref().unwrap_or("guest").to_string();
        // x is a native permission: it wins over the acl, including deny
        // rules. x users are still limited by the ip whitelist above.
        let is_x = access_paths.as_ref().is_some_and(|ap| ap.acl());
        // Whether the request only walks to a granted descendant instead of
        // reading the path itself (see the acl handling below).
        let mut traversal = false;
        let access_paths = if is_x {
            let mut ap = access_paths.unwrap_or_default();
            ap.set_perm(AccessPerm::ReadWrite);
            Some(ap)
        } else {
            // The acl sits on top of --auth: a listed user gets the listed
            // level even when --auth does not grant it, and a covered path
            // defaults to deny for users missing from its rule.
            let acl = self.acl_perm(&relative_path, &acl_user).await;
            let method_is_write = !is_readonly_method(&method);
            // When the acl covers nothing here the path falls back to --auth.
            // --auth may refuse it (no rule for this user at all, or an
            // index-only root) while a rule below still grants something: the
            // ancestor then has to stay walkable, otherwise the grant has no
            // entry point in the file list.
            traversal = acl.is_none()
                && !access_paths
                    .as_ref()
                    .is_some_and(|ap| !ap.perm().indexonly())
                && self.has_grant_below(&relative_path, &acl_user).await;
            if matches!(acl, Some(AclPerm::Deny))
                || (matches!(acl, Some(AclPerm::Read | AclPerm::Traverse)) && method_is_write)
                || (traversal && method_is_write)
            {
                status_forbid(&mut res);
                return Ok(res);
            }
            match acl {
                // A traversable directory only lets the user walk to a granted
                // child: the listing filters the entries, and the page stays
                // read-only so nothing can be created, renamed or deleted here.
                Some(AclPerm::Read | AclPerm::Traverse) => {
                    let mut ap = access_paths.unwrap_or_default();
                    ap.set_perm(AccessPerm::ReadOnly);
                    Some(ap)
                }
                Some(AclPerm::Write) => {
                    let mut ap = access_paths.unwrap_or_default();
                    ap.set_perm(AccessPerm::ReadWrite);
                    Some(ap)
                }
                Some(AclPerm::Deny) => unreachable!(),
                None => access_paths,
            }
        };

        let (user, access_paths) = match (user, access_paths) {
            (None, None) => {
                if traversal {
                    // Walk-only paths stay index-only: --auth grants nothing
                    // here, so no entry below counts as natively readable.
                    (None, AccessPaths::default())
                } else if self.oidc.is_some() {
                    let guest = self.args.auth.guest_paths().is_some();
                    if guest {
                        // The guest identity exists but this path is not granted
                        // to it; the login button is available on allowed pages.
                        status_forbid(&mut res);
                    } else {
                        let next = urlencoding::encode(req_path.as_str());
                        let location =
                            format!("{}__dufs__/oidc/login?next={next}", self.args.uri_prefix);
                        redirect(&mut res, &location);
                    }
                    return Ok(res);
                } else {
                    // Builtin auth challenges the request so the browser can
                    // prompt for credentials, even when a guest identity exists.
                    self.auth_reject(&mut res)?;
                    return Ok(res);
                }
            }
            (Some(user), None) => {
                if traversal {
                    (Some(user), AccessPaths::default())
                } else {
                    status_forbid(&mut res);
                    return Ok(res);
                }
            }
            (x, Some(y)) => (x, y),
        };

        // Deleting or renaming also needs write permission on the parent
        // directory, so a readable-but-unwritable parent cannot be bypassed.
        if (method == Method::DELETE || method.as_str() == "MOVE")
            && !self
                .parent_writable(&relative_path, &acl_user, &method, authorization, headers)
                .await
        {
            status_forbid(&mut res);
            return Ok(res);
        }

        if detect_noscript(&user_agent) {
            query_params.insert("noscript".to_string(), String::new());
        }

        if method.as_str() == "CHECKAUTH" {
            match user.clone() {
                Some(user) => {
                    *res.body_mut() = body_full(user);
                }
                None => {
                    if has_query_flag(&query_params, "login") || !access_paths.perm().readwrite() {
                        self.auth_reject(&mut res)?
                    } else {
                        *res.body_mut() = body_full("");
                    }
                }
            }
            return Ok(res);
        } else if method.as_str() == "LOGOUT" {
            if let Some(oidc) = &self.oidc {
                if let Some(session_id) = Oidc::session_id(headers) {
                    oidc.remove_session(&session_id);
                }
                res.headers_mut()
                    .insert("set-cookie", self.clear_session_cookie());
                *res.status_mut() = StatusCode::NO_CONTENT;
            } else {
                self.auth_reject(&mut res)?;
            }
            return Ok(res);
        }

        let head_only = method == Method::HEAD || method == Method::OPTIONS;

        if has_query_flag(&query_params, "tokengen") {
            // A share token must not be able to mint another token, otherwise a
            // short-lived link could be renewed forever regardless of expiry.
            if via_token || self.oidc.is_some() {
                self.auth_reject(&mut res)?;
                return Ok(res);
            }
            self.handle_tokengen(&relative_path, user, head_only, &mut res)
                .await?;
            return Ok(res);
        }

        // TODO(virtual-file): dispatch a virtual file here. A virtual file has
        // no file on disk; it only exists in .dufs/virtual-files.json and
        // proxies every request to an upstream. It has to be handled after the
        // acl and ip checks above, so it inherits the read/write rules of the
        // path it pretends to be, and before the filesystem lookup below.
        // Still to do: the .dufs store, the streaming proxy, the
        // PathType::Virtual listing entry and the __dufs__/virtual-files api.
        if self.args.path_is_file {
            if self
                .single_file_req_paths
                .iter()
                .any(|v| v.as_str() == req_path.as_str())
            {
                self.handle_send_file(&self.args.serve_path, headers, head_only, &mut res)
                    .await?;
            } else {
                self.handle_not_found(&query_params, head_only, &mut res)
                    .await?;
            }
            return Ok(res);
        }
        let path = match self.join_path(&relative_path) {
            Some(v) => v,
            None => {
                status_forbid(&mut res);
                return Ok(res);
            }
        };

        let path = path.as_path();

        let (is_miss, is_dir, is_file, size) = match fs::metadata(path).await.ok() {
            Some(meta) => (false, meta.is_dir(), meta.is_file(), meta.len()),
            None => (true, false, false, 0),
        };

        if !ip_ok {
            // A manager may browse directories to configure their rules, but
            // still may not read file contents or write on a denied path.
            let can_list = (method == Method::GET || method == Method::HEAD)
                && is_dir
                && !has_query_flag(&query_params, "zip");
            let can_meta = method == Method::OPTIONS || method.as_str() == "PROPFIND";
            if !(can_list || can_meta) {
                status_forbid(&mut res);
                return Ok(res);
            }
        }

        let allow_upload = self.args.allow_upload;
        let allow_delete = self.args.allow_delete;
        let allow_search = self.args.allow_search;
        let allow_archive = self.args.allow_archive;
        let render_index = self.args.render_index;
        let render_spa = self.args.render_spa;
        let render_try_index = self.args.render_try_index;

        if self.guard_root_contained(path).await
            || (self.args.allow_symlink && self.guard_metadata_contained(path).await)
        {
            self.handle_not_found(&query_params, head_only, &mut res)
                .await?;
            return Ok(res);
        }

        match method {
            Method::GET | Method::HEAD => {
                if is_dir {
                    if render_try_index {
                        if allow_archive && has_query_flag(&query_params, "zip") {
                            if !allow_archive {
                                self.handle_not_found(&query_params, head_only, &mut res)
                                    .await?;
                                return Ok(res);
                            }
                            self.handle_zip_dir(
                                path,
                                head_only,
                                access_paths,
                                ip,
                                &acl_user,
                                &mut res,
                            )
                            .await?;
                        } else if allow_search && query_params.contains_key("q") {
                            self.handle_search_dir(
                                path,
                                &query_params,
                                head_only,
                                user,
                                access_paths,
                                ip,
                                &mut res,
                            )
                            .await?;
                        } else {
                            self.handle_render_index(
                                path,
                                &query_params,
                                headers,
                                head_only,
                                user,
                                access_paths,
                                ip,
                                &acl_user,
                                &mut res,
                            )
                            .await?;
                        }
                    } else if render_index || render_spa {
                        self.handle_render_index(
                            path,
                            &query_params,
                            headers,
                            head_only,
                            user,
                            access_paths,
                            ip,
                            &acl_user,
                            &mut res,
                        )
                        .await?;
                    } else if has_query_flag(&query_params, "zip") {
                        if !allow_archive {
                            status_not_found(&mut res);
                            return Ok(res);
                        }
                        self.handle_zip_dir(path, head_only, access_paths, ip, &acl_user, &mut res)
                            .await?;
                    } else if allow_search && query_params.contains_key("q") {
                        self.handle_search_dir(
                            path,
                            &query_params,
                            head_only,
                            user,
                            access_paths,
                            ip,
                            &mut res,
                        )
                        .await?;
                    } else {
                        self.handle_ls_dir(
                            path,
                            true,
                            &query_params,
                            head_only,
                            user,
                            access_paths,
                            ip,
                            &mut res,
                        )
                        .await?;
                    }
                } else if is_file {
                    if has_query_flag(&query_params, "json") {
                        self.handle_file_json(path, head_only, &mut res).await?;
                    } else if has_query_flag(&query_params, "edit") {
                        self.handle_edit_file(path, DataKind::Edit, head_only, user, &mut res)
                            .await?;
                    } else if has_query_flag(&query_params, "view") {
                        self.handle_edit_file(path, DataKind::View, head_only, user, &mut res)
                            .await?;
                    } else if has_query_flag(&query_params, "hash") {
                        if self.args.allow_hash {
                            self.handle_hash_file(path, head_only, &mut res).await?;
                        } else {
                            status_forbid(&mut res);
                        }
                    } else {
                        self.handle_send_file(path, headers, head_only, &mut res)
                            .await?;
                    }
                } else if render_spa {
                    self.handle_render_spa(
                        path,
                        &query_params,
                        headers,
                        head_only,
                        ip,
                        &acl_user,
                        &mut res,
                    )
                    .await?;
                } else if allow_upload && req_path.ends_with('/') {
                    self.handle_ls_dir(
                        path,
                        false,
                        &query_params,
                        head_only,
                        user,
                        access_paths,
                        ip,
                        &mut res,
                    )
                    .await?;
                } else {
                    self.handle_not_found(&query_params, head_only, &mut res)
                        .await?;
                }
            }
            Method::OPTIONS => {
                set_webdav_headers(&mut res);
            }
            Method::PUT => {
                if is_dir || !allow_upload || (!allow_delete && size > 0) {
                    status_forbid(&mut res);
                } else {
                    self.handle_upload(path, None, size, req, &mut res).await?;
                }
            }
            Method::PATCH => {
                if is_miss {
                    status_not_found(&mut res);
                } else if !allow_upload {
                    status_forbid(&mut res);
                } else {
                    let offset = match parse_upload_offset(headers, size) {
                        Ok(v) => v,
                        Err(err) => {
                            status_bad_request(&mut res, &err.to_string());
                            return Ok(res);
                        }
                    };
                    match offset {
                        Some(offset) => {
                            if offset < size && !allow_delete {
                                status_forbid(&mut res);
                                return Ok(res);
                            }
                            self.handle_upload(path, Some(offset), size, req, &mut res)
                                .await?;
                        }
                        None => {
                            *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                        }
                    }
                }
            }
            Method::DELETE => {
                if !allow_delete {
                    status_forbid(&mut res);
                } else if !is_miss {
                    self.handle_delete(path, is_dir, &mut res).await?
                } else {
                    status_not_found(&mut res);
                }
            }
            method => match method.as_str() {
                "PROPFIND" => {
                    if is_dir {
                        let access_paths =
                            if access_paths.perm().indexonly() && authorization.is_none() {
                                // see https://github.com/sigoden/dufs/issues/229
                                AccessPaths::new(AccessPerm::ReadOnly)
                            } else {
                                access_paths
                            };
                        let propfind_is_auth_x = access_paths.acl() && user.is_some();
                        self.handle_propfind_dir(
                            path,
                            headers,
                            access_paths,
                            ip,
                            &acl_user,
                            propfind_is_auth_x,
                            &mut res,
                        )
                        .await?;
                    } else if is_file {
                        self.handle_propfind_file(path, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "PROPPATCH" => {
                    if is_file {
                        self.handle_proppatch(&req_path, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "MKCOL" => {
                    if !allow_upload {
                        status_forbid(&mut res);
                    } else if !is_miss {
                        *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                        *res.body_mut() = body_full("Already exists");
                    } else {
                        self.handle_mkcol(path, &mut res).await?;
                    }
                }
                "COPY" => {
                    if !allow_upload {
                        status_forbid(&mut res);
                    } else if is_miss {
                        status_not_found(&mut res);
                    } else {
                        self.handle_copy(path, &req, ip, &mut res).await?
                    }
                }
                "MOVE" => {
                    if !allow_upload || !allow_delete {
                        status_forbid(&mut res);
                    } else if is_miss {
                        status_not_found(&mut res);
                    } else {
                        self.handle_move(path, &req, ip, &mut res).await?
                    }
                }
                "LOCK" => {
                    // Fake lock
                    if is_file {
                        let has_auth = authorization.is_some();
                        self.handle_lock(&req_path, has_auth, &mut res).await?;
                    } else {
                        status_not_found(&mut res);
                    }
                }
                "UNLOCK" => {
                    // Fake unlock
                    if is_miss {
                        status_not_found(&mut res);
                    }
                }
                _ => {
                    *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                }
            },
        }
        Ok(res)
    }

    async fn handle_upload(
        &self,
        path: &Path,
        upload_offset: Option<u64>,
        size: u64,
        req: Request,
        res: &mut Response,
    ) -> Result<()> {
        ensure_path_parent(path).await?;
        let (mut file, status) = match upload_offset {
            None => (fs::File::create(path).await?, StatusCode::CREATED),
            Some(offset) if offset == size => (
                fs::OpenOptions::new().append(true).open(path).await?,
                StatusCode::NO_CONTENT,
            ),
            Some(offset) => {
                let mut file = fs::OpenOptions::new().write(true).open(path).await?;
                file.seek(SeekFrom::Start(offset)).await?;
                (file, StatusCode::NO_CONTENT)
            }
        };
        let stream = IncomingStream::new(req.into_body());

        let body_with_io_error = stream.map_err(io::Error::other);
        let body_reader = StreamReader::new(body_with_io_error);

        pin_mut!(body_reader);

        let ret = io::copy(&mut body_reader, &mut file).await;
        let size = fs::metadata(path)
            .await
            .map(|v| v.len())
            .unwrap_or_default();
        if ret.is_err() {
            if upload_offset.is_none() && size < RESUMABLE_UPLOAD_MIN_SIZE {
                let _ = tokio::fs::remove_file(&path).await;
            }
            ret?;
        }

        *res.status_mut() = status;

        Ok(())
    }

    async fn handle_delete(&self, path: &Path, is_dir: bool, res: &mut Response) -> Result<()> {
        // The permissions describing a path go away with it, so an entry
        // created at the same path later does not silently inherit rules that
        // nobody configured for it.
        let from = path
            .strip_prefix(&self.args.serve_path)
            .map(normalize_path)
            .unwrap_or_default();
        let root = Some(self.args.serve_path.as_path());
        let mut acl = (*self.user_acl_snapshot()).clone();
        let mut whitelist = (*self.whitelist_snapshot()).clone();
        let acl_removed = acl.remove_tree(&from, root).await;
        let ips_removed = whitelist.remove_tree(&from, root).await;

        match is_dir {
            true => fs::remove_dir_all(path).await?,
            false => fs::remove_file(path).await?,
        }

        if (acl_removed > 0 || ips_removed > 0)
            && !self.store_permissions(acl, whitelist, res).await
        {
            return Ok(());
        }

        status_no_content(res);
        Ok(())
    }

    /// Persist both permission stores and publish them to the running server.
    /// On failure the response is set and `false` is returned, leaving the
    /// in-memory stores untouched so they keep matching the disk.
    async fn store_permissions(
        &self,
        acl: UserAcl,
        whitelist: IpWhitelist,
        res: &mut Response,
    ) -> bool {
        if let Err(err) = ip_whitelist_store::save(&self.args.serve_path, &whitelist) {
            error!("Failed to save permissions, {err}");
            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            *res.body_mut() = body_full(format!("Failed to save permissions, {err}"));
            return false;
        }
        if let Err(err) = user_acl::save(&self.args.serve_path, &acl) {
            error!("Failed to save permissions, {err}");
            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            *res.body_mut() = body_full(format!("Failed to save permissions, {err}"));
            return false;
        }
        *self.ip_whitelist.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(whitelist);
        *self.user_acl.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(acl);
        true
    }

    async fn handle_ls_dir(
        &self,
        path: &Path,
        exist: bool,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        ip: Option<IpAddr>,
        res: &mut Response,
    ) -> Result<()> {
        let show_all = self.args.allow_ip_whitelist && access_paths.acl();
        let is_x = access_paths.acl();
        let is_auth_x = is_x && user.is_some();
        let acl_user = user.as_deref().unwrap_or("guest").to_string();
        let mut paths = vec![];
        if !head_only && exist {
            paths = match self
                .list_dir(
                    path,
                    path,
                    access_paths.clone(),
                    ip,
                    show_all,
                    is_x,
                    is_auth_x,
                    &acl_user,
                )
                .await
            {
                Ok(paths) => paths,
                Err(_) => {
                    status_forbid(res);
                    return Ok(());
                }
            }
        };
        self.send_index(
            path,
            paths,
            exist,
            query_params,
            head_only,
            user,
            access_paths,
            res,
        )
    }

    async fn handle_search_dir(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        ip: Option<IpAddr>,
        res: &mut Response,
    ) -> Result<()> {
        let is_x = access_paths.acl();
        let acl_user = user.clone().unwrap_or_else(|| "guest".to_string());
        let mut paths: Vec<PathItem> = vec![];
        let search = query_params
            .get("q")
            .ok_or_else(|| anyhow!("invalid q"))?
            .to_lowercase();
        if search.is_empty() {
            return self
                .handle_ls_dir(
                    path,
                    true,
                    query_params,
                    head_only,
                    user,
                    access_paths,
                    ip,
                    res,
                )
                .await;
        }

        if !head_only {
            let path_buf = path.to_path_buf();
            let hidden = Arc::new(self.args.hidden.to_vec());
            let search = search.clone();

            let search_paths = tokio::spawn(collect_dir_entries(
                access_paths.clone(),
                self.whitelist_snapshot(),
                ip,
                is_x,
                self.running.clone(),
                path_buf,
                hidden,
                self.args.allow_symlink,
                self.args.serve_path.clone(),
                self.user_acl_snapshot(),
                acl_user.clone(),
                move |x| get_file_name(x.path()).to_lowercase().contains(&search),
            ))
            .await?;

            for search_path in search_paths.into_iter() {
                if let Ok(Some(item)) = self.to_pathitem(search_path, path.to_path_buf()).await {
                    paths.push(item);
                }
            }
        }
        self.send_index(
            path,
            paths,
            true,
            query_params,
            head_only,
            user,
            access_paths,
            res,
        )
    }

    async fn handle_zip_dir(
        &self,
        path: &Path,
        head_only: bool,
        access_paths: AccessPaths,
        ip: Option<IpAddr>,
        acl_user: &str,
        res: &mut Response,
    ) -> Result<()> {
        let (mut writer, reader) = tokio::io::duplex(BUF_SIZE);
        let filename = try_get_file_name(path)?;
        set_content_disposition(res, false, &format!("{filename}.zip"))?;
        res.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/zip"));
        if head_only {
            return Ok(());
        }
        let path = path.to_owned();
        let hidden = self.args.hidden.clone();
        let running = self.running.clone();
        let compression = self.args.compress.to_compression();
        let follow_symlinks = self.args.allow_symlink;
        let serve_path = self.args.serve_path.clone();
        let ip_whitelist = self.whitelist_snapshot();
        let user_acl = self.user_acl_snapshot();
        let acl_user = acl_user.to_string();
        let is_x = access_paths.acl();
        tokio::spawn(async move {
            if let Err(e) = zip_dir(
                &mut writer,
                &path,
                access_paths,
                ip_whitelist,
                ip,
                &hidden,
                compression,
                follow_symlinks,
                serve_path,
                user_acl,
                acl_user,
                is_x,
                running,
            )
            .await
            {
                error!("Failed to zip {}, {e}", path.display());
            }
        });
        let reader_stream = ReaderStream::with_capacity(reader, BUF_SIZE);
        let stream_body = StreamBody::new(
            reader_stream
                .map_ok(Frame::data)
                .map_err(|err| anyhow!("{err}")),
        );
        let boxed_body = stream_body.boxed();
        *res.body_mut() = boxed_body;
        Ok(())
    }

    async fn handle_render_index(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        ip: Option<IpAddr>,
        acl_user: &str,
        res: &mut Response,
    ) -> Result<()> {
        let index_path = path.join(INDEX_NAME);
        if fs::metadata(&index_path)
            .await
            .ok()
            .map(|v| v.is_file())
            .unwrap_or_default()
        {
            if !self.entry_ip_allowed(&index_path, ip).await {
                status_forbid(res);
                return Ok(());
            }
            // The index file is served on behalf of the directory, so its own
            // acl entry has to be honored as well.
            if !self.file_acl_allows(&index_path, acl_user).await {
                if self.dir_traversable(path, acl_user).await {
                    // A user that may only walk this directory cannot read its
                    // index page, but has to be able to reach a granted child:
                    // show the filtered listing instead of a dead end.
                    self.handle_ls_dir(
                        path,
                        true,
                        query_params,
                        head_only,
                        user,
                        access_paths,
                        ip,
                        res,
                    )
                    .await?;
                } else {
                    status_forbid(res);
                }
                return Ok(());
            }
            self.handle_send_file(&index_path, headers, head_only, res)
                .await?;
        } else if self.args.render_try_index {
            self.handle_ls_dir(
                path,
                true,
                query_params,
                head_only,
                user,
                access_paths,
                ip,
                res,
            )
            .await?;
        } else {
            self.handle_not_found(query_params, head_only, res).await?;
        }
        Ok(())
    }

    async fn handle_file_json(
        &self,
        path: &Path,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let pathitem = match self.to_pathitem(path, &self.args.serve_path).await? {
            Some(v) => v,
            None => {
                status_not_found(res);
                return Ok(());
            }
        };
        let output = serde_json::to_string_pretty(&pathitem)?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_render_spa(
        &self,
        path: &Path,
        query_params: &HashMap<String, String>,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        ip: Option<IpAddr>,
        acl_user: &str,
        res: &mut Response,
    ) -> Result<()> {
        if path.extension().is_none() {
            let path = self.args.serve_path.join(INDEX_NAME);
            if !self.entry_ip_allowed(&path, ip).await {
                status_forbid(res);
                return Ok(());
            }
            if !self.file_acl_allows(&path, acl_user).await {
                status_forbid(res);
                return Ok(());
            }
            self.handle_send_file(&path, headers, head_only, res)
                .await?;
        } else {
            self.handle_not_found(query_params, head_only, res).await?;
        }
        Ok(())
    }

    async fn handle_not_found(
        &self,
        query_params: &HashMap<String, String>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        if let Some(error_page) = &self.args.error_page {
            if !has_query_flag(query_params, "noscript") {
                self.handle_send_error_page(error_page, head_only, res)
                    .await?;
                *res.status_mut() = StatusCode::NOT_FOUND;
                return Ok(());
            }
        }
        status_not_found(res);
        Ok(())
    }

    async fn handle_send_error_page(
        &self,
        path: &Path,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let html = fs::read_to_string(path).await?;
        let output = self.render_html(&html);
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_no_cache());
        res.headers_mut().insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    fn render_html(&self, html: &str) -> String {
        html.replace(
            "__ASSETS_PREFIX__",
            &format!("{}{}", self.args.uri_prefix, self.assets_prefix),
        )
        .replace("__PATH_PREFIX__", &self.args.uri_prefix)
    }

    async fn handle_internal(
        &self,
        req_path: &str,
        head_only: bool,
        headers: &HeaderMap<HeaderValue>,
        res: &mut Response,
    ) -> Result<bool> {
        // Browsers also probe /favicon.ico directly; serve it without an auth
        // challenge so an unauthenticated page load never prompts.
        if req_path == "favicon.ico" {
            res.headers_mut()
                .insert("content-type", HeaderValue::from_static("image/x-icon"));
            res.headers_mut()
                .typed_insert(ContentLength(FAVICON_ICO.len() as u64));
            if !head_only {
                *res.body_mut() = body_full(FAVICON_ICO);
            }
            return Ok(true);
        }
        if let Some(name) = req_path.strip_prefix(&self.assets_prefix) {
            match self.args.assets.as_ref() {
                Some(assets_path) => {
                    let path = match join_within(assets_path, name) {
                        Some(path) => path,
                        None => {
                            status_not_found(res);
                            return Ok(true);
                        }
                    };
                    if path.exists() {
                        self.handle_send_file(&path, headers, head_only, res)
                            .await?;
                    } else {
                        status_not_found(res);
                        return Ok(true);
                    }
                }
                None => match name {
                    "index.js" => {
                        res.headers_mut().insert(
                            "content-type",
                            HeaderValue::from_static("application/javascript; charset=UTF-8"),
                        );
                        res.headers_mut()
                            .typed_insert(ContentLength(INDEX_JS.len() as u64));
                        if !head_only {
                            *res.body_mut() = body_full(INDEX_JS);
                        }
                    }
                    "index.css" => {
                        res.headers_mut().insert(
                            "content-type",
                            HeaderValue::from_static("text/css; charset=UTF-8"),
                        );
                        res.headers_mut()
                            .typed_insert(ContentLength(INDEX_CSS.len() as u64));
                        if !head_only {
                            *res.body_mut() = body_full(INDEX_CSS);
                        }
                    }
                    "favicon.ico" => {
                        res.headers_mut()
                            .insert("content-type", HeaderValue::from_static("image/x-icon"));
                        res.headers_mut()
                            .typed_insert(ContentLength(FAVICON_ICO.len() as u64));
                        if !head_only {
                            *res.body_mut() = body_full(FAVICON_ICO);
                        }
                    }
                    _ => {
                        status_not_found(res);
                    }
                },
            }
            res.headers_mut().insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            );
            res.headers_mut().insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
            Ok(true)
        } else if req_path == HEALTH_CHECK_PATH {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
            let body = r#"{"status":"OK"}"#;
            res.headers_mut()
                .typed_insert(ContentLength(body.len() as u64));
            if !head_only {
                *res.body_mut() = body_full(body);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn handle_send_file(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let (file, meta) = tokio::join!(fs::File::open(path), fs::metadata(path),);
        let (mut file, meta) = (file?, meta?);
        let size = meta.len();
        let mut use_range = true;
        if let Some((etag, last_modified)) = extract_cache_headers(&meta) {
            if let Some(if_unmodified_since) = headers.typed_get::<IfUnmodifiedSince>() {
                if !if_unmodified_since.precondition_passes(last_modified.into()) {
                    *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                    return Ok(());
                }
            }
            if let Some(if_match) = headers.typed_get::<IfMatch>() {
                if !if_match.precondition_passes(&etag) {
                    *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                    return Ok(());
                }
            }
            if let Some(if_modified_since) = headers.typed_get::<IfModifiedSince>() {
                if !if_modified_since.is_modified(last_modified.into()) {
                    *res.status_mut() = StatusCode::NOT_MODIFIED;
                    return Ok(());
                }
            }
            if let Some(if_none_match) = headers.typed_get::<IfNoneMatch>() {
                if !if_none_match.precondition_passes(&etag) {
                    *res.status_mut() = StatusCode::NOT_MODIFIED;
                    return Ok(());
                }
            }

            res.headers_mut()
                .typed_insert(CacheControl::new().with_no_cache());
            res.headers_mut().typed_insert(last_modified);
            res.headers_mut().typed_insert(etag.clone());

            if headers.typed_get::<Range>().is_some() {
                use_range = headers
                    .typed_get::<IfRange>()
                    .map(|if_range| !if_range.is_modified(Some(&etag), Some(&last_modified)))
                    // Always be fresh if there is no validators
                    .unwrap_or(true);
            } else {
                use_range = false;
            }
        }

        let ranges = if use_range {
            headers.get(RANGE).map(|range| {
                range
                    .to_str()
                    .ok()
                    .and_then(|range| parse_range(range, size))
            })
        } else {
            None
        };

        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_str(&get_content_type(path).await?)?,
        );

        let filename = try_get_file_name(path)?;
        set_content_disposition(res, true, filename)?;

        res.headers_mut().typed_insert(AcceptRanges::bytes());

        if let Some(ranges) = ranges {
            if let Some(ranges) = ranges {
                if ranges.len() == 1 {
                    let (start, end) = ranges[0];
                    file.seek(SeekFrom::Start(start)).await?;
                    let range_size = end - start + 1;
                    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let content_range = format!("bytes {start}-{end}/{size}");
                    res.headers_mut()
                        .insert(CONTENT_RANGE, content_range.parse()?);
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, format!("{range_size}").parse()?);
                    if head_only {
                        return Ok(());
                    }

                    let stream_body = StreamBody::new(
                        LengthLimitedStream::new(file, range_size as usize)
                            .map_ok(Frame::data)
                            .map_err(|err| anyhow!("{err}")),
                    );
                    let boxed_body = stream_body.boxed();
                    *res.body_mut() = boxed_body;
                } else {
                    *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                    let boundary = Uuid::new_v4();
                    let content_type = get_content_type(path).await?;
                    let footer = format!("--{boundary}--\r\n");

                    // Compute the exact length up front, so a HEAD request (and
                    // the Content-Length header) never has to read the file.
                    let mut content_length = footer.len();
                    for (start, end) in &ranges {
                        let range_size = end - start + 1;
                        let part_header = format!(
                            "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {start}-{end}/{size}\r\n\r\n",
                        );
                        content_length += part_header.len() + range_size as usize + 2;
                    }

                    res.headers_mut().insert(
                        CONTENT_TYPE,
                        format!("multipart/byteranges; boundary={boundary}").parse()?,
                    );
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, format!("{content_length}").parse()?);
                    if head_only {
                        return Ok(());
                    }

                    // Stream the parts instead of materializing the whole body
                    // in memory.
                    let stream = async_stream::try_stream! {
                        let mut buffer = vec![0; BUF_SIZE];
                        for (start, end) in ranges {
                            file.seek(SeekFrom::Start(start)).await?;
                            let part_header = format!(
                                "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {start}-{end}/{size}\r\n\r\n",
                            );
                            yield Bytes::from(part_header);
                            let mut remaining = end - start + 1;
                            while remaining > 0 {
                                let want = remaining.min(BUF_SIZE as u64) as usize;
                                file.read_exact(&mut buffer[..want]).await?;
                                yield Bytes::copy_from_slice(&buffer[..want]);
                                remaining -= want as u64;
                            }
                            yield Bytes::from_static(b"\r\n");
                        }
                        yield Bytes::from(footer);
                    };
                    let stream_body = StreamBody::new(
                        stream
                            .map_ok(Frame::data)
                            .map_err(|err: io::Error| anyhow::Error::new(err)),
                    );
                    *res.body_mut() = stream_body.boxed();
                }
            } else {
                *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                res.headers_mut()
                    .insert(CONTENT_RANGE, format!("bytes */{size}").parse()?);
            }
        } else {
            res.headers_mut()
                .insert(CONTENT_LENGTH, format!("{size}").parse()?);
            if head_only {
                return Ok(());
            }

            let reader_stream = ReaderStream::with_capacity(file, BUF_SIZE);
            let stream_body = StreamBody::new(
                reader_stream
                    .map_ok(Frame::data)
                    .map_err(|err| anyhow!("{err}")),
            );
            let boxed_body = stream_body.boxed();
            *res.body_mut() = boxed_body;
        }
        Ok(())
    }

    async fn handle_edit_file(
        &self,
        path: &Path,
        kind: DataKind,
        head_only: bool,
        user: Option<String>,
        res: &mut Response,
    ) -> Result<()> {
        let (file, meta) = tokio::join!(fs::File::open(path), fs::metadata(path),);
        let (file, meta) = (file?, meta?);
        let href = format!(
            "/{}",
            normalize_path(path.strip_prefix(&self.args.serve_path)?)
        );
        let mut buffer: Vec<u8> = vec![];
        file.take(1024).read_to_end(&mut buffer).await?;
        let editable =
            meta.len() <= EDITABLE_TEXT_MAX_SIZE && content_inspector::inspect(&buffer).is_text();
        let data = EditData {
            href,
            kind,
            uri_prefix: self.args.uri_prefix.clone(),
            allow_upload: self.args.allow_upload,
            allow_delete: self.args.allow_delete,
            auth: self.args.auth.has_users(),
            auth_type: self.args.auth_type.as_str().to_string(),
            user,
            editable,
        };
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
        let index_data = STANDARD.encode(serde_json::to_string(&data)?);
        let output = self
            .render_html(&self.html)
            .replace("__INDEX_DATA__", &index_data);
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_no_cache());
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    async fn handle_hash_file(
        &self,
        path: &Path,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let output = sha256_file(path).await?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        if !head_only {
            *res.body_mut() = body_full(output);
        }
        Ok(())
    }

    async fn handle_tokengen(
        &self,
        relative_path: &str,
        user: Option<String>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<()> {
        let user = match user {
            Some(user) => user,
            None => {
                self.auth_reject(res)?;
                return Ok(());
            }
        };
        let output = self.args.auth.generate_token(relative_path, &user)?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_PLAIN_UTF_8));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        if !head_only {
            *res.body_mut() = body_full(output);
        }
        Ok(())
    }

    async fn handle_propfind_dir(
        &self,
        path: &Path,
        headers: &HeaderMap<HeaderValue>,
        access_paths: AccessPaths,
        ip: Option<IpAddr>,
        acl_user: &str,
        is_auth_x: bool,
        res: &mut Response,
    ) -> Result<()> {
        let show_all = self.args.allow_ip_whitelist && access_paths.acl();
        let is_x = access_paths.acl();
        let depth: u32 = match headers.get("depth") {
            Some(v) => match v.to_str().ok().and_then(|v| v.parse().ok()) {
                Some(0) => 0,
                Some(1) => 1,
                _ => {
                    status_bad_request(res, "Invalid depth: only 0 and 1 are allowed.");
                    return Ok(());
                }
            },
            None => 1,
        };
        let mut paths = match self.to_pathitem(path, &self.args.serve_path).await? {
            Some(mut v) => {
                if show_all {
                    v.whitelist = self.whitelist_label(path).await;
                }
                vec![v]
            }
            None => vec![],
        };
        if depth == 1 {
            match self
                .list_dir(
                    path,
                    &self.args.serve_path,
                    access_paths,
                    ip,
                    show_all,
                    is_x,
                    is_auth_x,
                    acl_user,
                )
                .await
            {
                Ok(child) => paths.extend(child),
                Err(_) => {
                    status_forbid(res);
                    return Ok(());
                }
            }
        }
        let output = paths
            .iter()
            .map(|v| v.to_dav_xml(self.args.uri_prefix.as_str()))
            .fold(String::new(), |mut acc, v| {
                acc.push_str(&v);
                acc
            });
        res_multistatus(res, &output);
        Ok(())
    }

    async fn handle_propfind_file(&self, path: &Path, res: &mut Response) -> Result<()> {
        if let Some(pathitem) = self.to_pathitem(path, &self.args.serve_path).await? {
            res_multistatus(res, &pathitem.to_dav_xml(self.args.uri_prefix.as_str()));
        } else {
            status_not_found(res);
        }
        Ok(())
    }

    async fn handle_mkcol(&self, path: &Path, res: &mut Response) -> Result<()> {
        fs::create_dir_all(path).await?;
        *res.status_mut() = StatusCode::CREATED;
        Ok(())
    }

    async fn handle_copy(
        &self,
        path: &Path,
        req: &Request,
        ip: Option<IpAddr>,
        res: &mut Response,
    ) -> Result<()> {
        let dest = match self.extract_dest(req, ip, res).await {
            Some(dest) => dest,
            None => {
                return Ok(());
            }
        };

        let meta = fs::symlink_metadata(path).await?;
        if meta.is_dir() {
            status_forbid(res);
            return Ok(());
        }

        if self.guard_root_contained(&dest).await {
            status_bad_request(res, "Invalid Destination");
            return Ok(());
        }

        ensure_path_parent(&dest).await?;

        let overwrite = req
            .headers()
            .get("overwrite")
            .map(|v| v.as_bytes() != b"F")
            .unwrap_or(true);
        if fs::symlink_metadata(&dest).await.is_ok() {
            if !overwrite {
                *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                return Ok(());
            }
            if !self.args.allow_delete {
                status_forbid(res);
                return Ok(());
            }
        }

        fs::copy(path, &dest).await?;

        status_no_content(res);
        Ok(())
    }

    async fn handle_move(
        &self,
        path: &Path,
        req: &Request,
        ip: Option<IpAddr>,
        res: &mut Response,
    ) -> Result<()> {
        let dest = match self.extract_dest(req, ip, res).await {
            Some(dest) => dest,
            None => {
                return Ok(());
            }
        };

        if self.guard_root_contained(&dest).await {
            status_bad_request(res, "Invalid Destination");
            return Ok(());
        }

        // Permissions are stored per path, so they have to move with the
        // content: otherwise a deny inside the moved directory would stay
        // behind and the content would silently inherit the destination's
        // rule instead (exposing a path the user was denied).
        let from = path
            .strip_prefix(&self.args.serve_path)
            .map(normalize_path)
            .unwrap_or_default();
        let to = dest
            .strip_prefix(&self.args.serve_path)
            .map(normalize_path)
            .unwrap_or_default();
        let root = Some(self.args.serve_path.as_path());
        let mut acl = (*self.user_acl_snapshot()).clone();
        let mut whitelist = (*self.whitelist_snapshot()).clone();
        // Moving a path onto itself leaves everything where it is.
        let (acl_moved, ips_moved) = if from == to {
            (0, 0)
        } else {
            let dest_taken = acl.has_rules(&to, root).await || whitelist.has_rules(&to, root).await;
            let acl_moved = acl.rename(&from, &to, root).await;
            let ips_moved = whitelist.rename(&from, &to, root).await;
            if (acl_moved > 0 || ips_moved > 0) && dest_taken {
                *res.status_mut() = StatusCode::CONFLICT;
                *res.body_mut() = body_full(
                    "Destination already has permissions configured, remove them or move the entry elsewhere",
                );
                return Ok(());
            }
            (acl_moved, ips_moved)
        };

        ensure_path_parent(&dest).await?;

        // The rules live in the local copies until the filesystem move
        // succeeded, so a failed rename changes nothing.
        fs::rename(path, &dest).await?;

        if (acl_moved > 0 || ips_moved > 0) && !self.store_permissions(acl, whitelist, res).await {
            return Ok(());
        }

        status_no_content(res);
        Ok(())
    }

    async fn handle_lock(&self, req_path: &str, auth: bool, res: &mut Response) -> Result<()> {
        let token = if auth {
            format!("opaquelocktoken:{}", Uuid::new_v4())
        } else {
            Utc::now().timestamp().to_string()
        };

        res.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
        res.headers_mut()
            .insert("lock-token", format!("<{token}>").parse()?);

        *res.body_mut() = body_full(format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>
<D:locktoken><D:href>{token}</D:href></D:locktoken>
<D:lockroot><D:href>{req_path}</D:href></D:lockroot>
</D:activelock></D:lockdiscovery></D:prop>"#
        ));
        Ok(())
    }

    async fn handle_proppatch(&self, req_path: &str, res: &mut Response) -> Result<()> {
        let output = format!(
            r#"<D:response>
<D:href>{req_path}</D:href>
<D:propstat>
<D:prop>
</D:prop>
<D:status>HTTP/1.1 403 Forbidden</D:status>
</D:propstat>
</D:response>"#
        );
        res_multistatus(res, &output);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn send_index(
        &self,
        path: &Path,
        mut paths: Vec<PathItem>,
        exist: bool,
        query_params: &HashMap<String, String>,
        head_only: bool,
        user: Option<String>,
        access_paths: AccessPaths,
        res: &mut Response,
    ) -> Result<()> {
        if let Some(sort) = query_params.get("sort") {
            if sort == "name" {
                paths.sort_by(|v1, v2| v1.sort_by_name(v2))
            } else if sort == "mtime" {
                paths.sort_by(|v1, v2| v1.sort_by_mtime(v2))
            } else if sort == "size" {
                paths.sort_by(|v1, v2| v1.sort_by_size(v2))
            }
            if query_params
                .get("order")
                .map(|v| v == "desc")
                .unwrap_or_default()
            {
                paths.reverse();
                // keep directories grouped on top, in reverse order within the group
                paths.sort_by_key(|v| !v.path_type.is_dir());
            }
        } else {
            paths.sort_by(|v1, v2| v1.sort_by_name(v2))
        }
        if has_query_flag(query_params, "simple") {
            let output = paths
                .into_iter()
                .map(|v| {
                    let displayname = escape_str_pcdata(&v.name);
                    if v.is_dir() {
                        format!("{}/\n", displayname)
                    } else {
                        format!("{}\n", displayname)
                    }
                })
                .collect::<Vec<String>>()
                .join("");
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
            res.headers_mut()
                .typed_insert(ContentLength(output.len() as u64));
            *res.body_mut() = body_full(output);
            if head_only {
                return Ok(());
            }
            return Ok(());
        }
        let href = format!(
            "/{}",
            normalize_path(path.strip_prefix(&self.args.serve_path)?)
        );
        let readwrite = access_paths.perm().readwrite();
        let data = IndexData {
            kind: DataKind::Index,
            href,
            uri_prefix: self.args.uri_prefix.clone(),
            allow_upload: self.args.allow_upload && readwrite,
            allow_delete: self.args.allow_delete && readwrite,
            allow_search: self.args.allow_search,
            allow_archive: self.args.allow_archive,
            allow_ip_whitelist: self.args.allow_ip_whitelist && access_paths.acl(),
            has_acl: !self.user_acl_snapshot().is_empty(),
            dir_exists: exist,
            auth: self.args.auth.has_users(),
            auth_type: self.args.auth_type.as_str().to_string(),
            user,
            paths,
        };
        let output = if has_query_flag(query_params, "json") {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
            serde_json::to_string_pretty(&data)?
        } else if has_query_flag(query_params, "noscript") {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
            generate_noscript_html(&data)?
        } else {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));

            let index_data = STANDARD.encode(serde_json::to_string(&data)?);
            self.render_html(&self.html)
                .replace("__INDEX_DATA__", &index_data)
        };
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_no_cache());
        res.headers_mut().insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        if head_only {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    fn auth_reject(&self, res: &mut Response) -> Result<()> {
        set_webdav_headers(res);

        www_authenticate(res, &self.args)?;
        *res.status_mut() = StatusCode::UNAUTHORIZED;
        Ok(())
    }

    /// Resolve the authenticated identity for OIDC mode.
    async fn guard_oidc(
        &self,
        oidc: &Oidc,
        headers: &HeaderMap<HeaderValue>,
        path: &str,
        method: &Method,
    ) -> (Option<String>, Option<AccessPaths>, bool) {
        if let Some(session_id) = Oidc::session_id(headers) {
            if let Some(username) = oidc.session_user(&session_id) {
                if let Some(access_paths) = self.args.auth.paths_for_user(&username) {
                    let guarded = access_paths
                        .guard(path, method, Some(&self.args.serve_path))
                        .await;
                    return (Some(username), guarded, false);
                }
                return (Some(username), None, false);
            }
        }
        if let Some(access_paths) = self.args.auth.guest_paths() {
            let guarded = access_paths
                .guard(path, method, Some(&self.args.serve_path))
                .await;
            return (None, guarded, false);
        }
        (None, None, false)
    }

    /// Handle the OIDC login, callback and logout endpoints.
    async fn handle_oidc(&self, oidc: &Oidc, action: &str, req: &Request) -> Result<Response> {
        let mut res = Response::default();
        if req.method() != Method::GET && req.method() != Method::HEAD {
            *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            return Ok(res);
        }
        let query_params: HashMap<String, String> =
            form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        match action {
            "login" => {
                let next = query_params.get("next").map(String::as_str).unwrap_or("/");
                match oidc.begin_login(next).await {
                    Ok(url) => redirect(&mut res, &url),
                    Err(err) => {
                        error!("OIDC login request failed, {err}");
                        *res.status_mut() = StatusCode::BAD_GATEWAY;
                        *res.body_mut() = body_full("OIDC login is unavailable");
                    }
                }
            }
            "callback" => {
                let (code, state) = match (
                    query_params.get("code").cloned(),
                    query_params.get("state").cloned(),
                ) {
                    (Some(code), Some(state)) => (code, state),
                    _ => {
                        status_bad_request(&mut res, "Missing OIDC code or state");
                        return Ok(res);
                    }
                };
                match oidc.complete_login(code, state).await {
                    Ok((username, next, id_token)) => {
                        let session = oidc.create_session(username, id_token);
                        res.headers_mut()
                            .insert("set-cookie", self.session_cookie(&session));
                        redirect(&mut res, &next);
                    }
                    Err(err) => {
                        error!("OIDC callback failed, {err}");
                        *res.status_mut() = StatusCode::UNAUTHORIZED;
                        *res.body_mut() = body_full("OIDC authentication failed");
                    }
                }
            }
            "logout" => {
                let session_id = Oidc::session_id(req.headers());
                let id_token = session_id
                    .as_deref()
                    .and_then(|session_id| oidc.session_id_token(session_id));
                if let Some(session_id) = &session_id {
                    oidc.remove_session(session_id);
                }
                res.headers_mut()
                    .insert("set-cookie", self.clear_session_cookie());
                match oidc.end_session_url(id_token.as_deref()).await {
                    Ok(Some(url)) => redirect(&mut res, &url),
                    Ok(None) => redirect(&mut res, &self.args.uri_prefix),
                    Err(err) => {
                        error!("OIDC end-session failed, {err}");
                        redirect(&mut res, &self.args.uri_prefix);
                    }
                }
            }
            _ => status_not_found(&mut res),
        }
        Ok(res)
    }

    /// Cookie scope; the prefix itself is included so a request to the
    /// prefix without a trailing slash still sends the cookie.
    fn cookie_path(&self) -> &str {
        let path = self.args.uri_prefix.trim_end_matches('/');
        if path.is_empty() {
            "/"
        } else {
            path
        }
    }

    fn session_cookie(&self, session: &str) -> HeaderValue {
        let mut value = format!(
            "{SESSION_COOKIE}={session}; Path={}; HttpOnly; SameSite=Lax; Max-Age={}",
            self.cookie_path(),
            self.oidc_session_ttl_secs()
        );
        if self.args.tls_cert.is_some() {
            value.push_str("; Secure");
        }
        HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    fn clear_session_cookie(&self) -> HeaderValue {
        let mut value = format!(
            "{SESSION_COOKIE}=; Path={}; HttpOnly; SameSite=Lax; Max-Age=0",
            self.cookie_path()
        );
        if self.args.tls_cert.is_some() {
            value.push_str("; Secure");
        }
        HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    fn oidc_session_ttl_secs(&self) -> u64 {
        self.oidc
            .as_ref()
            .map(|oidc| oidc.session_ttl().as_secs())
            .unwrap_or(0)
    }

    async fn guard_root_contained(&self, path: &Path) -> bool {
        if self.args.allow_symlink {
            return false;
        }
        let mut check_path = path.to_path_buf();
        while fs::symlink_metadata(&check_path).await.is_err() {
            match check_path.parent() {
                Some(parent) => check_path = parent.to_path_buf(),
                None => return true,
            }
        }
        !self.is_root_contained(check_path.as_path()).await
    }

    async fn is_root_contained(&self, path: &Path) -> bool {
        fs::canonicalize(path)
            .await
            .ok()
            .map(|v| v.starts_with(&self.args.serve_path))
            .unwrap_or_default()
    }

    /// Whether the path resolves into the metadata directory, following
    /// symlinks even when they are otherwise allowed.
    async fn guard_metadata_contained(&self, path: &Path) -> bool {
        if self.args.path_is_file {
            return false;
        }
        let metadata_dir = ip_whitelist_store::metadata_dir(&self.args.serve_path);
        let mut check_path = path.to_path_buf();
        while fs::symlink_metadata(&check_path).await.is_err() {
            match check_path.parent() {
                Some(parent) => check_path = parent.to_path_buf(),
                None => return false,
            }
        }
        fs::canonicalize(&check_path)
            .await
            .map(|v| v.starts_with(&metadata_dir))
            .unwrap_or_default()
    }

    async fn extract_dest(
        &self,
        req: &Request,
        ip: Option<IpAddr>,
        res: &mut Response,
    ) -> Option<PathBuf> {
        let headers = req.headers();
        let dest_path = match self
            .extract_destination_header(headers)
            .and_then(|dest| self.resolve_path(&dest))
        {
            Some(dest) => dest,
            None => {
                status_bad_request(res, "Invalid Destination");
                return None;
            }
        };

        // The destination must be authorized exactly like the source: through
        // the OIDC session when that adapter is active, and with the per-path
        // ACL applied on top of the --auth tree. Using the builtin guard here
        // made every MOVE/COPY fail under --auth-type oidc.
        if !self.dest_writable(req, &dest_path).await {
            status_forbid(res);
            return None;
        }

        if !self.ip_allowed(&dest_path, ip).await {
            status_forbid(res);
            return None;
        }

        let dest = match self.join_path(&dest_path) {
            Some(dest) => dest,
            None => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                return None;
            }
        };

        Some(dest)
    }

    fn extract_destination_header(&self, headers: &HeaderMap<HeaderValue>) -> Option<String> {
        let dest = headers.get("Destination")?.to_str().ok()?;
        let uri: Uri = dest.parse().ok()?;
        Some(uri.path().to_string())
    }

    fn resolve_path(&self, path: &str) -> Option<String> {
        let path = decode_uri(path)?;
        let path = path.trim_matches('/');
        let mut parts = vec![];
        for comp in Path::new(path).components() {
            if let Component::Normal(v) = comp {
                let v = v.to_string_lossy();
                if cfg!(windows) {
                    let chars: Vec<char> = v.chars().collect();
                    if chars.len() == 2 && chars[1] == ':' && chars[0].is_ascii_alphabetic() {
                        return None;
                    }
                }
                parts.push(v);
            } else {
                return None;
            }
        }
        let new_path = parts.join("/");
        let path_prefix = self.args.path_prefix.as_str();
        if path_prefix.is_empty() {
            return Some(new_path);
        }
        if new_path == path_prefix {
            return Some(String::new());
        }
        new_path
            .strip_prefix(&format!("{path_prefix}/"))
            .map(|v| v.trim_matches('/').to_string())
    }

    fn join_path(&self, path: &str) -> Option<PathBuf> {
        if path.is_empty() {
            return Some(self.args.serve_path.clone());
        }
        let path = if cfg!(windows) {
            path.replace('/', "\\")
        } else {
            path.to_string()
        };
        join_within(&self.args.serve_path, &path)
    }

    /// Snapshot the current whitelist so a request sees one consistent
    /// configuration even if it is updated while the request is in flight.
    fn whitelist_snapshot(&self) -> Arc<IpWhitelist> {
        self.ip_whitelist
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn user_acl_snapshot(&self) -> Arc<UserAcl> {
        self.user_acl
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// A content hash of both acl stores, used for optimistic concurrency.
    fn acl_version(&self) -> String {
        let acl = self.user_acl_snapshot();
        let ips = self.whitelist_snapshot();
        let data = serde_json::json!({
            "acl": acl.rules(),
            "ips": ips.rules(),
        });
        let bytes = serde_json::to_vec(&data).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hex::encode(hasher.finalize())
    }

    /// Whether the per-path acl allows reading `path`. Used where a file is
    /// served on behalf of another path (render-index / render-spa), where the
    /// main guard only checked the requested directory.
    async fn file_acl_allows(&self, path: &Path, acl_user: &str) -> bool {
        let rel_path = path
            .strip_prefix(&self.args.serve_path)
            .map(normalize_path)
            .unwrap_or_default();
        // `None` means no rule covers the file, so `--auth` (already enforced)
        // decides; only an explicit deny or a traversal-only ancestor refuses.
        !matches!(
            self.acl_perm(&rel_path, acl_user).await,
            Some(AclPerm::Deny | AclPerm::Traverse)
        )
    }

    /// Whether a rule below `path` grants `user` something.
    async fn has_grant_below(&self, path: &str, user: &str) -> bool {
        self.user_acl_snapshot()
            .grants_below(path, user, Some(&self.args.serve_path))
            .await
    }

    /// Whether the user may only walk `path`, i.e. the acl grants something
    /// below the directory but not the directory itself. This also covers a
    /// directory no rule mentions at all: --auth may refuse it while a rule
    /// below still has to be reachable.
    async fn dir_traversable(&self, path: &Path, acl_user: &str) -> bool {
        let rel_path = path
            .strip_prefix(&self.args.serve_path)
            .map(normalize_path)
            .unwrap_or_default();
        match self.acl_perm(&rel_path, acl_user).await {
            Some(AclPerm::Traverse) => true,
            Some(_) => false,
            None => self.has_grant_below(&rel_path, acl_user).await,
        }
    }

    /// The user acl decision for a path relative to the serve root.
    async fn acl_perm(&self, path: &str, user: &str) -> Option<AclPerm> {
        let perm = self
            .user_acl_snapshot()
            .perm(path, user, Some(&self.args.serve_path))
            .await;
        // A traversal is the permission to walk *through* a directory, so it
        // must never apply to a file: a rule below a file path is a
        // misconfiguration, not a read grant.
        if perm == Some(AclPerm::Traverse)
            && !fs::metadata(self.args.serve_path.join(path))
                .await
                .map(|v| v.is_dir())
                .unwrap_or_default()
        {
            return Some(AclPerm::Deny);
        }
        perm
    }

    /// Whether the user may write the parent directory of a path. This backs
    /// the per-operation rule for DELETE and MOVE (parent w + target r).
    async fn parent_writable(
        &self,
        path: &str,
        acl_user: &str,
        auth_method: &Method,
        authorization: Option<&HeaderValue>,
        headers: &HeaderMap<HeaderValue>,
    ) -> bool {
        let parent = path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("");
        let (_, parent_paths, _) = if let Some(oidc) = &self.oidc {
            self.guard_oidc(oidc, headers, parent, &Method::GET).await
        } else {
            self.args
                .auth
                .guard_with_auth_method(
                    parent,
                    &Method::GET,
                    auth_method,
                    authorization,
                    None,
                    false,
                    &self.args.serve_path,
                )
                .await
        };
        if parent_paths.as_ref().is_some_and(|v| v.acl()) {
            return true;
        }
        match self.acl_perm(parent, acl_user).await {
            Some(AclPerm::Write) => true,
            Some(_) => false,
            None => parent_paths.as_ref().is_some_and(|v| v.perm().readwrite()),
        }
    }

    /// Whether the identity behind the request may write `path`, used for the
    /// destination of MOVE/COPY.
    async fn dest_writable(&self, req: &Request, path: &str) -> bool {
        let headers = req.headers();
        let (user, access_paths, _) = if let Some(oidc) = &self.oidc {
            self.guard_oidc(oidc, headers, path, req.method()).await
        } else {
            self.args
                .auth
                .guard(
                    path,
                    req.method(),
                    headers.get(AUTHORIZATION),
                    None,
                    false,
                    &self.args.serve_path,
                )
                .await
        };
        // x users may write anywhere they can reach.
        if access_paths.as_ref().is_some_and(|ap| ap.acl()) {
            return true;
        }
        match self
            .acl_perm(path, user.as_deref().unwrap_or("guest"))
            .await
        {
            Some(AclPerm::Deny | AclPerm::Traverse) => false,
            Some(AclPerm::Read) => is_readonly_method(req.method()),
            Some(AclPerm::Write) => true,
            None => access_paths.is_some(),
        }
    }

    /// Whether the client address may access a path relative to the serve root.
    async fn ip_allowed(&self, path: &str, ip: Option<IpAddr>) -> bool {
        self.whitelist_snapshot()
            .allows(path, ip, Some(&self.args.serve_path))
            .await
    }

    /// Whether the client address may access an entry by its on-disk path.
    async fn entry_ip_allowed(&self, path: &Path, ip: Option<IpAddr>) -> bool {
        let rel_path = path
            .strip_prefix(&self.args.serve_path)
            .map(normalize_path)
            .unwrap_or_default();
        self.ip_allowed(&rel_path, ip).await
    }

    /// The effective whitelist label for a path, as shown to managers.
    async fn whitelist_label(&self, path: &Path) -> String {
        let rel_path = path
            .strip_prefix(&self.args.serve_path)
            .map(normalize_path)
            .unwrap_or_default();
        let whitelist = self.whitelist_snapshot();
        match whitelist.find(&rel_path, Some(&self.args.serve_path)).await {
            Some(ips) => format_ip_whitelist(ips),
            None => String::new(),
        }
    }

    /// Whether a path resolves into the metadata directory.
    async fn is_metadata_contained(&self, path: &Path) -> bool {
        if self.args.path_is_file {
            return false;
        }
        fs::canonicalize(path)
            .await
            .map(|v| v.starts_with(ip_whitelist_store::metadata_dir(&self.args.serve_path)))
            .unwrap_or_default()
    }

    /// Read, replace or clear the persisted per-path ip whitelist.
    async fn handle_ip_whitelist(&self, req: Request, method: Method) -> Result<Response> {
        let mut res = Response::default();

        if self.args.path_is_file || !self.args.allow_ip_whitelist {
            status_forbid(&mut res);
            return Ok(res);
        }

        let (user, access_paths, _) = if let Some(oidc) = &self.oidc {
            self.guard_oidc(oidc, req.headers(), "/", &Method::GET)
                .await
        } else {
            self.args
                .auth
                .guard_with_auth_method(
                    "/",
                    &Method::GET,
                    &method,
                    req.headers().get(AUTHORIZATION),
                    None,
                    false,
                    &self.args.serve_path,
                )
                .await
        };
        let access_paths = match access_paths {
            Some(v) => v,
            None => {
                self.auth_reject(&mut res)?;
                return Ok(res);
            }
        };
        if !access_paths.acl() {
            // A guest there is no x: challenge for a real user instead of
            // returning 403, which would stop the browser from prompting.
            if user.is_none() && self.args.auth.has_users() {
                self.auth_reject(&mut res)?;
            } else {
                status_forbid(&mut res);
            }
            return Ok(res);
        }

        match method {
            Method::GET | Method::HEAD => {
                let whitelist = self.whitelist_snapshot();
                let store = ip_whitelist_store::StoreFile::from_whitelist(&whitelist);
                let mut data = serde_json::json!({
                    "version": store.version,
                    "rules": store.rules,
                });
                // When a path is given, also report the whitelist that
                // currently applies to it: null means unrestricted, an empty
                // array means blocked, otherwise the effective members.
                let query_params: HashMap<String, String> =
                    form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                if let Some(path) = query_params.get("path") {
                    let effective = whitelist
                        .find(path, Some(&self.args.serve_path))
                        .await
                        .map(|ips| ips.iter().map(|v| v.to_string()).collect::<Vec<_>>());
                    data["path"] = serde_json::json!(path);
                    data["effective"] = serde_json::json!(effective);
                }
                let body = serde_json::to_string_pretty(&data)?;
                res.headers_mut()
                    .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
                res.headers_mut()
                    .typed_insert(ContentLength(body.len() as u64));
                if method == Method::GET {
                    *res.body_mut() = body_full(body);
                }
            }
            Method::PUT | Method::POST => {
                let bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map_err(|err| anyhow!("Failed to read request body, {err}"))?
                    .to_bytes();
                let store: ip_whitelist_store::StoreFile = match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(err) => {
                        status_bad_request(&mut res, &format!("Invalid JSON, {err}"));
                        return Ok(res);
                    }
                };
                let new_whitelist = match store.to_whitelist() {
                    Ok(v) => v,
                    Err(err) => {
                        status_bad_request(&mut res, &err.to_string());
                        return Ok(res);
                    }
                };
                if let Err(err) = ip_whitelist_store::save(&self.args.serve_path, &new_whitelist) {
                    error!("Failed to save ip-whitelist, {err}");
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    *res.body_mut() = body_full(format!("Failed to save ip-whitelist, {err}"));
                    return Ok(res);
                }
                *self.ip_whitelist.write().unwrap_or_else(|e| e.into_inner()) =
                    Arc::new(new_whitelist);
                *res.status_mut() = StatusCode::NO_CONTENT;
            }
            Method::DELETE => {
                let empty = IpWhitelist::default();
                if let Err(err) = ip_whitelist_store::save(&self.args.serve_path, &empty) {
                    error!("Failed to save ip-whitelist, {err}");
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    *res.body_mut() = body_full(format!("Failed to save ip-whitelist, {err}"));
                    return Ok(res);
                }
                *self.ip_whitelist.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(empty);
                *res.status_mut() = StatusCode::NO_CONTENT;
            }
            _ => {
                *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            }
        }

        Ok(res)
    }

    /// Combined read/write/deny-read acl for one path, editable from the WebUI.
    async fn handle_acl(&self, req: Request, method: Method) -> Result<Response> {
        let mut res = Response::default();

        if self.args.path_is_file || !self.args.allow_ip_whitelist {
            status_forbid(&mut res);
            return Ok(res);
        }

        let query_params: HashMap<String, String> =
            form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        let target = query_params
            .get("path")
            .cloned()
            .unwrap_or_else(|| "/".to_string());

        let (user, access_paths, _) = if let Some(oidc) = &self.oidc {
            self.guard_oidc(oidc, req.headers(), &target, &Method::GET)
                .await
        } else {
            self.args
                .auth
                .guard_with_auth_method(
                    &target,
                    &Method::GET,
                    &method,
                    req.headers().get(AUTHORIZATION),
                    None,
                    false,
                    &self.args.serve_path,
                )
                .await
        };
        let access_paths = match access_paths {
            Some(v) => v,
            None => {
                self.auth_reject(&mut res)?;
                return Ok(res);
            }
        };
        // Only the x permission may read or change the acl.
        if !access_paths.acl() {
            // A guest there is no x: challenge for a real user instead of
            // returning 403, which would stop the browser from prompting.
            if user.is_none() && self.args.auth.has_users() {
                self.auth_reject(&mut res)?;
            } else {
                status_forbid(&mut res);
            }
            return Ok(res);
        }

        match method {
            Method::GET | Method::HEAD => {
                let ips = self
                    .whitelist_snapshot()
                    .find(&target, Some(&self.args.serve_path))
                    .await
                    .map(|v| v.iter().map(|v| v.to_string()).collect::<Vec<_>>());
                let eff = self
                    .user_acl_snapshot()
                    .effective(&target, Some(&self.args.serve_path))
                    .await;
                let x_users = self.args.auth.x_users(&target, &self.args.serve_path).await;
                let chain = self
                    .user_acl_snapshot()
                    .chain(&target, Some(&self.args.serve_path))
                    .await;
                let own = self
                    .user_acl_snapshot()
                    .own(&target, Some(&self.args.serve_path))
                    .await;
                let inherited = self
                    .user_acl_snapshot()
                    .inherited(&target, Some(&self.args.serve_path))
                    .await;
                let data = serde_json::json!({
                    "path": target,
                    "ips": ips,
                    "allow_read": eff.allow_read,
                    "allow_write": eff.allow_write,
                    "deny_read": eff.deny_read,
                    "version": self.acl_version(),
                    "x_users": x_users,
                    "chain": chain,
                    "own": own,
                    "inherited": inherited,
                });
                let body = serde_json::to_string_pretty(&data)?;
                res.headers_mut()
                    .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
                res.headers_mut()
                    .typed_insert(ContentLength(body.len() as u64));
                if method == Method::GET {
                    *res.body_mut() = body_full(body);
                }
            }
            Method::PUT | Method::POST => {
                let bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map_err(|err| anyhow!("Failed to read request body, {err}"))?
                    .to_bytes();
                #[derive(serde::Deserialize)]
                struct AclPayload {
                    #[serde(default)]
                    version: Option<String>,
                    #[serde(default)]
                    ips: Option<Vec<String>>,
                    #[serde(default)]
                    allow_read: Option<Vec<String>>,
                    #[serde(default)]
                    allow_write: Option<Vec<String>>,
                    #[serde(default)]
                    deny_read: Option<Vec<String>>,
                }
                let payload: AclPayload = match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(err) => {
                        status_bad_request(&mut res, &format!("Invalid JSON, {err}"));
                        return Ok(res);
                    }
                };
                if let Some(version) = &payload.version {
                    if version != &self.acl_version() {
                        *res.status_mut() = StatusCode::CONFLICT;
                        *res.body_mut() = body_full("ACL has been modified, reload and try again");
                        return Ok(res);
                    }
                }
                let clean = |v: Option<Vec<String>>| {
                    v.map(|list| {
                        let mut out: Vec<String> = vec![];
                        for item in list {
                            let item = item.trim().to_string();
                            if item.is_empty() || out.contains(&item) {
                                continue;
                            }
                            out.push(item);
                        }
                        out
                    })
                };
                let mut allow_read = clean(payload.allow_read);
                let allow_write = clean(payload.allow_write);
                let deny_read = clean(payload.deny_read);
                // write implies read: keep allow_read complete
                if let Some(write) = &allow_write {
                    let read = allow_read.get_or_insert_with(Vec::new);
                    for user in write {
                        if !read.contains(user) {
                            read.push(user.clone());
                        }
                    }
                }
                // a user may not be both allowed and denied
                if let Some(user) = deny_read
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .find(|user| {
                        allow_read.iter().flatten().any(|u| u == *user)
                            || allow_write.iter().flatten().any(|u| u == *user)
                    })
                {
                    status_bad_request(
                        &mut res,
                        &format!("user '{user}' appears in both allow and deny"),
                    );
                    return Ok(res);
                }
                // x users always win over the acl, so they must not be denied
                let x_users = self.args.auth.x_users(&target, &self.args.serve_path).await;
                if let Some(user) = deny_read
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .find(|user| x_users.contains(user))
                {
                    status_bad_request(
                        &mut res,
                        &format!("user '{user}' has x and cannot be denied"),
                    );
                    return Ok(res);
                }

                let mut new_whitelist = (*self.whitelist_snapshot()).clone();
                if let Some(ips) = payload.ips {
                    if let Err(err) = new_whitelist.insert_ips(&target, &ips) {
                        status_bad_request(&mut res, &err.to_string());
                        return Ok(res);
                    }
                }
                let mut new_acl = (*self.user_acl_snapshot()).clone();
                new_acl.insert(
                    &target,
                    UserRule {
                        allow_read,
                        allow_write,
                        deny_read,
                    },
                );
                if let Err(err) = ip_whitelist_store::save(&self.args.serve_path, &new_whitelist) {
                    error!("Failed to save acl, {err}");
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    *res.body_mut() = body_full(format!("Failed to save acl, {err}"));
                    return Ok(res);
                }
                if let Err(err) = user_acl::save(&self.args.serve_path, &new_acl) {
                    error!("Failed to save acl, {err}");
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    *res.body_mut() = body_full(format!("Failed to save acl, {err}"));
                    return Ok(res);
                }
                *self.ip_whitelist.write().unwrap_or_else(|e| e.into_inner()) =
                    Arc::new(new_whitelist);
                *self.user_acl.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(new_acl);
                *res.status_mut() = StatusCode::NO_CONTENT;
            }
            Method::DELETE => {
                if let Some(version) = query_params.get("version") {
                    if version != &self.acl_version() {
                        *res.status_mut() = StatusCode::CONFLICT;
                        *res.body_mut() = body_full("ACL has been modified, reload and try again");
                        return Ok(res);
                    }
                }
                let mut new_whitelist = (*self.whitelist_snapshot()).clone();
                new_whitelist.remove(&target);
                let mut new_acl = (*self.user_acl_snapshot()).clone();
                new_acl.remove(&target);
                if let Err(err) = ip_whitelist_store::save(&self.args.serve_path, &new_whitelist) {
                    error!("Failed to save acl, {err}");
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    *res.body_mut() = body_full(format!("Failed to save acl, {err}"));
                    return Ok(res);
                }
                if let Err(err) = user_acl::save(&self.args.serve_path, &new_acl) {
                    error!("Failed to save acl, {err}");
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    *res.body_mut() = body_full(format!("Failed to save acl, {err}"));
                    return Ok(res);
                }
                *self.ip_whitelist.write().unwrap_or_else(|e| e.into_inner()) =
                    Arc::new(new_whitelist);
                *self.user_acl.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(new_acl);
                *res.status_mut() = StatusCode::NO_CONTENT;
            }
            _ => {
                *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            }
        }

        Ok(res)
    }

    async fn list_dir(
        &self,
        entry_path: &Path,
        base_path: &Path,
        access_paths: AccessPaths,
        ip: Option<IpAddr>,
        show_all: bool,
        is_x: bool,
        is_auth_x: bool,
        acl_user: &str,
    ) -> Result<Vec<PathItem>> {
        let mut paths: Vec<PathItem> = vec![];
        let mut rd = fs::read_dir(entry_path).await?;
        while let Ok(Some(entry)) = rd.next_entry().await {
            let entry_path = entry.path();
            self.add_pathitem(
                &mut paths,
                base_path,
                &entry_path,
                ip,
                show_all,
                is_x,
                is_auth_x,
                &access_paths,
                acl_user,
            )
            .await;
        }
        Ok(paths)
    }

    async fn add_pathitem(
        &self,
        paths: &mut Vec<PathItem>,
        base_path: &Path,
        entry_path: &Path,
        ip: Option<IpAddr>,
        show_all: bool,
        is_x: bool,
        is_auth_x: bool,
        access_paths: &AccessPaths,
        acl_user: &str,
    ) {
        // An x user sees ip-blocked entries so they can fix the rule; the
        // content itself is still refused by the ip check in handle().
        if !is_auth_x && !self.entry_ip_allowed(entry_path, ip).await {
            return;
        }
        let rel_path = entry_path
            .strip_prefix(&self.args.serve_path)
            .map(normalize_path)
            .unwrap_or_default();
        if !is_x {
            let acl = self.acl_perm(&rel_path, acl_user).await;
            let native = access_paths
                .find(get_file_name(entry_path), Some(&self.args.serve_path))
                .await
                .is_some();
            let allowed = match acl {
                // A traversable directory is listed so the granted child stays
                // reachable from the file list; its own entries are filtered
                // the same way when the user opens it.
                Some(AclPerm::Deny) => false,
                Some(AclPerm::Read | AclPerm::Write | AclPerm::Traverse) => true,
                // No rule covers the entry: --auth decides, unless a rule
                // below it needs this entry as its entry point.
                None => native || self.has_grant_below(&rel_path, acl_user).await,
            };
            if !allowed {
                return;
            }
        }
        let base_name = get_file_name(entry_path);
        if base_name.eq_ignore_ascii_case(ip_whitelist_store::METADATA_DIR) {
            return;
        }
        if let Ok(Some(mut item)) = self.to_pathitem(entry_path, base_path).await {
            if is_hidden(&self.args.hidden, base_name, item.is_dir()) {
                return;
            }
            if show_all {
                item.whitelist = self.whitelist_label(entry_path).await;
            }
            // The acl summary is only shown to x users: a viewer without x
            // on the directory learns neither the read nor the write list.
            if is_x {
                let x_users = self
                    .args
                    .auth
                    .x_users(&rel_path, &self.args.serve_path)
                    .await;
                let summary = self
                    .user_acl_snapshot()
                    .summary(&rel_path, &x_users, Some(&self.args.serve_path))
                    .await;
                item.allow_read = format_acl_members(&summary.allow_read);
                item.allow_write = format_acl_members(&summary.allow_write);
            }
            paths.push(item);
        }
    }

    async fn to_pathitem<P: AsRef<Path>>(&self, path: P, base_path: P) -> Result<Option<PathItem>> {
        let path = path.as_ref();
        let (meta, meta2) = tokio::join!(fs::metadata(&path), fs::symlink_metadata(&path));
        let (meta, meta2) = (meta?, meta2?);
        let is_symlink = meta2.is_symlink();
        if !self.args.allow_symlink && is_symlink && !self.is_root_contained(path).await {
            return Ok(None);
        }
        if is_symlink && self.is_metadata_contained(path).await {
            return Ok(None);
        }
        let is_dir = meta.is_dir();
        let path_type = match (is_symlink, is_dir) {
            (true, true) => PathType::SymlinkDir,
            (false, true) => PathType::Dir,
            (true, false) => PathType::SymlinkFile,
            (false, false) => PathType::File,
        };
        let mtime = match meta.modified().ok().or_else(|| meta.created().ok()) {
            Some(v) => to_timestamp(&v),
            None => 0,
        };
        let size = match path_type {
            PathType::Dir | PathType::SymlinkDir => {
                let mut count = 0;
                let mut entries = tokio::fs::read_dir(&path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    let entry_path = entry.path();
                    let base_name = get_file_name(&entry_path);
                    let is_dir = entry
                        .file_type()
                        .await
                        .map(|v| v.is_dir())
                        .unwrap_or_default();
                    if is_hidden(&self.args.hidden, base_name, is_dir) {
                        continue;
                    }
                    count += 1;
                    if count >= MAX_SUBPATHS_COUNT {
                        break;
                    }
                }
                count
            }
            PathType::File | PathType::SymlinkFile => meta.len(),
        };
        let rel_path = path.strip_prefix(base_path)?;
        let name = normalize_path(rel_path);
        Ok(Some(PathItem {
            path_type,
            name,
            mtime,
            size,
            whitelist: String::new(),
            allow_read: String::new(),
            allow_write: String::new(),
        }))
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub enum DataKind {
    Index,
    Edit,
    View,
}

#[derive(Debug, Serialize)]
pub struct IndexData {
    pub href: String,
    pub kind: DataKind,
    pub uri_prefix: String,
    pub allow_upload: bool,
    pub allow_delete: bool,
    pub allow_search: bool,
    pub allow_archive: bool,
    pub allow_ip_whitelist: bool,
    pub has_acl: bool,
    pub dir_exists: bool,
    pub auth: bool,
    pub auth_type: String,
    pub user: Option<String>,
    pub paths: Vec<PathItem>,
}

#[derive(Debug, Serialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct PathItem {
    pub path_type: PathType,
    pub name: String,
    pub mtime: u64,
    pub size: u64,
    /// Effective ip whitelist shown to managers: empty means allow all,
    /// `blocked` means nobody may access it.
    pub whitelist: String,
    /// User acl summary: `alice`, `(peter)` for partial, `[tom]` for an
    /// exception allow and `alice*` for an x user.
    pub allow_read: String,
    pub allow_write: String,
}

impl PathItem {
    pub fn is_dir(&self) -> bool {
        self.path_type == PathType::Dir || self.path_type == PathType::SymlinkDir
    }

    pub fn to_dav_xml(&self, prefix: &str) -> String {
        let mtime = match Utc.timestamp_millis_opt(self.mtime as i64) {
            LocalResult::Single(v) => format!("{}", v.format("%a, %d %b %Y %H:%M:%S GMT")),
            _ => String::new(),
        };
        let mut href = encode_uri(&format!("{}{}", prefix, self.name));
        if self.is_dir() && !href.ends_with('/') {
            href.push('/');
        }
        let displayname = escape_str_pcdata(self.base_name());
        match self.path_type {
            PathType::Dir | PathType::SymlinkDir => format!(
                r#"<D:response>
<D:href>{href}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{displayname}</D:displayname>
<D:getlastmodified>{mtime}</D:getlastmodified>
<D:resourcetype><D:collection/></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#
            ),
            PathType::File | PathType::SymlinkFile => format!(
                r#"<D:response>
<D:href>{href}</D:href>
<D:propstat>
<D:prop>
<D:displayname>{displayname}</D:displayname>
<D:getcontentlength>{}</D:getcontentlength>
<D:getlastmodified>{mtime}</D:getlastmodified>
<D:resourcetype></D:resourcetype>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"#,
                self.size
            ),
        }
    }

    pub fn base_name(&self) -> &str {
        self.name.split('/').next_back().unwrap_or_default()
    }

    pub fn sort_by_name(&self, other: &Self) -> Ordering {
        match self.path_type.cmp(&other.path_type) {
            Ordering::Equal => {
                alphanumeric_sort::compare_str(self.name.to_lowercase(), other.name.to_lowercase())
            }
            v => v,
        }
    }

    pub fn sort_by_mtime(&self, other: &Self) -> Ordering {
        match self.path_type.cmp(&other.path_type) {
            Ordering::Equal => self.mtime.cmp(&other.mtime),
            v => v,
        }
    }

    pub fn sort_by_size(&self, other: &Self) -> Ordering {
        match self.path_type.cmp(&other.path_type) {
            Ordering::Equal => self.size.cmp(&other.size),
            v => v,
        }
    }
}

#[derive(Debug, Serialize, Clone, Copy, Eq, PartialEq)]
pub enum PathType {
    Dir,
    SymlinkDir,
    File,
    SymlinkFile,
}

impl PathType {
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir | Self::SymlinkDir)
    }
}

impl Ord for PathType {
    fn cmp(&self, other: &Self) -> Ordering {
        let to_value = |t: &Self| -> u8 {
            if matches!(t, Self::Dir | Self::SymlinkDir) {
                0
            } else {
                1
            }
        };
        to_value(self).cmp(&to_value(other))
    }
}
impl PartialOrd for PathType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Serialize)]
struct EditData {
    href: String,
    kind: DataKind,
    uri_prefix: String,
    allow_upload: bool,
    allow_delete: bool,
    auth: bool,
    auth_type: String,
    user: Option<String>,
    editable: bool,
}

fn to_timestamp(time: &SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn normalize_path<P: AsRef<Path>>(path: P) -> String {
    let path = path.as_ref().to_str().unwrap_or_default();
    if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.to_string()
    }
}

async fn ensure_path_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if fs::symlink_metadata(parent).await.is_err() {
            fs::create_dir_all(&parent).await?;
        }
    }
    Ok(())
}

fn add_cors(res: &mut Response) {
    res.headers_mut()
        .typed_insert(AccessControlAllowOrigin::ANY);
    res.headers_mut()
        .typed_insert(AccessControlAllowCredentials);
    res.headers_mut().insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("*"),
    );
    res.headers_mut().insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Authorization,*"),
    );
    res.headers_mut().insert(
        "Access-Control-Expose-Headers",
        HeaderValue::from_static("Authorization,*,x-client-ip"),
    );
}

fn res_multistatus(res: &mut Response, content: &str) {
    *res.status_mut() = StatusCode::MULTI_STATUS;
    res.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    *res.body_mut() = body_full(format!(
        r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
{content}
</D:multistatus>"#,
    ));
}

async fn zip_dir<W: AsyncWrite + Unpin>(
    writer: &mut W,
    dir: &Path,
    access_paths: AccessPaths,
    ip_whitelist: Arc<IpWhitelist>,
    ip: Option<IpAddr>,
    hidden: &[String],
    compression: CompressionLevel,
    follow_symlinks: bool,
    serve_path: PathBuf,
    user_acl: Arc<UserAcl>,
    acl_user: String,
    is_x: bool,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let hidden = Arc::new(hidden.to_vec());
    let zip_paths = tokio::task::spawn(collect_dir_entries(
        access_paths,
        ip_whitelist,
        ip,
        is_x,
        running,
        dir.to_path_buf(),
        hidden,
        follow_symlinks,
        serve_path,
        user_acl,
        acl_user,
        move |x| x.path().symlink_metadata().is_ok() && x.file_type().is_file(),
    ))
    .await?;
    let mut zip = ZipWriter::new(&mut *writer).with_compression_level(compression);
    for zip_path in zip_paths.into_iter() {
        let filename = match zip_path
            .strip_prefix(dir)
            .ok()
            .and_then(|v| v.to_str())
            .map(|v| v.replace(MAIN_SEPARATOR, "/"))
        {
            Some(v) => v,
            None => continue,
        };
        zip.add_file(&filename, &zip_path).await?;
    }
    zip.finish().await?;
    Ok(())
}

fn extract_cache_headers(meta: &Metadata) -> Option<(ETag, LastModified)> {
    let mtime = meta.modified().ok().or_else(|| meta.created().ok())?;
    let timestamp = to_timestamp(&mtime);
    let size = meta.len();
    let etag = format!(r#""{timestamp}-{size}""#).parse::<ETag>().ok()?;
    let last_modified = LastModified::from(mtime);
    Some((etag, last_modified))
}

fn status_forbid(res: &mut Response) {
    *res.status_mut() = StatusCode::FORBIDDEN;
    *res.body_mut() = body_full("Forbidden");
}

fn status_not_found(res: &mut Response) {
    *res.status_mut() = StatusCode::NOT_FOUND;
    *res.body_mut() = body_full("Not Found");
}

fn redirect(res: &mut Response, location: &str) {
    *res.status_mut() = StatusCode::FOUND;
    if let Ok(value) = HeaderValue::from_str(location) {
        res.headers_mut().insert("location", value);
    }
}

fn status_no_content(res: &mut Response) {
    *res.status_mut() = StatusCode::NO_CONTENT;
}

fn status_bad_request(res: &mut Response, body: &str) {
    *res.status_mut() = StatusCode::BAD_REQUEST;
    if !body.is_empty() {
        *res.body_mut() = body_full(body.to_string());
    }
}

fn set_content_disposition(res: &mut Response, inline: bool, filename: &str) -> Result<()> {
    let kind = if inline { "inline" } else { "attachment" };
    let filename: String = filename
        .chars()
        .map(|ch| {
            if ch.is_ascii_control() && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect();
    let value = if filename.is_ascii() {
        HeaderValue::from_str(&format!("{kind}; filename=\"{filename}\"",))?
    } else {
        HeaderValue::from_str(&format!(
            "{kind}; filename=\"{}\"; filename*=UTF-8''{}",
            filename,
            encode_uri(&filename),
        ))?
    };
    res.headers_mut().insert(CONTENT_DISPOSITION, value);
    Ok(())
}

/// Render an effective whitelist for the WebUI. An allow-all range (0.0.0.0/0
/// or ::/0) and an unrestricted path render as empty; an empty list is blocked.
fn format_acl_members(members: &[AclMember]) -> String {
    members
        .iter()
        .map(|member| {
            let name = member.user.clone();
            let name = if member.is_x {
                format!("{name}*")
            } else {
                name
            };
            match member.kind {
                AclMemberKind::Full => name,
                AclMemberKind::Partial => format!("({name})"),
                AclMemberKind::Exception => format!("[{name}]"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_ip_whitelist(ips: &[IpNet]) -> String {
    if ips.iter().any(|v| v.is_allow_all()) {
        return String::new();
    }
    if ips.is_empty() {
        return "blocked".to_string();
    }
    ips.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn is_hidden(hidden: &[String], file_name: &str, is_dir: bool) -> bool {
    hidden.iter().any(|v| {
        if is_dir {
            if let Some(x) = v.strip_suffix('/') {
                return glob(x, file_name);
            }
        }
        glob(v, file_name)
    })
}

fn set_webdav_headers(res: &mut Response) {
    res.headers_mut().insert(
        "Allow",
        HeaderValue::from_static(
            "GET,HEAD,PUT,OPTIONS,DELETE,PATCH,PROPFIND,COPY,MOVE,CHECKAUTH,LOGOUT",
        ),
    );
    res.headers_mut()
        .insert("DAV", HeaderValue::from_static("1, 2, 3"));
}

async fn get_content_type(path: &Path) -> Result<String> {
    let mut buffer: Vec<u8> = vec![];
    fs::File::open(path)
        .await?
        .take(1024)
        .read_to_end(&mut buffer)
        .await?;
    let mime = mime_guess::from_path(path).first();
    let is_text = content_inspector::inspect(&buffer).is_text();
    let content_type = if is_text {
        let mut detector = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Allow);
        detector.feed(&buffer, buffer.len() < 1024);
        let enc = detector.guess(None, chardetng::Utf8Detection::Allow);
        let charset = format!("; charset={}", enc.name());
        match mime {
            Some(m) => format!("{m}{charset}"),
            None => format!("text/plain{charset}"),
        }
    } else {
        match mime {
            Some(m) => m.to_string(),
            None => "application/octet-stream".into(),
        }
    };
    Ok(content_type)
}

fn parse_upload_offset(headers: &HeaderMap<HeaderValue>, size: u64) -> Result<Option<u64>> {
    let value = match headers.get("x-update-range") {
        Some(v) => v,
        None => return Ok(None),
    };
    let err = || anyhow!("Invalid X-Update-Range Header");
    let value = value.to_str().map_err(|_| err())?;
    if value == "append" {
        return Ok(Some(size));
    }
    // use the first range
    let ranges = parse_range(value, size).ok_or_else(err)?;
    let (start, _) = ranges.first().ok_or_else(err)?;
    Ok(Some(*start))
}

async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn has_query_flag(query_params: &HashMap<String, String>, name: &str) -> bool {
    query_params
        .get(name)
        .map(|v| v.is_empty())
        .unwrap_or_default()
}

async fn collect_dir_entries<F>(
    access_paths: AccessPaths,
    ip_whitelist: Arc<IpWhitelist>,
    ip: Option<IpAddr>,
    is_x: bool,
    running: Arc<AtomicBool>,
    path: PathBuf,
    hidden: Arc<Vec<String>>,
    follow_symlinks: bool,
    serve_path: PathBuf,
    user_acl: Arc<UserAcl>,
    acl_user: String,
    include_entry: F,
) -> Vec<PathBuf>
where
    F: Fn(&DirEntry) -> bool,
{
    let mut paths: Vec<PathBuf> = vec![];
    // Walk the requested directory itself as well: its visible entries may
    // come from acl rules rather than from the native --auth tree.
    let mut roots = access_paths.entry_paths(&path);
    if !roots.iter().any(|v| v == &path) {
        roots.push(path.clone());
    }
    for dir in roots {
        // An --auth rule may point at the metadata dir directly (for example
        // `guest:guest@/.dufs`); never walk into it from an archive or search.
        let rel = dir.strip_prefix(&serve_path).unwrap_or(dir.as_path());
        if rel.components().any(|c| {
            c.as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(ip_whitelist_store::METADATA_DIR)
        }) {
            continue;
        }
        let mut it = WalkDir::new(&dir).follow_links(true).into_iter();
        it.next();
        while let Some(entry) = it.next() {
            if !running.load(atomic::Ordering::SeqCst) {
                break;
            }
            let entry = match entry {
                Ok(v) => v,
                Err(_) => continue,
            };
            let entry_path = entry.path();
            let base_name = get_file_name(entry_path);
            let is_dir = entry.file_type().is_dir();
            if base_name.eq_ignore_ascii_case(ip_whitelist_store::METADATA_DIR) {
                if is_dir {
                    it.skip_current_dir();
                }
                continue;
            }
            if is_hidden(&hidden, base_name, is_dir) {
                if is_dir {
                    it.skip_current_dir();
                }
                continue;
            }

            if !is_x {
                let rel_path = entry_path
                    .strip_prefix(&serve_path)
                    .map(normalize_path)
                    .unwrap_or_default();
                let acl = user_acl.perm(&rel_path, &acl_user, Some(&serve_path)).await;
                let native = access_paths
                    .find(&rel_path, Some(&serve_path))
                    .await
                    .is_some();
                let allowed = match acl {
                    Some(AclPerm::Deny) => false,
                    // Descend into a traversable directory so search and
                    // archives can reach the entries granted below it.
                    Some(AclPerm::Read | AclPerm::Write) => true,
                    Some(AclPerm::Traverse) => is_dir,
                    None => {
                        native
                            || (is_dir
                                && user_acl
                                    .grants_below(&rel_path, &acl_user, Some(&serve_path))
                                    .await)
                    }
                };
                if !allowed {
                    if is_dir {
                        it.skip_current_dir();
                    }
                    continue;
                }
            }

            if !follow_symlinks
                && !fs::canonicalize(entry_path)
                    .await
                    .ok()
                    .map(|v| v.starts_with(&serve_path))
                    .unwrap_or_default()
            {
                // We walked outside the server's root. This could only have
                // happened if we followed a symlink, and hence we only allow it
                // if allow_symlink is enabled, otherwise we skip this entry.
                if is_dir {
                    it.skip_current_dir();
                }
                continue;
            }
            if entry.path_is_symlink()
                && fs::canonicalize(entry_path)
                    .await
                    .ok()
                    .map(|v| v.starts_with(ip_whitelist_store::metadata_dir(&serve_path)))
                    .unwrap_or_default()
            {
                if is_dir {
                    it.skip_current_dir();
                }
                continue;
            }
            let rel_path = entry_path
                .strip_prefix(&serve_path)
                .map(normalize_path)
                .unwrap_or_default();
            if !ip_whitelist.allows(&rel_path, ip, Some(&serve_path)).await {
                continue;
            }
            if !include_entry(&entry) {
                continue;
            }
            paths.push(entry_path.to_path_buf());
        }
    }
    // Several roots may overlap; report each entry once.
    paths.sort();
    paths.dedup();
    paths
}
#[cfg(test)]
mod acl_tests {
    use super::*;

    #[test]
    fn test_format_acl_members() {
        let member = |user: &str, kind, is_x| AclMember {
            user: user.to_string(),
            kind,
            is_x,
        };
        assert_eq!(
            format_acl_members(&[member("guest", AclMemberKind::Full, false)]),
            "guest"
        );
        assert_eq!(
            format_acl_members(&[member("admin", AclMemberKind::Full, true)]),
            "admin*"
        );
        assert_eq!(
            format_acl_members(&[member("peter", AclMemberKind::Partial, false)]),
            "(peter)"
        );
        assert_eq!(
            format_acl_members(&[member("tom", AclMemberKind::Exception, false)]),
            "[tom]"
        );
    }
}
