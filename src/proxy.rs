//! The HTTP side: http://127.0.0.1:<port>/<service>/<route>/... with the token in the service's auth header → Host and token
//! check → allowlist → upstream with the key in place of the token → scrubbed reply. S3 routes instead sign the
//! request with SigV4 (the secret never goes upstream) and stream bodies both ways.

use crate::config::Route;
use crate::graphql;
use crate::log;
use crate::s3;
use crate::vault::Vault;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const MAX_REQUEST: usize = 1 << 20;
pub const MAX_RESPONSE: usize = 16 << 20;
/// Largest S3 request body (one PutObject or UploadPart). RunPod's limit per part is 500 MB.
pub const MAX_S3_BODY: u64 = 512 << 20;
pub const USER_AGENT: &str = concat!("credproxy/", env!("CARGO_PKG_VERSION"));
/// Whole upstream call for key-in-header routes.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
/// A client that takes this long to send a small (key-in-header) body is refused. S3 calls use the config's
/// `s3_idle` and `s3_reply_wait` instead (defaults 60 s and 2 h: RunPod's docs say a CompleteMultipartUpload of a
/// 10 GB+ file can take long and suggest a 2 h read timeout), enforced by the connection watchdog (serve.rs);
/// they have no overall time limit.
const IDLE: Duration = Duration::from_secs(60);

/// What a connection's watchdog (serve.rs) needs to know: whether it carries an allowed S3 call, when bytes last
/// moved, and until when silence is expected (Touch ID, the upstream preparing its reply).
pub struct Progress {
    state: std::sync::Mutex<ProgressState>,
}

struct ProgressState {
    /// Some("service METHOD path") once the connection carries an allowed S3 call (named in the log if cut)
    label: Option<String>,
    last: tokio::time::Instant,
    quiet_until: Option<tokio::time::Instant>,
}

impl Default for Progress {
    fn default() -> Self {
        Progress {
            state: std::sync::Mutex::new(ProgressState {
                label: None,
                last: tokio::time::Instant::now(),
                quiet_until: None,
            }),
        }
    }
}

impl Progress {
    pub fn is_s3(&self) -> bool {
        self.state.lock().unwrap().label.is_some()
    }

    pub(crate) fn mark_s3(&self, label: String) {
        let mut s = self.state.lock().unwrap();
        s.label = Some(label);
        s.last = tokio::time::Instant::now();
    }

    pub fn label(&self) -> String {
        self.state.lock().unwrap().label.clone().unwrap_or_default()
    }

    /// Bytes moved.
    pub(crate) fn touch(&self) {
        let mut s = self.state.lock().unwrap();
        s.last = tokio::time::Instant::now();
        s.quiet_until = None;
    }

    /// Silence is expected for up to `d` from now.
    pub(crate) fn quiet_for(&self, d: Duration) {
        self.state.lock().unwrap().quiet_until = Some(tokio::time::Instant::now() + d);
    }

    /// No bytes for `idle`, and no expected silence left.
    pub fn stalled(&self, idle: Duration) -> bool {
        let s = self.state.lock().unwrap();
        let mut deadline = s.last + idle;
        if let Some(q) = s.quiet_until {
            deadline = deadline.max(q);
        }
        tokio::time::Instant::now() >= deadline
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;

/// Upstream HTTP clients: one for key-in-header APIs, one for S3. S3 goes over HTTP/1.1 only, the protocol the
/// tests exercise (an S3 endpoint behind a CDN would otherwise negotiate HTTP/2).
#[derive(Clone)]
pub struct Clients {
    api: reqwest::Client,
    s3: reqwest::Client,
}

fn api_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .no_proxy()
}

fn s3_builder() -> reqwest::ClientBuilder {
    api_builder().http1_only()
}

pub fn clients() -> Clients {
    Clients {
        api: api_builder().build().expect("http client"),
        s3: s3_builder().build().expect("http client"),
    }
}

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|n| match n {}).boxed()
}

fn reply(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full(format!("credproxy: {msg}\n")))
        .unwrap()
}

/// Replace every occurrence of `key` in `body`.
pub fn scrub(body: &[u8], key: &[u8]) -> Vec<u8> {
    const MARK: &[u8] = b"[REDACTED]";
    if key.is_empty() || body.len() < key.len() {
        return body.to_vec();
    }
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(key) {
            out.extend_from_slice(MARK);
            i += key.len();
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    out
}

/// The token the client presented in the service's own auth header (e.g. "Bearer <token>").
fn presented<'a>(headers: &'a hyper::HeaderMap, header: &str, format: &str) -> Option<&'a [u8]> {
    let v = headers.get(header)?.as_bytes();
    let (pre, post) = format.split_once("{key}")?;
    v.strip_prefix(pre.as_bytes())?
        .strip_suffix(post.as_bytes())
}

/// Only requests addressed to this proxy by its loopback name. A DNS-rebinding page reaches 127.0.0.1 under its
/// own domain name, which the browser always puts in `Host`, so it never gets past this.
fn host_ok(headers: &hyper::HeaderMap, listen: std::net::SocketAddr) -> bool {
    let Some(h) = headers
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
    else {
        return false;
    };
    let port = listen.port();
    let ip = if listen.is_ipv6() {
        format!("[{}]", listen.ip())
    } else {
        listen.ip().to_string()
    };
    h == format!("{ip}:{port}") || h.eq_ignore_ascii_case(&format!("localhost:{port}"))
}

/// `progress` tells the connection's watchdog about an allowed S3 call; other calls live within the short limit.
pub async fn handle(
    vault: Arc<Vault>,
    http: Clients,
    req: Request<Incoming>,
    progress: Arc<Progress>,
) -> Response<Body> {
    let start = Instant::now();
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let (service, rest) = match path
        .strip_prefix('/')
        .map(|p| p.split_once('/').unwrap_or((p, "")))
    {
        Some((s, r)) => (s.to_string(), format!("/{r}")),
        None => (String::new(), String::new()),
    };
    if !host_ok(req.headers(), vault.cfg.listen) {
        log::line(
            &vault.cfg.log,
            &format!("- {method} - 403 (Host is not this proxy)"),
        );
        return reply(
            StatusCode::FORBIDDEN,
            "Host must be this proxy's loopback address",
        );
    }
    // Unknown services get the same 401 as a wrong token: callers without one can't list what's configured.
    let Some(svc) = vault.cfg.services.get(&service) else {
        log::line(
            &vault.cfg.log,
            &format!("- {method} - 401 (no such service)"),
        );
        return reply(
            StatusCode::UNAUTHORIZED,
            "send the credproxy token as the API key",
        );
    };
    let rest = if rest == "/" { String::new() } else { rest };
    let shown = if rest.is_empty() {
        "/".to_string()
    } else {
        log::printable(&rest)
    };
    let ok = presented(req.headers(), &svc.auth_header, &svc.auth_format)
        .is_some_and(|t| vault.check_token(&service, t));
    let res = if ok {
        forward(&vault, &http, &service, &method, &rest, req, &progress).await
    } else {
        // same text as for an unknown service
        reply(
            StatusCode::UNAUTHORIZED,
            "send the credproxy token as the API key",
        )
    };
    let status = res.status().as_u16();
    log::line(
        &vault.cfg.log,
        &format!(
            "{service} {method} {shown} {status} {}ms",
            start.elapsed().as_millis()
        ),
    );
    res
}

/// Allowlist first, then the key (unlocking if needed): a refused call never raises a Touch ID prompt.
async fn forward(
    vault: &Arc<Vault>,
    http: &Clients,
    service: &str,
    method: &str,
    rest: &str,
    req: Request<Incoming>,
    progress: &Arc<Progress>,
) -> Response<Body> {
    let svc = &vault.cfg.services[service];
    let Some((route, sub)) = svc.route(rest) else {
        return reply(StatusCode::FORBIDDEN, "path not allowed");
    };
    if route.s3.is_some() {
        return forward_s3(vault, &http.s3, service, method, route, &sub, req, progress).await;
    }
    let (parts, body) = req.into_parts();
    let body = match read_small(body, IDLE).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    // GraphQL: send only the checked request, as JSON, without the client's query string or content type.
    let graphql = route.graphql_queries.is_some();
    let body = if let Some(fields) = &route.graphql_queries {
        if method != "POST" || !sub.is_empty() {
            return reply(StatusCode::FORBIDDEN, "GraphQL: POST to the endpoint only");
        }
        match graphql::check(&body, fields) {
            Ok(canonical) => Bytes::from(canonical),
            Err(e) => return reply(StatusCode::FORBIDDEN, &format!("GraphQL: {e}")),
        }
    } else {
        let p = if sub.is_empty() { "/" } else { sub.as_str() };
        if !route.allow.iter().any(|r| r.matches(method, p)) {
            return reply(
                StatusCode::FORBIDDEN,
                &format!("{method} {} not allowed", log::printable(p)),
            );
        }
        body
    };

    let key = match vault.key(service, false).await {
        Ok(k) => k,
        Err(e) => return reply(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    let key = &key;
    let mut url = format!("{}{sub}", route.upstream);
    if let Some(q) = parts.uri.query().filter(|_| !graphql) {
        url.push('?');
        url.push_str(q);
    }
    let Ok(m) = reqwest::Method::from_bytes(method.as_bytes()) else {
        return reply(StatusCode::METHOD_NOT_ALLOWED, "bad method");
    };
    let auth = Zeroizing::new(svc.auth_format.replace("{key}", key));
    let Ok(mut auth_value) = reqwest::header::HeaderValue::from_str(&auth) else {
        return reply(StatusCode::INTERNAL_SERVER_ERROR, "bad auth header");
    };
    auth_value.set_sensitive(true);
    // Only these client headers go upstream; cookies, auth and anything else are dropped. Replies must come back
    // uncompressed, or the key couldn't be scrubbed from them.
    let mut out = http
        .api
        .request(m, &url)
        .timeout(UPSTREAM_TIMEOUT)
        .header(svc.auth_header.as_str(), auth_value)
        .header("accept-encoding", "identity");
    if graphql {
        out = out.header("content-type", "application/json");
    } else if let Some(v) = parts.headers.get("content-type") {
        out = out.header("content-type", v.clone());
    }
    if let Some(v) = parts.headers.get("accept") {
        out = out.header("accept", v.clone());
    }
    if !body.is_empty() {
        out = out.body(body);
    }
    let res = match out.send().await {
        Ok(r) => r,
        Err(e) => return upstream_failed(&e),
    };
    buffered_reply(res, &[key.as_bytes()], None).await
}

/// A small client body (≤ MAX_REQUEST), read within `limit`.
#[allow(clippy::result_large_err)]
async fn read_small(body: Incoming, limit: Duration) -> Result<Bytes, Response<Body>> {
    match tokio::time::timeout(limit, Limited::new(body, MAX_REQUEST).collect()).await {
        Ok(Ok(b)) => Ok(b.to_bytes()),
        Ok(Err(_)) => Err(reply(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        )),
        Err(_) => Err(reply(StatusCode::REQUEST_TIMEOUT, "request body too slow")),
    }
}

fn upstream_failed(e: &reqwest::Error) -> Response<Body> {
    let what = if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "cannot connect"
    } else {
        "request failed"
    };
    reply(StatusCode::BAD_GATEWAY, &format!("upstream {what}"))
}

/// The whole upstream reply (≤ MAX_RESPONSE, uncompressed) as status, content type and body, with every copy of
/// each of `secrets` replaced; or the reply to send instead.
#[allow(clippy::result_large_err)]
async fn read_reply(
    mut res: reqwest::Response,
    secrets: &[&[u8]],
    progress: Option<&Progress>,
) -> Result<(StatusCode, Option<hyper::header::HeaderValue>, Vec<u8>), Response<Body>> {
    let status = StatusCode::from_u16(res.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if res
        .headers()
        .get("content-encoding")
        .is_some_and(|e| !e.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(reply(
            StatusCode::BAD_GATEWAY,
            "upstream sent a compressed reply",
        ));
    }
    let ctype = res.headers().get("content-type").cloned();
    let mut buf = Vec::new();
    loop {
        match res.chunk().await {
            Ok(Some(c)) => {
                if let Some(p) = progress {
                    p.touch();
                }
                if buf.len() + c.len() > MAX_RESPONSE {
                    return Err(reply(
                        StatusCode::BAD_GATEWAY,
                        "upstream response too large",
                    ));
                }
                buf.extend_from_slice(&c);
            }
            Ok(None) => break,
            Err(_) => {
                return Err(reply(StatusCode::BAD_GATEWAY, "upstream response broken"));
            }
        }
    }
    let clean = |b: &[u8]| secrets.iter().fold(b.to_vec(), |acc, s| scrub(&acc, s));
    let ctype =
        ctype.and_then(|ct| hyper::header::HeaderValue::from_bytes(&clean(ct.as_bytes())).ok());
    Ok((status, ctype, clean(&buf)))
}

fn reply_with(
    status: StatusCode,
    ctype: Option<hyper::header::HeaderValue>,
    body: Vec<u8>,
) -> Response<Body> {
    let mut b = Response::builder().status(status);
    if let Some(ct) = ctype {
        b = b.header("content-type", ct);
    }
    b.body(full(body)).unwrap()
}

async fn buffered_reply(
    res: reqwest::Response,
    secrets: &[&[u8]],
    progress: Option<&Progress>,
) -> Response<Body> {
    match read_reply(res, secrets, progress).await {
        Ok((status, ctype, body)) => reply_with(status, ctype, body),
        Err(r) => r,
    }
}

/// The only `x-amz-*` headers a client may send: the payload hash, and two the signature replaces anyway.
const S3_CLIENT_AMZ_OK: [&str; 3] = ["x-amz-content-sha256", "x-amz-date", "x-amz-user-agent"];
/// Upstream headers a successful S3 reply keeps (multipart needs the ETag).
const S3_REPLY_HEADERS: [&str; 9] = [
    "content-type",
    "content-encoding",
    "content-disposition",
    "cache-control",
    "content-length",
    "content-range",
    "accept-ranges",
    "etag",
    "last-modified",
];

/// The request body as it goes upstream, with its SHA-256 (hex) or UNSIGNED-PAYLOAD.
enum Payload {
    Small(Bytes, String),
    Stream(Incoming, u64, String),
}

/// S3: check the operation, settle the payload hash, then the key (unlocking if needed), sign, forward.
/// Successful replies stream back as they are: the secret never went upstream, so it can't come back in them.
/// Error replies are small, buffered, and scrubbed of the access key id and secret.
#[allow(clippy::too_many_arguments)]
async fn forward_s3(
    vault: &Arc<Vault>,
    http: &reqwest::Client,
    service: &str,
    method: &str,
    route: &Route,
    sub: &str,
    req: Request<Incoming>,
    progress: &Arc<Progress>,
) -> Response<Body> {
    let svc = &vault.cfg.services[service];
    let cfg = route.s3.as_ref().expect("s3 route");
    let target = match s3::classify(method, sub, req.uri().query(), &cfg.key_prefixes) {
        Ok(t) => t,
        Err(e) => return reply(StatusCode::FORBIDDEN, &e),
    };
    if !cfg.ops.contains(&target.op) {
        return reply(
            StatusCode::FORBIDDEN,
            &format!("{} not allowed", target.op.name()),
        );
    }
    let (parts, body) = req.into_parts();
    // A header-selected variant (copy, SSE, tagging, metadata, checksums) is refused rather than silently changed.
    if let Some(h) = parts
        .headers
        .keys()
        .find(|h| h.as_str().starts_with("x-amz-") && !S3_CLIENT_AMZ_OK.contains(&h.as_str()))
    {
        return reply(
            StatusCode::FORBIDDEN,
            &format!("header {} not allowed", h.as_str()),
        );
    }
    // every check is made before the key: a refused call must never raise a Touch ID prompt
    for n in s3::FORWARDED_HEADERS
        .iter()
        .chain(&["x-amz-content-sha256"])
    {
        let mut values = parts.headers.get_all(*n).iter();
        let first = values.next();
        if values.next().is_some() {
            return reply(StatusCode::BAD_REQUEST, &format!("header {n} given twice"));
        }
        // a value that isn't visible ASCII would be dropped on the way, silently changing the call
        if first.is_some_and(|v| v.to_str().is_err()) {
            return reply(
                StatusCode::BAD_REQUEST,
                &format!("header {n}: only ASCII values (percent-encode, e.g. filename*=UTF-8'')"),
            );
        }
    }
    if parts.headers.get_all("content-encoding").iter().any(|v| {
        v.as_bytes()
            .to_ascii_lowercase()
            .windows(11)
            .any(|w| w == b"aws-chunked")
    }) {
        return reply(
            StatusCode::BAD_REQUEST,
            "aws-chunked bodies are not supported; send the body's SHA-256 in x-amz-content-sha256",
        );
    }
    let claimed = match parts
        .headers
        .get("x-amz-content-sha256")
        .map(|v| v.to_str())
    {
        None => None,
        Some(Ok(v)) if v == s3::UNSIGNED_PAYLOAD => {
            if !cfg.unsigned_payload {
                return reply(
                    StatusCode::FORBIDDEN,
                    "UNSIGNED-PAYLOAD is not enabled for this route; send the body's SHA-256",
                );
            }
            Some(v.to_string())
        }
        Some(v) => match v.ok().and_then(s3::client_hash) {
            Some(h) => Some(h),
            None => {
                return reply(
                    StatusCode::BAD_REQUEST,
                    "x-amz-content-sha256 must be the body's SHA-256 (hex)",
                );
            }
        },
    };
    let length = match parts
        .headers
        .get("content-length")
        .map(|v| v.to_str().ok().and_then(|s| s.parse::<u64>().ok()))
    {
        // neither Content-Length nor chunked: HTTP/1.1 says the body is empty
        None if !parts.headers.contains_key("transfer-encoding") => Some(0),
        None => None,
        Some(Some(n)) => Some(n),
        Some(None) => return reply(StatusCode::BAD_REQUEST, "bad content-length"),
    };
    let payload = match (claimed, target.op.streams_body()) {
        (Some(hash), true) => {
            let Some(n) = length else {
                return reply(StatusCode::LENGTH_REQUIRED, "content-length required");
            };
            if n > MAX_S3_BODY {
                return reply(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &format!(
                        "body over {} MiB: use a multipart upload with smaller parts",
                        MAX_S3_BODY >> 20
                    ),
                );
            }
            Payload::Stream(body, n, hash)
        }
        (claimed, streams) => {
            if length.is_some_and(|n| n > MAX_REQUEST as u64) {
                let msg = if streams {
                    "bodies over 1 MiB need x-amz-content-sha256 (the body's SHA-256)"
                } else {
                    "request body too large"
                };
                return reply(StatusCode::PAYLOAD_TOO_LARGE, msg);
            }
            let b = match read_small(body, vault.cfg.s3_idle).await {
                Ok(b) => b,
                Err(r) => return r,
            };
            let hash = s3::sha256_hex(&b);
            if claimed.is_some_and(|c| c != hash && c != s3::UNSIGNED_PAYLOAD) {
                return reply(
                    StatusCode::BAD_REQUEST,
                    "x-amz-content-sha256 does not match the body",
                );
            }
            Payload::Small(b, hash)
        }
    };

    // allowed: from now on the watchdog (not the short limit) decides, and a Touch ID prompt is expected silence.
    // The watchdog is the one place S3 stalls are handled, in both directions: it also sees a client that stops
    // reading or an upstream that stops accepting, where nothing polls the streams.
    let what = format!("{service} {method} {}{}", route.prefix, log::printable(sub));
    progress.mark_s3(what.clone());
    progress.quiet_for(crate::vault::UNLOCK_TIMEOUT + Duration::from_secs(10));
    let key = match vault.key(service, false).await {
        Ok(k) => k,
        Err(e) => return reply(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    progress.touch();
    let Some((access_key, secret)) = key.split_once('\n') else {
        return reply(StatusCode::INTERNAL_SERVER_ERROR, "bad key");
    };
    let mut url = format!("{}{}", route.upstream, target.path);
    if !target.query.is_empty() {
        url.push('?');
        url.push_str(&target.query);
    }
    // (all ASCII: checked above)
    let forwarded: Vec<(&str, &str)> = s3::FORWARDED_HEADERS
        .iter()
        .filter_map(|n| Some((*n, parts.headers.get(*n)?.to_str().ok()?)))
        .collect();
    let hash = match &payload {
        Payload::Small(_, h) | Payload::Stream(_, _, h) => h.as_str(),
    };
    let signed = match s3::sign_headers(
        method,
        &url,
        &forwarded,
        hash,
        &cfg.region,
        svc.sigv4.as_deref().unwrap_or("s3"),
        access_key,
        secret,
    ) {
        Ok(h) => h,
        Err(e) => return reply(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let Ok(m) = reqwest::Method::from_bytes(method.as_bytes()) else {
        return reply(StatusCode::METHOD_NOT_ALLOWED, "bad method");
    };
    let mut out = http.request(m, &url).header("accept-encoding", "identity");
    for (n, v) in forwarded.iter() {
        out = out.header(*n, *v);
    }
    for (n, v) in &signed {
        let Ok(mut v) = reqwest::header::HeaderValue::from_str(v) else {
            return reply(StatusCode::INTERNAL_SERVER_ERROR, "bad signature header");
        };
        v.set_sensitive(n.eq_ignore_ascii_case("authorization"));
        out = out.header(n.as_str(), v);
    }
    // Once the whole request is out, the upstream may be silent before replying: up to s3_reply_wait where it
    // has real work to do (storing an upload, assembling a multipart upload), s3_idle otherwise.
    let idle_limit = vault.cfg.s3_idle;
    let reply_limit = if target.op.streams_body() || target.op == s3::Op::CompleteMultipartUpload {
        vault.cfg.s3_reply_wait
    } else {
        idle_limit
    };
    let (sent_tx, sent_rx) = tokio::sync::oneshot::channel::<()>();
    // called once the last request byte has been handed on: from then on silence is the upstream working
    let mut on_sent = {
        let progress = progress.clone();
        let mut sent_tx = Some(sent_tx);
        move || {
            if let Some(t) = sent_tx.take() {
                progress.quiet_for(reply_limit + idle_limit);
                let _ = t.send(());
            }
        }
    };
    // when a small request (e.g. CompleteMultipartUpload) went out: its reply, body included, must be done
    // within reply_limit of this
    let sent_at = tokio::time::Instant::now();
    if !matches!(payload, Payload::Stream(..)) {
        on_sent();
    }
    out = match payload {
        // hyper sends no Content-Length for an empty body; some S3 front ends answer a bodiless POST/PUT with 411
        Payload::Small(b, _) if b.is_empty() && matches!(method, "POST" | "PUT") => {
            out.header("content-length", "0")
        }
        Payload::Small(b, _) if b.is_empty() => out,
        Payload::Small(b, _) => out.body(b),
        Payload::Stream(body, n, _) => {
            // counted, not waited for: hyper stops polling the body once Content-Length bytes are out, so the
            // stream's own end may never be seen
            if n == 0 {
                on_sent();
            }
            let progress = progress.clone();
            let mut sent = 0u64;
            let chunks = body.into_data_stream().inspect_ok(move |b: &Bytes| {
                progress.touch();
                sent += b.len() as u64;
                if sent >= n {
                    on_sent();
                }
            });
            out.header("content-length", n)
                .body(reqwest::Body::wrap_stream(chunks))
        }
    };
    let no_reply = async {
        // a dropped sender (the request failed before its end) never starts the clock; send() reports that
        if sent_rx.await.is_ok() {
            tokio::time::sleep(reply_limit).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    let res = tokio::select! {
        r = out.send() => match r {
            Ok(r) => r,
            Err(e) => return upstream_failed(&e),
        },
        _ = no_reply => {
            return reply(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream sent no reply in time (s3_idle, or s3_reply_wait for uploads and completions): the \
                 outcome is unknown (it may still complete); check the object (HEAD, ListParts) before retrying",
            );
        }
    };
    progress.touch();
    if !res.status().is_success() {
        // 304 and 412 need the validators, 416 the object size; a redirect's Location is not passed on
        let keep: Vec<_> = ["etag", "last-modified", "content-range"]
            .iter()
            .filter_map(|n| Some((*n, res.headers().get(*n)?.clone())))
            .collect();
        let mut r = buffered_reply(
            res,
            &[access_key.as_bytes(), secret.as_bytes()],
            Some(progress),
        )
        .await;
        for (n, v) in keep {
            r.headers_mut().insert(n, v);
        }
        return r;
    }
    // S3 may answer CompleteMultipartUpload with 200 and an <Error> body (the failure shows up after the headers
    // went out). A client checking only the status would think the object exists: make it a 502.
    if target.op == s3::Op::CompleteMultipartUpload {
        // The whole reply counts as the upstream's work: S3 may send the headers at once, then keep-alive spaces
        // (or nothing) while it assembles the parts, then the result. Silence is expected throughout, up to
        // s3_reply_wait.
        let left = reply_limit.saturating_sub(sent_at.elapsed());
        progress.quiet_for(left + idle_limit);
        let secrets = [access_key.as_bytes(), secret.as_bytes()];
        let read = read_reply(res, &secrets, None);
        let (status, ctype, body) = match tokio::time::timeout(left, read).await {
            Ok(Ok(r)) => r,
            Ok(Err(r)) => return r,
            Err(_) => {
                return reply(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream did not finish CompleteMultipartUpload within s3_reply_wait: the outcome is \
                     unknown (it may still complete); check the object (HEAD, ListParts) before retrying",
                );
            }
        };
        progress.touch();
        let failed = body.windows(7).any(|w| w == b"<Error>");
        let status = if failed {
            StatusCode::BAD_GATEWAY
        } else {
            status
        };
        return reply_with(status, ctype, body);
    }
    let mut b = Response::builder().status(res.status().as_u16());
    for n in S3_REPLY_HEADERS {
        if let Some(v) = res.headers().get(n) {
            b = b.header(n, v.clone());
        }
    }
    // The request is logged when the reply starts; a reply the upstream breaks off later gets its own line (a
    // stalled one is cut and logged by the watchdog).
    let log_file = vault.cfg.log.clone();
    let moved = progress.clone();
    let stream = res
        .bytes_stream()
        .map_err(BoxError::from)
        .inspect_ok(move |_: &Bytes| moved.touch())
        .inspect_err(move |_: &BoxError| {
            log::line(
                &log_file,
                &format!("{what} reply broke off (upstream closed)"),
            )
        })
        .map_ok(Frame::data);
    b.body(BodyExt::boxed(StreamBody::new(stream))).unwrap()
}

#[cfg(test)]
mod tests {
    use super::scrub;

    /// The protocol a client built from `builder` picks with a TLS server that offers both h2 and http/1.1.
    async fn negotiated(builder: reqwest::ClientBuilder) -> Vec<u8> {
        use tokio::io::AsyncWriteExt;
        use tokio_rustls::rustls;
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (tcp, _) = l.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let alpn = tls.get_ref().1.alpn_protocol().unwrap_or_default().to_vec();
            if alpn == b"http/1.1" {
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
            }
            alpn
        });
        let client = builder
            .add_root_certificate(reqwest::Certificate::from_der(&cert).unwrap())
            .build()
            .unwrap();
        let _ = client
            .get(format!("https://127.0.0.1:{port}/"))
            .send()
            .await;
        server.await.unwrap()
    }

    #[tokio::test]
    async fn s3_upstreams_speak_http1_only() {
        assert_eq!(negotiated(super::s3_builder()).await, b"http/1.1");
        // the same server and setup do get HTTP/2 from the other client: the check can tell them apart
        assert_eq!(negotiated(super::api_builder()).await, b"h2");
    }

    #[test]
    fn host_must_be_the_proxy() {
        let listen: std::net::SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let h = |v: &str| {
            let mut m = hyper::HeaderMap::new();
            m.insert(hyper::header::HOST, v.parse().unwrap());
            m
        };
        for ok in ["127.0.0.1:7777", "localhost:7777", "LocalHost:7777"] {
            assert!(super::host_ok(&h(ok), listen), "{ok}");
        }
        for bad in [
            "evil.example:7777",
            "127.0.0.1:7778",
            "127.0.0.1",
            "localhost",
            "127.0.0.1.evil.example:7777",
        ] {
            assert!(!super::host_ok(&h(bad), listen), "{bad}");
        }
        assert!(!super::host_ok(&hyper::HeaderMap::new(), listen));
    }

    #[test]
    fn scrubs_every_copy() {
        assert_eq!(
            scrub(b"a KEY b KEYKEY", b"KEY"),
            b"a [REDACTED] b [REDACTED][REDACTED]"
        );
        assert_eq!(scrub(b"KE", b"KEY"), b"KE");
        assert_eq!(scrub(b"nothing", b"KEY"), b"nothing");
    }
}
