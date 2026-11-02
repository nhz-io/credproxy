//! The HTTP side: http://127.0.0.1:<port>/<service>/<route>/... with the token in the service's auth header → Host and token
//! check → allowlist → upstream with the key in place of the token → scrubbed reply. S3 routes instead sign the
//! request with SigV4 (the secret never goes upstream) and stream bodies both ways.

use crate::config::Route;
use crate::graphql;
use crate::log;
use crate::s3;
use crate::vault::Vault;
use bytes::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt};
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
/// Whole upstream call for S3 routes (a 500 MB part over a slow uplink; a slow CompleteMultipartUpload).
pub const S3_TIMEOUT: Duration = Duration::from_secs(3600);
/// A streamed S3 body (either way) that moves no bytes for this long is aborted; so is a client that takes this
/// long to send a small body.
const IDLE: Duration = Duration::from_secs(60);

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .no_proxy()
        .build()
        .expect("http client")
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

/// `s`, failing with "idle timeout" when no item arrives for `IDLE`.
fn idle<S, T, E>(s: S) -> impl Stream<Item = Result<T, BoxError>> + Send + 'static
where
    S: Stream<Item = Result<T, E>> + Send + 'static,
    E: Into<BoxError>,
    T: Send + 'static,
{
    futures_util::stream::unfold(Some(Box::pin(s)), |state| async move {
        let mut s = state?;
        match tokio::time::timeout(IDLE, s.next()).await {
            Ok(Some(Ok(x))) => Some((Ok(x), Some(s))),
            Ok(Some(Err(e))) => Some((Err(e.into()), None)),
            Ok(None) => None,
            Err(_) => Some((Err("idle timeout".into()), None)),
        }
    })
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

/// Path for the log: printable, short, never the token.
fn loggable(p: &str) -> String {
    p.chars()
        .take(200)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
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

pub async fn handle(
    vault: Arc<Vault>,
    http: reqwest::Client,
    req: Request<Incoming>,
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
        loggable(&rest)
    };
    let ok = presented(req.headers(), &svc.auth_header, &svc.auth_format)
        .is_some_and(|t| vault.check_token(&service, t));
    let res = if ok {
        forward(&vault, &http, &service, &method, &rest, req).await
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
    http: &reqwest::Client,
    service: &str,
    method: &str,
    rest: &str,
    req: Request<Incoming>,
) -> Response<Body> {
    let svc = &vault.cfg.services[service];
    let Some((route, sub)) = svc.route(rest) else {
        return reply(StatusCode::FORBIDDEN, "path not allowed");
    };
    if route.s3.is_some() {
        return forward_s3(vault, http, service, method, route, &sub, req).await;
    }
    let (parts, body) = req.into_parts();
    let body = match read_small(body).await {
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
                &format!("{method} {} not allowed", loggable(p)),
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
    buffered_reply(res, &[key.as_bytes()]).await
}

/// A small client body (≤ MAX_REQUEST), read within IDLE.
#[allow(clippy::result_large_err)]
async fn read_small(body: Incoming) -> Result<Bytes, Response<Body>> {
    match tokio::time::timeout(IDLE, Limited::new(body, MAX_REQUEST).collect()).await {
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

/// The whole upstream reply (≤ MAX_RESPONSE, uncompressed): status, content type and body, with every copy of
/// each of `secrets` replaced.
async fn buffered_reply(mut res: reqwest::Response, secrets: &[&[u8]]) -> Response<Body> {
    let status = res.status();
    if res
        .headers()
        .get("content-encoding")
        .is_some_and(|e| !e.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return reply(StatusCode::BAD_GATEWAY, "upstream sent a compressed reply");
    }
    let ctype = res.headers().get("content-type").cloned();
    let mut buf = Vec::new();
    loop {
        match res.chunk().await {
            Ok(Some(c)) => {
                if buf.len() + c.len() > MAX_RESPONSE {
                    return reply(StatusCode::BAD_GATEWAY, "upstream response too large");
                }
                buf.extend_from_slice(&c);
            }
            Ok(None) => break,
            Err(_) => return reply(StatusCode::BAD_GATEWAY, "upstream response broken"),
        }
    }
    let clean = |b: &[u8]| secrets.iter().fold(b.to_vec(), |acc, s| scrub(&acc, s));
    let mut b = Response::builder().status(status.as_u16());
    if let Some(ct) = ctype
        && let Ok(v) = hyper::header::HeaderValue::from_bytes(&clean(ct.as_bytes()))
    {
        b = b.header("content-type", v);
    }
    b.body(full(clean(&buf))).unwrap()
}

/// Client headers an S3 call may carry upstream (all signed). Others are dropped: notably `x-amz-copy-source`
/// (CopyObject, UploadPartCopy) and the client's own auth.
const S3_REQUEST_HEADERS: [&str; 5] = [
    "content-type",
    "content-md5",
    "range",
    "if-match",
    "if-none-match",
];
/// Upstream headers a successful S3 reply keeps (multipart needs the ETag).
const S3_REPLY_HEADERS: [&str; 6] = [
    "content-type",
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
async fn forward_s3(
    vault: &Arc<Vault>,
    http: &reqwest::Client,
    service: &str,
    method: &str,
    route: &Route,
    sub: &str,
    req: Request<Incoming>,
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
            let b = match read_small(body).await {
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

    let key = match vault.key(service, false).await {
        Ok(k) => k,
        Err(e) => return reply(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    let Some((access_key, secret)) = key.split_once('\n') else {
        return reply(StatusCode::INTERNAL_SERVER_ERROR, "bad key");
    };
    let mut url = format!("{}{}", route.upstream, target.path);
    if !target.query.is_empty() {
        url.push('?');
        url.push_str(&target.query);
    }
    let forwarded: Vec<(&str, &str)> = S3_REQUEST_HEADERS
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
    let mut out = http
        .request(m, &url)
        .timeout(S3_TIMEOUT)
        .header("accept-encoding", "identity");
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
    out = match payload {
        // hyper sends no Content-Length for an empty body; some S3 front ends answer a bodiless POST/PUT with 411
        Payload::Small(b, _) if b.is_empty() && matches!(method, "POST" | "PUT") => {
            out.header("content-length", "0")
        }
        Payload::Small(b, _) if b.is_empty() => out,
        Payload::Small(b, _) => out.body(b),
        Payload::Stream(body, n, _) => out
            .header("content-length", n)
            .body(reqwest::Body::wrap_stream(idle(body.into_data_stream()))),
    };
    let res = match out.send().await {
        Ok(r) => r,
        Err(e) => return upstream_failed(&e),
    };
    if !res.status().is_success() {
        return buffered_reply(res, &[access_key.as_bytes(), secret.as_bytes()]).await;
    }
    let mut b = Response::builder().status(res.status().as_u16());
    for n in S3_REPLY_HEADERS {
        if let Some(v) = res.headers().get(n) {
            b = b.header(n, v.clone());
        }
    }
    // The request is logged when the reply starts; a reply that breaks off later gets its own line.
    let (log_file, what) = (
        vault.cfg.log.clone(),
        format!("{service} {method} {}{}", route.prefix, loggable(sub)),
    );
    let stream = idle(res.bytes_stream())
        .inspect_err(move |_| {
            log::line(
                &log_file,
                &format!("{what} reply broke off (stalled or upstream closed)"),
            )
        })
        .map_ok(Frame::data);
    b.body(BodyExt::boxed(StreamBody::new(stream))).unwrap()
}

#[cfg(test)]
mod tests {
    use super::scrub;

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
