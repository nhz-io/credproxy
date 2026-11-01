//! The HTTP side: http://127.0.0.1:<port>/<service>/<route>/... with the token in the service's auth header → Host and token
//! check → allowlist → upstream with the key in place of the token → scrubbed reply.

use crate::graphql;
use crate::log;
use crate::vault::Vault;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroizing;

pub const MAX_REQUEST: usize = 1 << 20;
pub const MAX_RESPONSE: usize = 16 << 20;
pub const USER_AGENT: &str = concat!("credproxy/", env!("CARGO_PKG_VERSION"));

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(USER_AGENT)
        .no_proxy()
        .build()
        .expect("http client")
}

fn reply(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(format!("credproxy: {msg}\n"))))
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
) -> Response<Full<Bytes>> {
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
        reply(
            StatusCode::UNAUTHORIZED,
            &format!(
                "send the credproxy token as the API key ({})",
                svc.auth_header
            ),
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
) -> Response<Full<Bytes>> {
    let svc = &vault.cfg.services[service];
    let Some((route, sub)) = svc.route(rest) else {
        return reply(StatusCode::FORBIDDEN, "path not allowed");
    };
    let (parts, body) = req.into_parts();
    let body = match Limited::new(body, MAX_REQUEST).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return reply(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
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
    let mut res = match out.send().await {
        Ok(r) => r,
        Err(e) => {
            let what = if e.is_timeout() {
                "timed out"
            } else if e.is_connect() {
                "cannot connect"
            } else {
                "request failed"
            };
            return reply(StatusCode::BAD_GATEWAY, &format!("upstream {what}"));
        }
    };
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
    let mut b = Response::builder().status(status.as_u16());
    if let Some(ct) = ctype {
        let clean = scrub(ct.as_bytes(), key.as_bytes());
        if let Ok(v) = hyper::header::HeaderValue::from_bytes(&clean) {
            b = b.header("content-type", v);
        }
    }
    b.body(Full::new(Bytes::from(scrub(&buf, key.as_bytes()))))
        .unwrap()
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
