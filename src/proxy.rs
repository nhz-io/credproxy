//! The HTTP side: http://127.0.0.1:<port>/<token>/<path> → allowlist → upstream with the key added → scrubbed reply.

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

pub async fn handle(
    vault: Arc<Vault>,
    http: reqwest::Client,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let start = Instant::now();
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let (token, rest) = match path
        .strip_prefix('/')
        .map(|p| p.split_once('/').unwrap_or((p, "")))
    {
        Some((t, r)) => (t.to_string(), format!("/{r}")),
        None => (String::new(), String::new()),
    };
    let Some(used) = vault.take(&token) else {
        log::line(
            &vault.cfg.log,
            &format!("- {method} - 404 (no such token, or locked)"),
        );
        return reply(StatusCode::NOT_FOUND, "unknown token (locked?)");
    };
    let rest = if rest == "/" { String::new() } else { rest };
    let res = forward(&vault, &http, &used.service, &used.key, &method, &rest, req).await;
    let status = res.status().as_u16();
    let shown = if rest.is_empty() {
        "/".to_string()
    } else {
        loggable(&rest)
    };
    log::line(
        &vault.cfg.log,
        &format!(
            "{} {method} {shown} {status} {}ms",
            used.service,
            start.elapsed().as_millis()
        ),
    );
    res
}

async fn forward(
    vault: &Vault,
    http: &reqwest::Client,
    service: &str,
    key: &Zeroizing<String>,
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
    if let Some(fields) = &route.graphql_queries {
        if method != "POST" || !sub.is_empty() {
            return reply(StatusCode::FORBIDDEN, "GraphQL: POST to the endpoint only");
        }
        if let Err(e) = graphql::check(&body, fields) {
            return reply(StatusCode::FORBIDDEN, &format!("GraphQL: {e}"));
        }
    } else {
        let p = if sub.is_empty() { "/" } else { sub.as_str() };
        if !route.allow.iter().any(|r| r.matches(method, p)) {
            return reply(
                StatusCode::FORBIDDEN,
                &format!("{method} {} not allowed", loggable(p)),
            );
        }
    }

    let mut url = format!("{}{sub}", route.upstream);
    if let Some(q) = parts.uri.query() {
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
    // Only these client headers go upstream; cookies, auth and anything else are dropped.
    let mut out = http
        .request(m, &url)
        .header(svc.auth_header.as_str(), auth_value);
    for h in ["content-type", "accept"] {
        if let Some(v) = parts.headers.get(h) {
            out = out.header(h, v.clone());
        }
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
    fn scrubs_every_copy() {
        assert_eq!(
            scrub(b"a KEY b KEYKEY", b"KEY"),
            b"a [REDACTED] b [REDACTED][REDACTED]"
        );
        assert_eq!(scrub(b"KE", b"KEY"), b"KE");
        assert_eq!(scrub(b"nothing", b"KEY"), b"nothing");
    }
}
