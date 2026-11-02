//! Backblaze B2 native API. At unlock the sealed key pair is traded for a B2 token (b2_authorize_account) and
//! zeroed; only the token, the account's apiUrl and downloadUrl and its id stay in memory. Calls are allowed by
//! name (POST <apiUrl>/b2api/<version>/<call>) and downloads by name (GET <downloadUrl>/file/<bucket>/<name>).
//! When the token ends (relock_after, or B2 says it's bad or expired) the service locks: the next request unlocks
//! again (Touch ID), since the key is gone.

use crate::config::{B2Auth, B2Route, check_upstream};
use crate::log;
use crate::proxy::{
    Body, Clients, IDLE, Progress, UPSTREAM_TIMEOUT, read_buffered, read_small, reply,
    stream_reply, upstream_failed,
};
use crate::s3;
use crate::vault::Vault;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use zeroize::Zeroizing;

/// The authorize call (one small request and reply), made right after the Touch ID wait.
pub(crate) const AUTHORIZE_TIMEOUT: Duration = Duration::from_secs(30);
/// Tries of the authorize call: a connection failure or a 5xx is tried again (the key is still held then; once
/// it's gone, only a new Touch ID can get a token).
const AUTHORIZE_TRIES: u32 = 3;
/// Largest authorize reply read (they are a few KiB).
const MAX_AUTHORIZE_REPLY: usize = 64 << 10;
/// Calls that name the account: credproxy fills in `accountId` (a client may not send one).
const ACCOUNT_CALLS: [&str; 6] = [
    "b2_list_buckets",
    "b2_create_bucket",
    "b2_update_bucket",
    "b2_delete_bucket",
    "b2_create_key",
    "b2_list_keys",
];
/// Upstream headers a successful download keeps (plus every `x-bz-info-*`).
const DOWNLOAD_HEADERS: [&str; 16] = [
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "content-disposition",
    "content-language",
    "content-encoding",
    "cache-control",
    "expires",
    "x-bz-file-id",
    "x-bz-file-name",
    "x-bz-content-sha1",
    "x-bz-upload-timestamp",
    "x-bz-server-side-encryption",
    "x-bz-file-retention-mode",
    "x-bz-file-legal-hold",
];

/// How long a B2 unlock may take: the Touch ID wait, then the authorize call (all its tries).
pub(crate) fn unlock_wait() -> Duration {
    crate::vault::UNLOCK_TIMEOUT + AUTHORIZE_TIMEOUT + Duration::from_secs(10)
}

/// What an unlocked B2 service holds. No Debug: nothing may print the token.
pub struct Session {
    pub token: Zeroizing<String>,
    /// Without a trailing slash.
    pub api_url: String,
    pub download_url: String,
    pub account_id: String,
    /// Some call with this token got a reply other than 401: a later 401 without B2's reason is then taken as the
    /// token's end; before that, as a refusal.
    pub worked: std::sync::atomic::AtomicBool,
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 of `src`, appended to `out` (which has room: no copies left behind by growing).
fn base64_into(src: &[u8], out: &mut String) {
    for c in src.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
}

/// An apiUrl/downloadUrl from the authorize reply: https on a backblazeb2.com host, no path; or, when the
/// authorize URL itself is on this machine (tests, fakes), a URL on this machine.
fn check_b2_url(u: &str, local: bool) -> Result<String, String> {
    let u = check_upstream(u)?;
    if local {
        return match u.starts_with("http://") {
            true => Ok(u),
            false => Err(format!("{u:?} is not on this machine")),
        };
    }
    let host = u.strip_prefix("https://").unwrap_or("");
    let name = host.split(':').next().unwrap_or("");
    if host.contains('/') || !(name == "backblazeb2.com" || name.ends_with(".backblazeb2.com")) {
        return Err(format!("{u:?} is not a backblazeb2.com URL"));
    }
    Ok(u)
}

/// b2_authorize_account with `key` ("<key id>\n<application key>"). credproxy's own buffers holding it (the key,
/// `id:key`, the Basic header string) are zeroed once the reply's headers are in, before its body is read; the
/// header values handed to the HTTP client (one per try) are freed without zeroing, like its internal buffers.
pub async fn authorize(
    http: &reqwest::Client,
    cfg: &B2Auth,
    key: Zeroizing<String>,
) -> Result<Session, String> {
    let (id, secret) = key.split_once('\n').ok_or("bad key")?;
    let mut pair = Zeroizing::new(String::with_capacity(id.len() + secret.len() + 1));
    pair.push_str(id);
    pair.push(':');
    pair.push_str(secret);
    let mut basic = Zeroizing::new(String::with_capacity(6 + pair.len().div_ceil(3) * 4));
    basic.push_str("Basic ");
    base64_into(pair.as_bytes(), &mut basic);
    let mut value = reqwest::header::HeaderValue::from_str(&basic).map_err(|_| "bad key")?;
    value.set_sensitive(true);
    // every try, and the waits between them, within AUTHORIZE_TIMEOUT
    let deadline = tokio::time::Instant::now() + AUTHORIZE_TIMEOUT;
    let mut tries = 0;
    let sent = loop {
        tries += 1;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let r = http
            .get(&cfg.authorize_url)
            .timeout(left)
            .header("authorization", value.clone())
            .header("accept-encoding", "identity")
            .send()
            .await;
        let transient = match &r {
            Ok(res) => res.status().is_server_error(),
            Err(e) => !e.is_builder(),
        };
        let pause = Duration::from_secs(tries.into());
        if !transient
            || tries == AUTHORIZE_TRIES
            || deadline.saturating_duration_since(tokio::time::Instant::now()) <= pause
        {
            break r;
        }
        tokio::time::sleep(pause).await;
    };
    drop((value, basic, pair, key));
    let mut res = sent.map_err(|e| {
        let what = if e.is_timeout() {
            "timed out"
        } else if e.is_connect() {
            "cannot connect"
        } else {
            "request failed"
        };
        format!("B2 authorize: {what}")
    })?;
    let status = res.status();
    let mut body = Zeroizing::new(Vec::with_capacity(MAX_AUTHORIZE_REPLY));
    while let Some(c) = res
        .chunk()
        .await
        .map_err(|_| "B2 authorize: reply broken".to_string())?
    {
        if body.len() + c.len() > MAX_AUTHORIZE_REPLY {
            return Err("B2 authorize: reply too large".into());
        }
        body.extend_from_slice(&c);
    }
    let mut v: Value = serde_json::from_slice(&body)
        .map_err(|_| format!("B2 authorize: {} (reply is not JSON)", status.as_u16()))?;
    if !status.is_success() {
        let s = |k: &str| {
            // B2's own words, printable ASCII only (it goes into the log)
            v[k].as_str()
                .unwrap_or("")
                .chars()
                .take(200)
                .map(|c| {
                    if c.is_ascii_graphic() || c == ' ' {
                        c
                    } else {
                        '?'
                    }
                })
                .collect::<String>()
        };
        return Err(format!(
            "B2 authorize failed: {} {}: {}",
            status.as_u16(),
            s("code"),
            s("message")
        ));
    }
    // taken out of the parsed reply, not copied: the token's own buffer is zeroed when the session ends
    let token = match v["authorizationToken"].take() {
        Value::String(t) => Zeroizing::new(t),
        _ => return Err("B2 authorize: no authorizationToken".into()),
    };
    if token.is_empty() || token.len() > 4096 || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err("B2 authorize: bad authorizationToken".into());
    }
    let account_id = v["accountId"].as_str().unwrap_or("").to_string();
    if account_id.is_empty() || !account_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("B2 authorize: bad accountId".into());
    }
    let local = cfg.authorize_url.starts_with("http://");
    let api = &v["apiInfo"]["storageApi"];
    let url = |k: &str| {
        check_b2_url(api[k].as_str().unwrap_or(""), local)
            .map_err(|e| format!("B2 authorize: {k} {e}"))
    };
    Ok(Session {
        api_url: url("apiUrl")?,
        download_url: url("downloadUrl")?,
        token,
        account_id,
        worked: Default::default(),
    })
}

/// A bucket name as B2 makes them: letters, digits and `-`.
fn valid_bucket(b: &str) -> bool {
    !b.is_empty() && b.len() <= 63 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

/// A file name in a download URL: each segment percent-encoded, `/` kept.
fn encode_name(name: &str) -> String {
    name.split('/')
        .map(s3::encode)
        .collect::<Vec<_>>()
        .join("/")
}

#[allow(clippy::result_large_err)]
fn token_value(session: &Session) -> Result<reqwest::header::HeaderValue, Response<Body>> {
    let mut v = reqwest::header::HeaderValue::from_str(&session.token)
        .map_err(|_| reply(StatusCode::INTERNAL_SERVER_ERROR, "bad B2 token"))?;
    v.set_sensitive(true);
    Ok(v)
}

/// A reply other than a successful download: buffered and scrubbed of the token. A 401 saying the token expired or
/// is bad, or one without B2's code (e.g. a HEAD's) to a token that has worked before, means the token ended: the
/// service locks and the client gets a 503 (a retry unlocks again). The call is not replayed, it may change state.
/// A codeless 401 to a token that never worked isn't taken as its end: it becomes a 502, so a client doesn't unlock (Touch ID)
/// again and again for a refusal. B2's `unauthorized` (the token is good but may not do this) is passed on.
async fn buffered(
    vault: &Vault,
    service: &str,
    session: &Arc<Session>,
    res: reqwest::Response,
    progress: Option<&Progress>,
) -> Response<Body> {
    // a download's watchdog must see the error body's bytes move
    let b = match read_buffered(res, &[session.token.as_bytes()], progress).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let code = serde_json::from_slice::<Value>(&b.body)
        .ok()
        .and_then(|v| v["code"].as_str().map(str::to_string));
    if b.status != StatusCode::UNAUTHORIZED {
        // the token got past B2's check: a success, or B2's own error about the call (a front end's 5xx didn't
        // look at it)
        if b.status.is_success() || code.is_some() {
            session.worked.store(true, Ordering::Relaxed);
        }
        return b.into_response();
    }
    match code.as_deref() {
        Some("expired_auth_token" | "bad_auth_token") => {}
        None if session.worked.load(Ordering::Relaxed) => {}
        None => {
            return reply(
                StatusCode::BAD_GATEWAY,
                "B2 answered 401 without saying why, to a token that hasn't worked yet: not taken as its end",
            );
        }
        // e.g. `unauthorized`: the token is good but may not do this
        Some(_) => return b.into_response(),
    }
    vault.expire(service, session);
    reply(
        StatusCode::SERVICE_UNAVAILABLE,
        "B2 token expired or revoked, so the service is locked: retry (the retry unlocks: Touch ID)",
    )
}

/// Allowlist first, then the session (unlocking if needed): a refused call never raises a Touch ID prompt.
#[allow(clippy::too_many_arguments)]
pub async fn forward(
    vault: &Arc<Vault>,
    http: &Clients,
    service: &str,
    method: &str,
    route: &B2Route,
    sub: &str,
    req: Request<Incoming>,
    progress: &Arc<Progress>,
) -> Response<Body> {
    match route {
        B2Route::Api(calls) => api(vault, &http.api, service, method, calls, sub, req).await,
        B2Route::Download => download(vault, &http.s3, service, method, sub, req, progress).await,
    }
}

async fn api(
    vault: &Arc<Vault>,
    http: &reqwest::Client,
    service: &str,
    method: &str,
    calls: &[String],
    sub: &str,
    req: Request<Incoming>,
) -> Response<Body> {
    let call = sub.strip_prefix('/').unwrap_or("");
    if method != "POST" || !calls.iter().any(|c| c == call) {
        let p = if sub.is_empty() { "/" } else { sub };
        return reply(
            StatusCode::FORBIDDEN,
            &format!("{method} {} not allowed", log::printable(p)),
        );
    }
    if req.uri().query().is_some() {
        return reply(
            StatusCode::FORBIDDEN,
            "B2 calls take a JSON body, no query string",
        );
    }
    let body = match read_small(req.into_body(), IDLE).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let mut json: Value = if body.is_empty() {
        Value::Object(Default::default())
    } else {
        match serde_json::from_slice(&body) {
            Ok(v @ Value::Object(_)) => v,
            _ => return reply(StatusCode::BAD_REQUEST, "body must be a JSON object"),
        }
    };
    // credproxy names the account; a client's own accountId is refused before unlocking (a refused call never
    // raises a Touch ID prompt, and the account isn't known until then)
    if ACCOUNT_CALLS.contains(&call) && json.get("accountId").is_some() {
        return reply(
            StatusCode::FORBIDDEN,
            "leave accountId out: credproxy fills it in",
        );
    }
    let session = match vault.b2(service).await {
        Ok(s) => s,
        Err(e) => return reply(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    if ACCOUNT_CALLS.contains(&call) {
        json.as_object_mut().expect("object").insert(
            "accountId".into(),
            Value::String(session.account_id.clone()),
        );
    }
    let version = &vault.cfg.services[service]
        .b2
        .as_ref()
        .expect("b2 service")
        .version;
    let url = format!("{}/b2api/{version}/{call}", session.api_url);
    let auth = match token_value(&session) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let res = http
        .post(&url)
        .timeout(UPSTREAM_TIMEOUT)
        .header("authorization", auth)
        .header("accept-encoding", "identity")
        .header("content-type", "application/json")
        .body(json.to_string())
        .send()
        .await;
    match res {
        Ok(r) => buffered(vault, service, &session, r, None).await,
        Err(e) => upstream_failed(&e),
    }
}

async fn download(
    vault: &Arc<Vault>,
    http: &reqwest::Client,
    service: &str,
    method: &str,
    sub: &str,
    req: Request<Incoming>,
    progress: &Arc<Progress>,
) -> Response<Body> {
    if method != "GET" && method != "HEAD" {
        return reply(
            StatusCode::FORBIDDEN,
            &format!("{method} not allowed on downloads"),
        );
    }
    // B2 takes a token in the query too: nothing from the client's query goes upstream
    if req.uri().query().is_some() {
        return reply(StatusCode::FORBIDDEN, "no query string on downloads");
    }
    let Some((bucket, raw)) = sub.strip_prefix('/').and_then(|p| p.split_once('/')) else {
        return reply(
            StatusCode::FORBIDDEN,
            "download path: /<bucket>/<file name>",
        );
    };
    if !valid_bucket(bucket) {
        return reply(StatusCode::FORBIDDEN, "bad bucket name");
    }
    let Some(name) = s3::decode(raw).filter(|n| s3::valid_key(n)) else {
        return reply(
            StatusCode::FORBIDDEN,
            "bad file name (no empty, . or .. segments, no control characters)",
        );
    };
    let mut ranges = req.headers().get_all("range").iter();
    let range = ranges.next().cloned();
    if ranges.next().is_some() {
        return reply(StatusCode::BAD_REQUEST, "header range given twice");
    }
    if range.as_ref().is_some_and(|v| v.to_str().is_err()) {
        return reply(StatusCode::BAD_REQUEST, "header range: only ASCII values");
    }
    // allowed: the watchdog decides from now on (a download runs as long as it moves), and a Touch ID prompt is
    // expected silence
    let what = format!("{service} {method} /file{}", log::printable(sub));
    progress.mark_streaming(what.clone());
    progress.quiet_for(unlock_wait());
    let session = match vault.b2(service).await {
        Ok(s) => s,
        Err(e) => return reply(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    let (idle, connect) = (vault.cfg.s3_idle, vault.cfg.s3_connect_timeout);
    progress.quiet_for(connect + idle);
    let url = format!(
        "{}/file/{bucket}/{}",
        session.download_url,
        encode_name(&name)
    );
    let auth = match token_value(&session) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(m) = reqwest::Method::from_bytes(method.as_bytes()) else {
        return reply(StatusCode::METHOD_NOT_ALLOWED, "bad method");
    };
    let mut out = http
        .request(m, &url)
        .header("authorization", auth)
        .header("accept-encoding", "identity");
    if let Some(r) = range {
        out = out.header("range", r);
    }
    let res = match tokio::time::timeout(connect + idle, out.send()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return upstream_failed(&e),
        Err(_) => {
            return reply(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream sent no reply in time (s3_idle)",
            );
        }
    };
    progress.touch();
    if !res.status().is_success() {
        // 416 needs the size
        let range = res.headers().get("content-range").cloned();
        let mut r = buffered(vault, service, &session, res, Some(progress)).await;
        if let Some(v) = range {
            r.headers_mut().insert("content-range", v);
        }
        return r;
    }
    session.worked.store(true, Ordering::Relaxed);
    // a header holding the token is dropped (B2 never sends one; the body can't be checked, it streams)
    let token = session.token.as_bytes();
    let keep: Vec<_> = res
        .headers()
        .iter()
        .filter(|(n, v)| {
            (DOWNLOAD_HEADERS.contains(&n.as_str()) || n.as_str().starts_with("x-bz-info-"))
                && !v.as_bytes().windows(token.len()).any(|w| w == token)
        })
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    stream_reply(res, method, false, keep, &vault.cfg.log, what, progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("Aladdin:open sesame", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        ] {
            let mut s = String::new();
            base64_into(i.as_bytes(), &mut s);
            assert_eq!(s, o, "{i:?}");
        }
    }

    #[test]
    fn unlock_wait_covers_touch_id_and_authorize() {
        assert!(unlock_wait() > crate::vault::UNLOCK_TIMEOUT + AUTHORIZE_TIMEOUT);
    }

    #[test]
    fn b2_urls() {
        for ok in [
            "https://api005.backblazeb2.com",
            "https://f005.backblazeb2.com/",
        ] {
            assert!(check_b2_url(ok, false).is_ok(), "{ok}");
        }
        for bad in [
            "http://api005.backblazeb2.com",
            "https://api005.backblazeb2.com.evil.example",
            "https://evilbackblazeb2.com",
            "https://api005.backblazeb2.com/x",
            "https://user@api005.backblazeb2.com",
            "http://127.0.0.1:9",
            "",
        ] {
            assert!(check_b2_url(bad, false).is_err(), "{bad}");
        }
        assert!(check_b2_url("http://127.0.0.1:9", true).is_ok());
        assert!(check_b2_url("https://api005.backblazeb2.com", true).is_err());
        assert!(check_b2_url("http://evil.example", true).is_err());
    }

    #[test]
    fn names() {
        assert_eq!(encode_name("runs/a b/ø.txt"), "runs/a%20b/%C3%B8.txt");
        assert!(valid_bucket("gpurent-results-1") && !valid_bucket("a/b") && !valid_bucket(""));
    }
}
