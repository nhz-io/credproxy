//! Backblaze B2 native API. At unlock the sealed key pair is traded for a B2 token (b2_authorize_account) and
//! zeroed; only the token, the account's apiUrl and downloadUrl and its id stay in memory. Calls are allowed by
//! name (POST <apiUrl>/b2api/<version>/<call>) and downloads by name (GET <downloadUrl>/file/<bucket>/<name>).
//! When the token ends (relock_after, or B2 says it's bad or expired) the service locks: the next request unlocks
//! again (Touch ID), since the key is gone.

use crate::config::{B2Auth, B2Route, check_upstream};
use crate::log;
use crate::proxy::{
    Body, Buffered, Clients, IDLE, NotDone, Outgoing, Progress, UPSTREAM_TIMEOUT, read_buffered,
    read_small, reply, send_watched, stream_reply, upstream_failed,
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
    /// Bucket name → id, looked up once per session (uploads name the bucket, b2_get_upload_url wants its id).
    pub bucket_ids: std::sync::Mutex<std::collections::HashMap<String, String>>,
    /// Upload URLs not in use. An upload takes one to itself (B2 refuses a token another upload is using), puts it
    /// back after success and drops it after any failure (B2: a refused upload's URL may no longer be good).
    pub upload_urls: std::sync::Mutex<Vec<UploadUrl>>,
}

impl Session {
    /// Forget bucket `id` (deleted, or recreated under its name with a new id): its cached name and pooled
    /// upload URLs.
    fn forget_bucket(&self, id: &str) {
        self.bucket_ids.lock().unwrap().retain(|_, v| v != id);
        self.upload_urls
            .lock()
            .unwrap()
            .retain(|u| u.bucket_id != id);
    }
}

/// One of B2's upload URLs, with the token that goes with it (valid with it, at most 24 h). No Debug.
pub struct UploadUrl {
    pub bucket_id: String,
    pub url: String,
    pub token: Zeroizing<String>,
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
        bucket_ids: Default::default(),
        upload_urls: Default::default(),
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
    match read_buffered(res, &[session.token.as_bytes()], progress).await {
        Ok(b) => judge(vault, service, session, b),
        Err(r) => r,
    }
}

/// B2's `code` in an error reply, if it has one.
fn b2_code(b: &Buffered) -> Option<String> {
    serde_json::from_slice::<Value>(&b.body)
        .ok()
        .and_then(|v| v["code"].as_str().map(str::to_string))
}

/// What `buffered` sends for a reply already read (see there).
fn judge(vault: &Vault, service: &str, session: &Arc<Session>, b: Buffered) -> Response<Body> {
    let code = b2_code(&b);
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
    prefix: &str,
    route: &B2Route,
    sub: &str,
    req: Request<Incoming>,
    progress: &Arc<Progress>,
) -> Response<Body> {
    match route {
        B2Route::Api(calls) => api(vault, &http.api, service, method, calls, sub, req).await,
        B2Route::Download => {
            download(vault, &http.s3, service, method, prefix, sub, req, progress).await
        }
        B2Route::Upload => upload(vault, http, service, method, prefix, sub, req, progress).await,
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
    let r = match post_account(vault, http, service, &session, call, &json).await {
        Ok(r) => buffered(vault, service, &session, r, None).await,
        Err(r) => r,
    };
    // a deleted bucket's cached id and upload URLs go with it
    if call == "b2_delete_bucket"
        && r.status().is_success()
        && let Some(id) = json["bucketId"].as_str()
    {
        session.forget_bucket(id);
    }
    r
}

/// POST <apiUrl>/b2api/<version>/<call> with the account token.
#[allow(clippy::result_large_err)]
async fn post_account(
    vault: &Vault,
    http: &reqwest::Client,
    service: &str,
    session: &Session,
    call: &str,
    json: &Value,
) -> Result<reqwest::Response, Response<Body>> {
    let version = &vault.cfg.services[service]
        .b2
        .as_ref()
        .expect("b2 service")
        .version;
    let url = format!("{}/b2api/{version}/{call}", session.api_url);
    let auth = token_value(session)?;
    http.post(&url)
        .timeout(UPSTREAM_TIMEOUT)
        .header("authorization", auth)
        .header("accept-encoding", "identity")
        .header("content-type", "application/json")
        .body(json.to_string())
        .send()
        .await
        .map_err(|e| upstream_failed(&e))
}

/// A call credproxy makes itself (bucket lookup, upload URL): its JSON reply, or the reply to send instead (B2's
/// error, scrubbed; an ended token locks the service as for any call).
#[allow(clippy::result_large_err)]
async fn account_call(
    vault: &Vault,
    http: &reqwest::Client,
    service: &str,
    session: &Arc<Session>,
    call: &str,
    json: Value,
) -> Result<Value, Response<Body>> {
    let res = post_account(vault, http, service, session, call, &json).await?;
    if !res.status().is_success() {
        return Err(buffered(vault, service, session, res, None).await);
    }
    session.worked.store(true, Ordering::Relaxed);
    let b = read_buffered(res, &[session.token.as_bytes()], None).await?;
    serde_json::from_slice(&b.body).map_err(|_| {
        reply(
            StatusCode::BAD_GATEWAY,
            &format!("B2 {call}: reply is not JSON"),
        )
    })
}

/// `/<bucket>/<file name>` (the name percent-encoded), checked: the bucket and the decoded name.
#[allow(clippy::result_large_err)]
fn bucket_and_name(sub: &str) -> Result<(&str, String), Response<Body>> {
    let Some((bucket, raw)) = sub.strip_prefix('/').and_then(|p| p.split_once('/')) else {
        return Err(reply(StatusCode::FORBIDDEN, "path: /<bucket>/<file name>"));
    };
    if !valid_bucket(bucket) {
        return Err(reply(StatusCode::FORBIDDEN, "bad bucket name"));
    }
    let Some(name) = s3::decode(raw).filter(|n| s3::valid_key(n)) else {
        return Err(reply(
            StatusCode::FORBIDDEN,
            "bad file name (no empty, . or .. segments, no control characters)",
        ));
    };
    Ok((bucket, name))
}

#[allow(clippy::too_many_arguments)]
async fn download(
    vault: &Arc<Vault>,
    http: &reqwest::Client,
    service: &str,
    method: &str,
    prefix: &str,
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
    let (bucket, name) = match bucket_and_name(sub) {
        Ok(x) => x,
        Err(r) => return r,
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
    let what = format!("{service} {method} {prefix}{}", log::printable(sub));
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

/// Client headers an upload can't carry: B2 refuses them on uploads, and dropping one would change what is stored.
const UPLOAD_REFUSED_HEADERS: [&str; 5] = [
    "content-encoding",
    "content-disposition",
    "content-language",
    "content-range",
    "expires",
];

/// An upload URL from b2_get_upload_url: https on a backblaze.com or backblazeb2.com host (B2's examples use
/// pod-….backblaze.com), with its path; or, when authorizing on this machine (tests), a URL on this machine.
fn check_upload_url(u: &str, local: bool) -> Result<String, String> {
    let u = check_upstream(u)?;
    if local {
        return match u.starts_with("http://") {
            true => Ok(u),
            false => Err(format!("{u:?} is not on this machine")),
        };
    }
    let host = u
        .strip_prefix("https://")
        .and_then(|r| r.split(['/', ':']).next())
        .unwrap_or("");
    if !(host.ends_with(".backblaze.com") || host.ends_with(".backblazeb2.com")) {
        return Err(format!("{u:?} is not a backblaze.com URL"));
    }
    Ok(u)
}

/// The bucket's id, looked up once per session.
#[allow(clippy::result_large_err)]
async fn bucket_id(
    vault: &Vault,
    http: &reqwest::Client,
    service: &str,
    session: &Arc<Session>,
    bucket: &str,
) -> Result<String, Response<Body>> {
    if let Some(id) = session.bucket_ids.lock().unwrap().get(bucket) {
        return Ok(id.clone());
    }
    let json = serde_json::json!({"accountId": session.account_id, "bucketName": bucket});
    let v = account_call(vault, http, service, session, "b2_list_buckets", json).await?;
    let id = v["buckets"]
        .as_array()
        .and_then(|b| b.iter().find(|x| x["bucketName"].as_str() == Some(bucket)))
        .and_then(|x| x["bucketId"].as_str())
        .filter(|id| !id.is_empty() && id.bytes().all(|c| c.is_ascii_alphanumeric()));
    let Some(id) = id else {
        return Err(reply(
            StatusCode::NOT_FOUND,
            &format!("no bucket {bucket:?} in this account"),
        ));
    };
    session
        .bucket_ids
        .lock()
        .unwrap()
        .insert(bucket.to_string(), id.to_string());
    Ok(id.to_string())
}

/// Why there's no upload URL: B2 doesn't know the bucket id (deleted or recreated since it was looked up), or
/// another reply to send.
enum UrlError {
    BadBucket,
    Reply(Response<Body>),
}

/// An upload URL for the bucket for this upload alone: one from the pool, or a new one.
#[allow(clippy::result_large_err)]
async fn upload_url(
    vault: &Vault,
    http: &reqwest::Client,
    service: &str,
    session: &Arc<Session>,
    bucket_id: &str,
) -> Result<UploadUrl, UrlError> {
    {
        let mut pool = session.upload_urls.lock().unwrap();
        if let Some(i) = pool.iter().position(|u| u.bucket_id == bucket_id) {
            return Ok(pool.swap_remove(i));
        }
    }
    let json = serde_json::json!({ "bucketId": bucket_id });
    let res = post_account(vault, http, service, session, "b2_get_upload_url", &json)
        .await
        .map_err(UrlError::Reply)?;
    let ok = res.status().is_success();
    let b = read_buffered(res, &[session.token.as_bytes()], None)
        .await
        .map_err(UrlError::Reply)?;
    if !ok {
        if b.status == StatusCode::BAD_REQUEST && b2_code(&b).as_deref() == Some("bad_bucket_id") {
            return Err(UrlError::BadBucket);
        }
        return Err(UrlError::Reply(judge(vault, service, session, b)));
    }
    session.worked.store(true, Ordering::Relaxed);
    let bad = |what: &str| {
        UrlError::Reply(reply(
            StatusCode::BAD_GATEWAY,
            &format!("B2 b2_get_upload_url: {what}"),
        ))
    };
    let Ok(mut v) = serde_json::from_slice::<Value>(&b.body) else {
        return Err(bad("reply is not JSON"));
    };
    // taken out of the parsed reply, not copied (zeroed when the URL is dropped)
    let token = match v["authorizationToken"].take() {
        Value::String(t) => Zeroizing::new(t),
        _ => return Err(bad("no authorizationToken")),
    };
    if token.is_empty() || token.len() > 4096 || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(bad("bad authorizationToken"));
    }
    let b2 = vault.cfg.services[service].b2.as_ref().expect("b2 service");
    let local = b2.authorize_url.starts_with("http://");
    let url = check_upload_url(v["uploadUrl"].as_str().unwrap_or(""), local)
        .map_err(|e| bad(&format!("uploadUrl {e}")))?;
    Ok(UploadUrl {
        bucket_id: bucket_id.to_string(),
        url,
        token,
    })
}

/// The one value of client header `n`, if any: given twice or not ASCII is a 400.
#[allow(clippy::result_large_err)]
fn one_header<'a>(h: &'a hyper::HeaderMap, n: &str) -> Result<Option<&'a str>, Response<Body>> {
    let mut values = h.get_all(n).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(reply(
            StatusCode::BAD_REQUEST,
            &format!("header {n} given twice"),
        ));
    }
    first.map(|v| v.to_str()).transpose().map_err(|_| {
        reply(
            StatusCode::BAD_REQUEST,
            &format!("header {n}: only ASCII values"),
        )
    })
}

/// PUT <prefix>/<bucket>/<file name>: every check first (no Touch ID for a refused upload), then the session, the
/// bucket's id and an upload URL (credproxy's own calls), then the body streams to B2. A failed upload isn't
/// replayed (the body went by): the reply says whether the client should retry.
#[allow(clippy::too_many_arguments)]
async fn upload(
    vault: &Arc<Vault>,
    http: &Clients,
    service: &str,
    method: &str,
    prefix: &str,
    sub: &str,
    req: Request<Incoming>,
    progress: &Arc<Progress>,
) -> Response<Body> {
    macro_rules! or_reply {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(r) => return r,
            }
        };
    }
    if method != "PUT" {
        return reply(
            StatusCode::FORBIDDEN,
            &format!("{method} not allowed on uploads (PUT)"),
        );
    }
    if req.uri().query().is_some() {
        return reply(StatusCode::FORBIDDEN, "no query string on uploads");
    }
    let (bucket, name) = or_reply!(bucket_and_name(sub));
    let h = req.headers();
    // a header that selects something else (SSE, retention, other file info) is refused, not dropped
    if let Some(n) = h.keys().map(|n| n.as_str()).find(|n| {
        UPLOAD_REFUSED_HEADERS.contains(n)
            || (n.starts_with("x-bz-")
                && *n != "x-bz-content-sha1"
                && *n != "x-bz-info-src_last_modified_millis")
    }) {
        return reply(
            StatusCode::FORBIDDEN,
            &format!("header {n} not allowed on uploads"),
        );
    }
    let Some(length) = or_reply!(one_header(h, "content-length")) else {
        return reply(
            StatusCode::LENGTH_REQUIRED,
            "content-length required (B2 takes no chunked bodies)",
        );
    };
    let Ok(length) = length.parse::<u64>() else {
        return reply(StatusCode::BAD_REQUEST, "bad content-length");
    };
    let sha1 = match or_reply!(one_header(h, "x-bz-content-sha1")) {
        Some(v) if v.len() == 40 && v.bytes().all(|b| b.is_ascii_hexdigit()) => {
            v.to_ascii_lowercase()
        }
        _ => {
            return reply(
                StatusCode::BAD_REQUEST,
                "x-bz-content-sha1 must be the body's SHA-1 (40 hex digits)",
            );
        }
    };
    let ctype = match or_reply!(one_header(h, "content-type")) {
        None => "b2/x-auto".to_string(),
        Some(v) if !v.is_empty() && v.bytes().all(|b| (0x20..=0x7e).contains(&b)) => v.to_string(),
        Some(_) => return reply(StatusCode::BAD_REQUEST, "bad content-type"),
    };
    let mtime = match or_reply!(one_header(h, "x-bz-info-src_last_modified_millis")) {
        None => None,
        Some(v) if !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()) => {
            Some(v.to_string())
        }
        Some(_) => {
            return reply(
                StatusCode::BAD_REQUEST,
                "x-bz-info-src_last_modified_millis: milliseconds since the epoch",
            );
        }
    };
    // allowed: the watchdog decides from now on; a Touch ID prompt and credproxy's own two calls are expected
    // silence
    let what = format!("{service} {method} {prefix}{}", log::printable(sub));
    progress.mark_streaming(what);
    progress.quiet_for(unlock_wait());
    let session = match vault.b2(service).await {
        Ok(s) => s,
        Err(e) => return reply(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    let (idle, connect) = (vault.cfg.s3_idle, vault.cfg.s3_connect_timeout);
    // a cached id B2 no longer knows (the bucket was deleted, maybe recreated): forget it and look it up again,
    // once
    let mut looked_again = false;
    let up = loop {
        // each of credproxy's own calls (up to four here) is expected silence
        progress.quiet_for(UPSTREAM_TIMEOUT + idle);
        let id = or_reply!(bucket_id(vault, &http.api, service, &session, bucket).await);
        progress.quiet_for(UPSTREAM_TIMEOUT + idle);
        match upload_url(vault, &http.api, service, &session, &id).await {
            Ok(u) => break u,
            Err(UrlError::BadBucket) if !looked_again => {
                session.forget_bucket(&id);
                looked_again = true;
            }
            Err(UrlError::BadBucket) => {
                session.forget_bucket(&id);
                return reply(
                    StatusCode::NOT_FOUND,
                    &format!("no bucket {bucket:?} in this account (B2: bad_bucket_id)"),
                );
            }
            Err(UrlError::Reply(r)) => return r,
        }
    };
    progress.quiet_for(connect + idle);
    let Ok(mut auth) = reqwest::header::HeaderValue::from_str(&up.token) else {
        return reply(StatusCode::INTERNAL_SERVER_ERROR, "bad upload token");
    };
    auth.set_sensitive(true);
    let mut out = http
        .s3
        .post(&up.url)
        .header("authorization", auth)
        .header("x-bz-file-name", encode_name(&name))
        .header("content-type", ctype)
        .header("x-bz-content-sha1", sha1)
        .header("accept-encoding", "identity");
    if let Some(m) = mtime {
        out = out.header("x-bz-info-src_last_modified_millis", m);
    }
    let body = Outgoing::Stream(req.into_body(), length);
    // the upload URL (`up`) goes back to the pool only after a success; on every other path it's dropped
    let res = match send_watched(out, body, progress, vault.cfg.s3_reply_wait, idle).await {
        Ok(r) => r,
        Err(NotDone {
            sent: true,
            error: Some(e),
        }) if !e.is_connect() => {
            return reply(
                StatusCode::BAD_GATEWAY,
                &format!("upload broke off after the body was sent: {UPLOAD_OUTCOME_UNKNOWN}"),
            );
        }
        Err(NotDone { error: Some(_), .. }) => {
            return reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "upload not stored (it broke off before the body was sent): retry",
            );
        }
        Err(NotDone { error: None, .. }) => {
            return reply(
                StatusCode::GATEWAY_TIMEOUT,
                &format!("B2 sent no reply in time (s3_reply_wait): {UPLOAD_OUTCOME_UNKNOWN}"),
            );
        }
    };
    progress.touch();
    let b = or_reply!(
        read_buffered(
            res,
            &[session.token.as_bytes(), up.token.as_bytes()],
            Some(progress)
        )
        .await
    );
    if b.status.is_success() {
        session.worked.store(true, Ordering::Relaxed);
        // back to the pool, unless its bucket was forgotten (deleted) while this upload ran
        let known = session
            .bucket_ids
            .lock()
            .unwrap()
            .values()
            .any(|id| *id == up.bucket_id);
        if known {
            session.upload_urls.lock().unwrap().push(up);
        }
        return b.into_response();
    }
    // B2 refused the upload, so nothing was stored; for these B2 says to get a new upload URL and try again
    let code = b2_code(&b);
    let retry = match b.status.as_u16() {
        // the pooled URL's bucket is gone (deleted, maybe recreated): the retry looks it up again
        400 if code.as_deref() == Some("bad_bucket_id") => {
            session.forget_bucket(&up.bucket_id);
            true
        }
        401 => code.as_deref() != Some("unauthorized"),
        408 | 429 | 500..=599 => true,
        _ => false,
    };
    if retry {
        let mut r = reply(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!(
                "upload not stored (B2: {} {}): retry (with a new upload URL)",
                b.status.as_u16(),
                code.as_deref().unwrap_or("-")
            ),
        );
        if let Some(v) = b.retry_after {
            r.headers_mut().insert("retry-after", v);
        }
        return r;
    }
    b.into_response()
}

/// How a client finds out whether a broken-off upload was stored.
const UPLOAD_OUTCOME_UNKNOWN: &str = "the outcome is unknown; check with b2_list_file_names (contentSha1) before \
     uploading again (another upload of the same name only adds a version)";

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
    fn upload_urls() {
        for ok in [
            "https://pod-000-1007-13.backblaze.com/b2api/v4/b2_upload_file/bid/c001",
            "https://pod-1.backblazeb2.com/b2api/v3/b2_upload_file/x",
        ] {
            assert!(check_upload_url(ok, false).is_ok(), "{ok}");
        }
        for bad in [
            "http://pod-1.backblaze.com/x",
            "https://pod-1.backblaze.com.evil.example/x",
            "https://evilbackblaze.com/x",
            "https://pod-1.backblaze.com/x?y",
            "https://u@pod-1.backblaze.com/x",
            "http://127.0.0.1:9/upload/0",
            "",
        ] {
            assert!(check_upload_url(bad, false).is_err(), "{bad}");
        }
        assert!(check_upload_url("http://127.0.0.1:9/upload/0", true).is_ok());
        assert!(check_upload_url("https://pod-1.backblaze.com/x", true).is_err());
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
