//! End to end for B2 services: real daemon, real `age` with a throwaway identity, a fake key pair, a fake B2
//! (authorize, API calls, downloads) on 127.0.0.1.

use bytes::Bytes;
use http_body_util::{BodyExt, Either, Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod common;
use common::{BIN, age_identity, free_port, seal, sh, start_daemon};

/// What the fake B2 saw and how it behaves.
#[derive(Default)]
struct B2State {
    /// "Basic <base64 of id:secret>" it accepts
    basic: String,
    authorizes: usize,
    /// API and download requests that reached it
    hits: usize,
    /// the token handed out by the last authorize
    token: String,
    /// answer every call with 401 expired_auth_token
    expire: bool,
    /// answer every call with this 401 instead: Some(None) = plain text, Some(Some(code)) = B2 JSON with `code`
    other_401: Option<Option<&'static str>>,
    /// answer this many authorize calls with 503 first
    authorize_fail: usize,
    /// answer this many API calls with a front end's 503 (no B2 JSON) first
    call_fail: usize,
    /// b2_list_buckets calls that named a bucket (credproxy's own lookups)
    list_lookups: usize,
    /// upload tokens handed out by b2_get_upload_url (the URL /upload/<index> goes with each)
    upload_tokens: Vec<String>,
    /// the bucket id each of those URLs is for
    upload_buckets: Vec<String>,
    /// bumped when a bucket is "recreated": its id changes, old ids get 400 bad_bucket_id
    bucket_gen: usize,
    /// drop the connection after reading an upload's body, without replying
    drop_after_body: bool,
    /// refuse b2_delete_bucket (as B2 does for a bucket that still has files)
    delete_fail: bool,
    /// answer the next upload with this status and B2 code
    upload_fail: Option<(u16, &'static str)>,
    /// wait before answering an upload
    upload_delay: Duration,
    /// the last stored upload: X-Bz-File-Name, Content-Type, src_last_modified_millis, length, SHA-1 of the body
    stored: Option<(String, String, Option<String>, usize, String)>,
    /// authorize calls received, failed ones included
    authorize_tries: usize,
    /// wait before answering an authorize call
    authorize_delay: Duration,
    /// apiUrl to hand out instead of its own
    api_url: Option<String>,
    /// the last call: path, Authorization, body, Range
    last: Option<(String, Option<String>, String, Option<String>)>,
}

fn rnd(prefix: &str) -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).unwrap();
    format!(
        "{prefix}{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// SHA-1 of `b` in hex, by the system's shasum.
fn sha1_hex(b: &[u8]) -> String {
    let mut c = Command::new("shasum")
        .args(["-a", "1"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    let data = b.to_vec();
    let w = std::thread::spawn(move || std::io::Write::write_all(&mut stdin, &data).unwrap());
    let out = c.wait_with_output().unwrap();
    w.join().unwrap();
    String::from_utf8(out.stdout).unwrap()[..40].to_string()
}

fn json_reply(status: u16, v: Value) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(v.to_string())))
        .unwrap()
}

type Slow = StreamBody<
    std::pin::Pin<
        Box<dyn futures_util::Stream<Item = Result<Frame<Bytes>, std::convert::Infallible>> + Send>,
    >,
>;

/// A 404 whose body comes in five pieces, 0.5 s apart.
fn slow_404() -> hyper::Response<Either<Full<Bytes>, Slow>> {
    let pieces = futures_util::stream::unfold(0, |i| async move {
        if i == 5 {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        Some((Ok(Frame::data(Bytes::from_static(b"missing "))), i + 1))
    });
    hyper::Response::builder()
        .status(404)
        .header("content-type", "text/plain")
        .body(Either::Right(StreamBody::new(Box::pin(pieces) as _)))
        .unwrap()
}

async fn fake_b2(state: Arc<Mutex<B2State>>) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (c, _) = l.accept().await.unwrap();
            let state = state.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let state = state.clone();
                    async move {
                        if req.uri().path().ends_with("/slow-404") {
                            return Ok::<_, std::convert::Infallible>(slow_404());
                        }
                        let r: Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> = async move {
                        let h = |n: &str| {
                            req.headers()
                                .get(n)
                                .map(|v| v.to_str().unwrap().to_string())
                        };
                        let (auth, range) = (h("authorization"), h("range"));
                        let upload_headers = (
                            h("x-bz-file-name").unwrap_or_default(),
                            h("content-type").unwrap_or_default(),
                            h("x-bz-info-src_last_modified_millis"),
                            h("x-bz-content-sha1").unwrap_or_default(),
                        );
                        let method = req.method().to_string();
                        let path = req.uri().path().to_string();
                        let raw = req.into_body().collect().await.unwrap().to_bytes();
                        let body = String::from_utf8_lossy(&raw).to_string();
                        let up_delay = state.lock().unwrap().upload_delay;
                        if path.starts_with("/upload/") && !up_delay.is_zero() {
                            tokio::time::sleep(up_delay).await;
                        }
                        let delay = state.lock().unwrap().authorize_delay;
                        let authorize = path.ends_with("/b2_authorize_account");
                        if authorize && !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        let mut s = state.lock().unwrap();
                        if authorize {
                            s.authorize_tries += 1;
                            if s.authorize_fail > 0 {
                                s.authorize_fail -= 1;
                                return Ok::<_, std::convert::Infallible>(json_reply(
                                    503,
                                    json!({"status": 503, "code": "service_unavailable", "message": "busy"}),
                                ));
                            }
                            if auth.as_deref() != Some(s.basic.as_str()) {
                                return Ok::<_, std::convert::Infallible>(json_reply(
                                    401,
                                    json!({"status": 401, "code": "unauthorized", "message": "bad key"}),
                                ));
                            }
                            s.authorizes += 1;
                            s.token = rnd("4_tok_");
                            let me = format!("http://127.0.0.1:{port}");
                            return Ok(json_reply(
                                200,
                                json!({
                                    "accountId": "acc123", "authorizationToken": s.token,
                                    "apiInfo": {"storageApi": {"apiUrl": s.api_url.clone().unwrap_or(me.clone()), "downloadUrl": me}},
                                }),
                            ));
                        }
                        s.hits += 1;
                        s.last = Some((path.clone(), auth.clone(), body.clone(), range.clone()));
                        if let Some(i) = path.strip_prefix("/upload/") {
                            let i: usize = i.parse().unwrap();
                            if auth.as_deref() != s.upload_tokens.get(i).map(String::as_str) {
                                return Ok(json_reply(401, json!({"status": 401, "code": "bad_auth_token", "message": "upload token"})));
                            }
                            if s.drop_after_body {
                                drop(s);
                                std::panic::resume_unwind(Box::new("drop the connection"));
                            }
                            let current = format!("bid{}g{}", "mybkt", s.bucket_gen);
                            if s.upload_buckets[i].starts_with("bidmybkt") && s.upload_buckets[i] != current {
                                return Ok(json_reply(400, json!({"status": 400, "code": "bad_bucket_id", "message": "bucket"})));
                            }
                            if let Some((status, code)) = s.upload_fail.take() {
                                return Ok(json_reply(status, json!({"status": status, "code": code, "message": "refused"})));
                            }
                            let (name, ctype, mtime, sha_header) = upload_headers;
                            let sha = sha1_hex(&raw);
                            if sha != sha_header {
                                return Ok(json_reply(400, json!({"status": 400, "code": "bad_request", "message": "Sha1 did not match data received"})));
                            }
                            s.stored = Some((name.clone(), ctype, mtime, raw.len(), sha.clone()));
                            return Ok(json_reply(
                                200,
                                json!({"fileId": "4_zf1", "fileName": name, "contentLength": raw.len(), "contentSha1": sha,
                                       "echo": [s.token.clone(), s.upload_tokens[i].clone()]}),
                            ));
                        }
                        if s.expire {
                            return Ok(json_reply(
                                401,
                                json!({"status": 401, "code": "expired_auth_token", "message": "expired"}),
                            ));
                        }
                        if s.call_fail > 0 {
                            s.call_fail -= 1;
                            return Ok(hyper::Response::builder()
                                .status(503)
                                .body(Full::new(Bytes::from("<html>busy</html>")))
                                .unwrap());
                        }
                        match s.other_401 {
                            Some(None) => {
                                return Ok(hyper::Response::builder()
                                    .status(401)
                                    .header("content-type", "text/html")
                                    .body(Full::new(Bytes::from("<html>401</html>")))
                                    .unwrap());
                            }
                            Some(Some(code)) => {
                                let mut r = json_reply(
                                    401,
                                    json!({"status": 401, "code": code, "message": "no"}),
                                );
                                r.headers_mut().insert("retry-after", "7".parse().unwrap());
                                return Ok(r);
                            }
                            None => {}
                        }
                        if auth.as_deref() != Some(s.token.as_str()) {
                            return Ok(json_reply(
                                401,
                                json!({"status": 401, "code": "bad_auth_token", "message": "bad"}),
                            ));
                        }
                        if let Some(call) = path
                            .strip_prefix("/b2api/")
                            .and_then(|p| p.split_once('/'))
                            .map(|(_, c)| c)
                        {
                            let mut v = json!({"call": call, "got": serde_json::from_str::<Value>(&body).unwrap_or(Value::Null), "echo": s.token});
                            if call == "b2_create_key" {
                                v["applicationKey"] = json!("K005NEWKEYSECRET");
                            }
                            if let Some(name) = v["got"]["bucketName"].as_str().map(str::to_string) {
                                s.list_lookups += 1;
                                let buckets = if name == "missing" {
                                    json!([])
                                } else {
                                    json!([{"bucketId": format!("bid{}g{}", name.replace('-', ""), s.bucket_gen), "bucketName": name}])
                                };
                                return Ok(json_reply(200, json!({ "buckets": buckets })));
                            }
                            if call == "b2_delete_bucket" && s.delete_fail {
                                return Ok(json_reply(400, json!({"status": 400, "code": "cannot_delete_non_empty_bucket", "message": "not empty"})));
                            }
                            if call == "b2_get_upload_url" {
                                let id = v["got"]["bucketId"].as_str().unwrap_or("").to_string();
                                if id.starts_with("bidmybkt") && id != format!("bidmybktg{}", s.bucket_gen) {
                                    return Ok(json_reply(400, json!({"status": 400, "code": "bad_bucket_id", "message": "bucket"})));
                                }
                                s.upload_buckets.push(id);
                                let i = s.upload_tokens.len();
                                let tok = rnd("up_tok_");
                                s.upload_tokens.push(tok.clone());
                                return Ok(json_reply(
                                    200,
                                    json!({"bucketId": v["got"]["bucketId"], "uploadUrl": format!("http://127.0.0.1:{port}/upload/{i}"), "authorizationToken": tok}),
                                ));
                            }
                            if call == "b2_list_keys" {
                                return Ok(json_reply(
                                    400,
                                    json!({"status": 400, "code": "bad_request", "message": format!("token {}", s.token)}),
                                ));
                            }
                            return Ok(json_reply(200, v));
                        }
                        let content = format!("contents of {path}");
                        let mut b = hyper::Response::builder()
                            .header("content-type", "application/octet-stream")
                            .header("x-bz-file-name", "runs%2Fa%20b.txt")
                            .header("x-bz-info-src_last_modified_millis", "1")
                            .header("x-other", "dropped")
                            .header("x-bz-content-sha1", s.token.clone());
                        let data = match range.as_deref() {
                            Some("bytes=0-3") => {
                                b = b.status(206).header(
                                    "content-range",
                                    format!("bytes 0-3/{}", content.len()),
                                );
                                content[..4].to_string()
                            }
                            _ => content,
                        };
                        let data = if method == "HEAD" {
                            String::new()
                        } else {
                            data
                        };
                        Ok(b.body(Full::new(Bytes::from(data))).unwrap())
                        }
                        .await;
                        r.map(|r| r.map(Either::Left))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(c), svc)
                    .await;
            });
        }
    });
    port
}

struct Env {
    dir: tempfile::TempDir,
    cfg: PathBuf,
    base: String,
    /// the API version in call paths
    version: String,
    secret: String,
    state: Arc<Mutex<B2State>>,
    daemon: Option<Child>,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.cli(&["stop"]);
        if let Some(mut d) = self.daemon.take() {
            let _ = d.wait();
        }
    }
}

async fn setup(relock: &str) -> Env {
    setup_with(relock, "", None).await
}

/// `top`: extra top-level config lines; `age_delay`: seconds `age` takes before decrypting (a slow Touch ID).
async fn setup_with(relock: &str, top: &str, age_delay: Option<u32>) -> Env {
    setup_version(relock, top, age_delay, "v3").await
}

async fn setup_version(relock: &str, top: &str, age_delay: Option<u32>, version: &str) -> Env {
    let dir = tempfile::Builder::new().prefix("cp").tempdir().unwrap();
    let d = dir.path();
    let state = Arc::new(Mutex::new(B2State::default()));
    let port = fake_b2(state.clone()).await;
    let listen = free_port();
    let (id, secret) = (rnd("005kid"), rnd("K005sec"));
    let basic = sh(Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("printf %s '{id}:{secret}' | base64")))
    .stdout;
    state.lock().unwrap().basic = format!("Basic {}", String::from_utf8(basic).unwrap().trim());
    let public = age_identity(d);
    seal(
        &public,
        d.join("secrets/backblaze/master.age"),
        &format!("{id}\n{secret}\n"),
    );
    let age_line = match age_delay {
        Some(secs) => {
            let p = d.join("slow-age");
            let age = String::from_utf8(
                sh(Command::new("/bin/sh").args(["-c", "command -v age"])).stdout,
            )
            .unwrap();
            std::fs::write(
                &p,
                format!("#!/bin/sh\nsleep {secs}\nexec {} \"$@\"\n", age.trim()),
            )
            .unwrap();
            std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
            format!("age = \"{}\"\n", p.display())
        }
        None => String::new(),
    };
    let cfg = d.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"{top}
{age_line}listen = "127.0.0.1:{listen}"
identity = "{d}/id.txt"
secrets_dir = "{d}/secrets"
runtime_dir = "{d}/run"
log = "{d}/credproxy.log"

[services.b2]
secret = "backblaze/master"
auth = {{ b2 = {{ version = "{version}", relock_after = "{relock}", authorize_url = "http://127.0.0.1:{port}/b2api/{version}/b2_authorize_account" }} }}

[[services.b2.routes]]
prefix = "/b2api/{version}"
b2 = {{ calls = ["b2_list_buckets", "b2_create_key", "b2_list_keys", "b2_list_file_names", "b2_delete_bucket"] }}

[[services.b2.routes]]
prefix = "/file"
b2 = {{ download = true }}

[[services.b2.routes]]
prefix = "/upload"
b2 = {{ upload = true }}
"#,
            d = d.display(),
        ),
    )
    .unwrap();
    let daemon = start_daemon(&cfg).await;
    Env {
        dir,
        cfg,
        base: format!("http://127.0.0.1:{listen}/b2"),
        version: version.to_string(),
        secret,
        state,
        daemon: Some(daemon),
    }
}

impl Env {
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .env("CREDPROXY_CONFIG", &self.cfg)
            .output()
            .unwrap()
    }

    fn token(&self) -> String {
        String::from_utf8(
            sh(Command::new(BIN)
                .args(["token", "b2"])
                .env("CREDPROXY_CONFIG", &self.cfg))
            .stdout,
        )
        .unwrap()
        .trim()
        .to_string()
    }

    fn status(&self) -> String {
        String::from_utf8_lossy(&self.cli(&["status"]).stdout).to_string()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("credproxy.log")).unwrap_or_default()
    }

    async fn call(&self, call: &str, body: &str) -> (u16, String) {
        let r = reqwest::Client::new()
            .post(format!("{}/b2api/{}/{call}", self.base, self.version))
            .header("authorization", format!("Bearer {}", self.token()))
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }

    fn st<T>(&self, f: impl FnOnce(&mut B2State) -> T) -> T {
        f(&mut self.state.lock().unwrap())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn api_calls_carry_the_b2_token_only() {
    let env = setup("23h").await;
    let tok = env.token();
    let (code, body) = env.call("b2_list_buckets", "").await;
    assert_eq!(code, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    // the account is filled in; the token went upstream and is scrubbed from the reply
    assert_eq!(v["got"], json!({"accountId": "acc123"}));
    assert_eq!(v["echo"], "[REDACTED]");
    let b2_token = env.st(|s| s.token.clone());
    let (path, auth, _, _) = env.st(|s| s.last.clone()).unwrap();
    assert_eq!(path, "/b2api/v3/b2_list_buckets");
    assert_eq!(auth.as_deref(), Some(b2_token.as_str()));
    assert!(!body.contains(&b2_token) && !body.contains(&tok) && !body.contains(&env.secret));

    // a second call reuses the session: one authorize per unlock
    let (code, body) = env
        .call(
            "b2_list_file_names",
            r#"{"bucketId": "b1", "prefix": "runs/"}"#,
        )
        .await;
    assert_eq!(code, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["got"],
        json!({"bucketId": "b1", "prefix": "runs/"}),
        "no accountId where none belongs"
    );
    assert_eq!(env.st(|s| s.authorizes), 1);

    // a client's own accountId, even the right one, is refused before it goes out
    let hits = env.st(|s| s.hits);
    for id in [r#"{"accountId": "acc123"}"#, r#"{"accountId": "other"}"#] {
        let (code, body) = env.call("b2_list_buckets", id).await;
        assert_eq!(
            (code, body.contains("leave accountId out")),
            (403, true),
            "{body}"
        );
    }
    assert_eq!(env.call("b2_list_buckets", "[1]").await.0, 400);
    assert_eq!(env.call("b2_list_buckets", "nope").await.0, 400);
    assert_eq!(env.st(|s| s.hits), hits);

    // b2_create_key: the new key comes back to the client, but never into the log
    let (code, body) = env
        .call(
            "b2_create_key",
            r#"{"keyName": "vast", "capabilities": ["readFiles"]}"#,
        )
        .await;
    assert_eq!(code, 200);
    assert!(body.contains("K005NEWKEYSECRET"));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["got"]["accountId"],
        "acc123"
    );
    // error replies are scrubbed too
    let (code, body) = env.call("b2_list_keys", "{}").await;
    assert_eq!(code, 400);
    assert!(
        body.contains("token [REDACTED]") && !body.contains(&b2_token),
        "{body}"
    );
    let log = env.log();
    for secret in [
        "K005NEWKEYSECRET",
        b2_token.as_str(),
        env.secret.as_str(),
        tok.as_str(),
    ] {
        assert!(!log.contains(secret), "log has a secret:\n{log}");
    }
    assert!(log.contains("b2 POST /b2api/v3/b2_create_key 200"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_calls_never_unlock_or_reach_b2() {
    let env = setup("23h").await;
    let tok = env.token();
    let c = reqwest::Client::new();
    let send = |m: reqwest::Method, path: &str| {
        c.request(m, format!("{}{path}", env.base))
            .header("authorization", format!("Bearer {tok}"))
            .send()
    };
    use reqwest::Method;
    for (m, p, code) in [
        (Method::POST, "/b2api/v3/b2_list_file_versions", 403),
        (Method::POST, "/b2api/v3/b2_authorize_account", 403),
        (Method::POST, "/b2api/v3/b2_get_upload_url", 403),
        (Method::POST, "/b2api/v3/", 403),
        (Method::POST, "/b2api/v3/b2_list_buckets/x", 403),
        (Method::GET, "/b2api/v3/b2_list_buckets", 403),
        (Method::POST, "/b2api/v3/b2_list_buckets?accountId=x", 403),
        (Method::POST, "/b2api/v2/b2_list_buckets", 403),
        (Method::GET, "/file/bkt/a.txt?Authorization=x", 403),
        (Method::PUT, "/file/bkt/a.txt", 403),
        (Method::GET, "/file/bkt", 403),
        (Method::GET, "/file/bkt/", 403),
        (Method::GET, "/file/bkt/a//b", 403),
        (Method::GET, "/file/bkt/a%00b", 403),
        (Method::GET, "/file/b_kt/a", 403),
    ] {
        let r = send(m.clone(), p).await.unwrap();
        assert_eq!(
            r.status().as_u16(),
            code,
            "{m} {p}: {}",
            r.text().await.unwrap()
        );
    }
    // dot segments, sent as they are (an HTTP client's URL parser would resolve them first)
    let addr = env
        .base
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap()
        .to_string();
    for p in [
        "/b2/file/bkt/a/../b",
        "/b2/file/bkt/a/%2e%2e/b",
        "/b2/file/bkt/./b",
    ] {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
        s.write_all(
            format!("GET {p} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {tok}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 403"), "{p}: {out}");
    }
    // a body naming the account is refused before unlocking: no prompt for a call that would be refused
    let (code, _) = env
        .call("b2_create_key", r#"{"accountId": "acc123"}"#)
        .await;
    assert_eq!(code, 403);
    assert_eq!(env.st(|s| (s.authorizes, s.hits)), (0, 0));
    assert!(env.status().contains("b2: locked"), "{}", env.status());
    // a wrong credproxy token: 401
    let r = c
        .post(format!("{}/b2api/v3/b2_list_buckets", env.base))
        .header("authorization", format!("Bearer {}", env.secret))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_token_locks_and_the_retry_unlocks_again() {
    let env = setup("23h").await;
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 200);
    assert!(env.status().contains("b2: unlocked"));
    env.st(|s| s.expire = true);
    let (code, body) = env.call("b2_list_buckets", "{}").await;
    assert_eq!(code, 503);
    assert!(body.contains("retry"), "{body}");
    assert!(env.status().contains("b2: locked"), "{}", env.status());
    assert!(env.log().contains("b2 locked (B2 token no longer valid)"));
    env.st(|s| s.expire = false);
    let (code, body) = env.call("b2_list_buckets", "{}").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(env.st(|s| s.authorizes), 2);

    // a token B2 calls bad (e.g. the key was deleted) does the same
    env.st(|s| s.token = "revoked".into());
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 503);
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 200);
    assert_eq!(env.st(|s| s.authorizes), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_ends_after_relock_after() {
    let env = setup("2s").await;
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 200);
    let status = env.status();
    assert!(status.contains("b2: unlocked, locks in 0h00m"), "{status}");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(env.status().contains("b2: locked"), "{}", env.status());
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 200);
    assert_eq!(env.st(|s| s.authorizes), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn downloads_stream_with_b2_headers_only() {
    let env = setup("23h").await;
    let tok = env.token();
    let c = reqwest::Client::new();
    let r = c
        .get(format!("{}/file/my-bkt/runs/a%20b.txt", env.base))
        .header("authorization", format!("Bearer {tok}"))
        .header("cookie", "leak")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let h = r.headers().clone();
    assert_eq!(h["x-bz-file-name"], "runs%2Fa%20b.txt");
    assert_eq!(h["x-bz-info-src_last_modified_millis"], "1");
    assert!(h.get("x-other").is_none());
    assert!(
        h.get("x-bz-content-sha1").is_none(),
        "a header holding the token is dropped"
    );
    assert_eq!(
        r.text().await.unwrap(),
        "contents of /file/my-bkt/runs/a%20b.txt"
    );
    let b2_token = env.st(|s| s.token.clone());
    let (_, auth, _, _) = env.st(|s| s.last.clone()).unwrap();
    assert_eq!(auth.as_deref(), Some(b2_token.as_str()));

    let r = c
        .get(format!("{}/file/my-bkt/x.bin", env.base))
        .header("authorization", format!("Bearer {tok}"))
        .header("range", "bytes=0-3")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 206);
    assert!(
        r.headers()["content-range"]
            .to_str()
            .unwrap()
            .starts_with("bytes 0-3/")
    );
    assert_eq!(r.text().await.unwrap(), "cont");
    assert_eq!(
        env.st(|s| s.last.clone()).unwrap().3.as_deref(),
        Some("bytes=0-3")
    );

    let r = c
        .head(format!("{}/file/my-bkt/x.bin", env.base))
        .header("authorization", format!("Bearer {tok}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(env.st(|s| s.authorizes), 1);

    // an expired token on a download locks too
    env.st(|s| s.expire = true);
    let r = c
        .get(format!("{}/file/my-bkt/x.bin", env.base))
        .header("authorization", format!("Bearer {tok}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 503);
    assert!(env.status().contains("b2: locked"));
    // a HEAD's 401 has no body to say why: taken as the end of a token that has worked
    env.st(|s| s.expire = false);
    let head = |env: &Env| {
        reqwest::Client::new()
            .head(format!("{}/file/my-bkt/x.bin", env.base))
            .header("authorization", format!("Bearer {}", env.token()))
            .send()
    };
    assert_eq!(head(&env).await.unwrap().status().as_u16(), 200);
    env.st(|s| s.expire = true);
    assert_eq!(head(&env).await.unwrap().status().as_u16(), 503);
    assert_eq!(env.st(|s| s.authorizes), 2);
    assert!(env.status().contains("b2: locked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_authorize_replies_fail_the_unlock() {
    let env = setup("23h").await;
    env.st(|s| s.api_url = Some("http://evil.example".into()));
    let (code, body) = env.call("b2_list_buckets", "{}").await;
    assert_eq!(code, 503);
    assert!(
        body.contains("apiUrl") && body.contains("evil.example"),
        "{body}"
    );
    assert_eq!(env.st(|s| s.hits), 0);
    assert!(env.status().contains("b2: locked"));

    // a wrong key: B2's own error, and nothing else reaches it
    env.st(|s| {
        s.api_url = None;
        s.basic = "Basic other".into();
    });
    let err = String::from_utf8_lossy(&env.cli(&["unlock", "b2"]).stderr).to_string();
    assert!(
        err.contains("B2 authorize failed: 401 unauthorized: bad key"),
        "{err}"
    );
    assert_eq!(env.st(|s| s.hits), 0);
    assert!(!env.log().contains(&env.secret));
}

#[tokio::test(flavor = "multi_thread")]
async fn authorize_is_retried_while_the_key_is_held() {
    let env = setup("23h").await;
    env.st(|s| s.authorize_fail = 2);
    let (code, body) = env.call("b2_list_buckets", "{}").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(env.st(|s| (s.authorize_tries, s.authorizes)), (3, 1));

    // three failures: the unlock fails with B2's own words, and stops there
    let env = setup("23h").await;
    env.st(|s| s.authorize_fail = 5);
    let (code, body) = env.call("b2_list_buckets", "{}").await;
    assert_eq!(code, 503);
    assert!(body.contains("503 service_unavailable: busy"), "{body}");
    assert_eq!(env.st(|s| (s.authorize_tries, s.hits)), (3, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_401_ends_the_token_unless_b2_says_unauthorized() {
    let env = setup("23h").await;
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 200);
    // the token is good but may not do this: B2's reply as it is, Retry-After included; still unlocked
    env.st(|s| s.other_401 = Some(Some("unauthorized")));
    let r = reqwest::Client::new()
        .post(format!("{}/b2api/v3/b2_list_buckets", env.base))
        .header("authorization", format!("Bearer {}", env.token()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    assert_eq!(r.headers()["retry-after"], "7");
    assert!(r.text().await.unwrap().contains("\"unauthorized\""));
    assert!(env.status().contains("b2: unlocked"));
    // a 401 without B2's code (a front end's page) to a token that has worked: taken as its end
    env.st(|s| s.other_401 = Some(None));
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 503);
    assert!(env.status().contains("b2: locked"));
    // the retry unlocks; the same 401 to the new token, which never worked, is a refusal: 502, no unlock loop
    let (code, body) = env.call("b2_list_buckets", "{}").await;
    assert_eq!(code, 502, "{body}");
    assert!(env.status().contains("b2: unlocked"));
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 502);
    assert_eq!(env.st(|s| s.authorizes), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_download_waits_through_a_slow_unlock() {
    // s3_idle 1s: a watchdog that didn't count the unlock as expected silence would cut this
    let env = setup_with("23h", "s3_idle = \"1s\"", Some(2)).await;
    env.st(|s| {
        s.authorize_fail = 1;
        s.authorize_delay = Duration::from_millis(700);
    });
    let r = reqwest::Client::new()
        .get(format!("{}/file/my-bkt/x.bin", env.base))
        .header("authorization", format!("Bearer {}", env.token()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(r.text().await.unwrap(), "contents of /file/my-bkt/x.bin");
    assert!(!env.log().contains("cut off"), "{}", env.log());
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_stops_an_authorize_in_flight() {
    let env = setup("23h").await;
    env.st(|s| {
        s.authorize_fail = 10;
        s.authorize_delay = Duration::from_millis(500);
    });
    let base = env.base.clone();
    let tok = env.token();
    let call = tokio::spawn(async move {
        let r = reqwest::Client::new()
            .post(format!("{base}/b2api/v3/b2_list_buckets"))
            .header("authorization", format!("Bearer {tok}"))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    });
    // the first try is answered (503) at ~0.5 s; the second would go out at ~1.5 s
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let status = env.status();
    assert!(
        status.contains("b2: unlocking (Touch ID done; authorizing with B2)"),
        "{status}"
    );
    assert!(env.cli(&["lock", "b2"]).status.success());
    let (code, body) = call.await.unwrap();
    assert_eq!(code, 503);
    assert!(
        body.contains("locked while unlocking (authorizing with B2)"),
        "{body}"
    );
    let tries = env.st(|s| s.authorize_tries);
    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert_eq!(
        env.st(|s| s.authorize_tries),
        tries,
        "no try after the lock"
    );
    // (0 if the lock came while the first try was still in the fake's delay)
    assert!(tries <= 1, "{tries}");
    assert!(env.status().contains("b2: locked"));
    assert!(!env.log().contains("b2 unlocked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_front_end_5xx_doesnt_count_as_the_token_working() {
    let env = setup("23h").await;
    // the first call meets a front end's 503, the next a codeless 401: the token never got past B2's check
    env.st(|s| {
        s.call_fail = 1;
        s.other_401 = Some(None);
    });
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 503);
    assert!(env.status().contains("b2: unlocked"));
    let (code, body) = env.call("b2_list_buckets", "{}").await;
    assert_eq!(code, 502, "{body}");
    assert!(env.status().contains("b2: unlocked"));
    assert_eq!(env.st(|s| s.authorizes), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn version_v4_goes_out_as_v4() {
    let env = setup_version("23h", "", None, "v4").await;
    let (code, body) = env.call("b2_list_buckets", "{}").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        env.st(|s| s.last.clone()).unwrap().0,
        "/b2api/v4/b2_list_buckets"
    );
    // the v3 path isn't served by a v4 service
    let r = reqwest::Client::new()
        .post(format!("{}/b2api/v3/b2_list_buckets", env.base))
        .header("authorization", format!("Bearer {}", env.token()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_download_error_body_isnt_cut() {
    // s3_idle 1s, and the fake's 404 body takes 2.5 s in five pieces
    let env = setup_with("23h", "s3_idle = \"1s\"", None).await;
    let r = reqwest::Client::new()
        .get(format!("{}/file/my-bkt/slow-404", env.base))
        .header("authorization", format!("Bearer {}", env.token()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    assert_eq!(
        r.text().await.unwrap(),
        "missing missing missing missing missing "
    );
}

impl Env {
    async fn put(
        &self,
        path: &str,
        body: Vec<u8>,
        headers: Vec<(&'static str, String)>,
    ) -> (u16, String) {
        let mut r = reqwest::Client::new()
            .put(format!("{}/upload{path}", self.base))
            .header("authorization", format!("Bearer {}", self.token()));
        for (n, v) in headers {
            r = r.header(n, v);
        }
        let r = r.body(body).send().await.unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).unwrap();
    b
}

#[tokio::test(flavor = "multi_thread")]
async fn uploads_stream_to_b2_through_credproxys_own_upload_url() {
    let env = setup("23h").await;
    let body = random_bytes(20 << 20);
    let sha = sha1_hex(&body);
    let (code, reply) = env
        .put(
            "/my-bkt/sessions/s1/in/a%20b.bin",
            body.clone(),
            vec![("x-bz-content-sha1", sha.to_string())],
        )
        .await;
    assert_eq!(code, 200, "{reply}");
    let v: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(
        (v["contentLength"].as_u64(), v["contentSha1"].as_str()),
        (Some(body.len() as u64), Some(sha.as_str()))
    );
    // neither the account token nor the upload token comes back
    assert_eq!(v["echo"], json!(["[REDACTED]", "[REDACTED]"]));
    let (name, ctype, mtime, len, stored_sha) = env.st(|s| s.stored.clone()).unwrap();
    assert_eq!(
        (
            name.as_str(),
            ctype.as_str(),
            mtime,
            len,
            stored_sha.as_str()
        ),
        (
            "sessions/s1/in/a%20b.bin",
            "b2/x-auto",
            None,
            body.len(),
            sha.as_str()
        )
    );
    // a second upload reuses the bucket's id and the upload URL
    let small = b"hello".to_vec();
    let (code, reply) = env
        .put(
            "/my-bkt/sessions/s1/in/hello.txt",
            small.clone(),
            vec![
                ("x-bz-content-sha1", sha1_hex(&small).to_string()),
                ("content-type", "text/plain".to_string()),
                (
                    "x-bz-info-src_last_modified_millis",
                    "1700000000000".to_string(),
                ),
            ],
        )
        .await;
    assert_eq!(code, 200, "{reply}");
    let stored = env.st(|s| s.stored.clone()).unwrap();
    assert_eq!(
        (stored.1.as_str(), stored.2.as_deref()),
        ("text/plain", Some("1700000000000"))
    );
    assert_eq!(
        env.st(|s| (s.list_lookups, s.upload_tokens.len(), s.authorizes)),
        (1, 1, 1)
    );
    let log = env.log();
    let tokens = env.st(|s| (s.token.clone(), s.upload_tokens.clone()));
    for t in std::iter::once(&tokens.0).chain(&tokens.1) {
        assert!(!log.contains(t.as_str()), "{log}");
    }
    assert!(
        log.contains("b2 PUT /upload/my-bkt/sessions/s1/in/a%20b.bin 200"),
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_uploads_never_unlock_or_reach_b2() {
    let env = setup("23h").await;
    let sha = sha1_hex(b"x");
    let c = reqwest::Client::new();
    let tok = env.token();
    let send = |m: reqwest::Method, path: &str, headers: Vec<(&'static str, String)>| {
        let mut r = c
            .request(m, format!("{}/upload{path}", env.base))
            .header("authorization", format!("Bearer {tok}"))
            .body("x");
        for (n, v) in headers {
            r = r.header(n, v);
        }
        r.send()
    };
    use reqwest::Method;
    let s = || ("x-bz-content-sha1", sha.clone());
    for (m, p, headers, code) in [
        (Method::POST, "/bkt/a", vec![s()], 403),
        (Method::GET, "/bkt/a", vec![s()], 403),
        (Method::PUT, "/bkt/a?x=1", vec![s()], 403),
        (Method::PUT, "/bkt", vec![s()], 403),
        (Method::PUT, "/bkt/a//b", vec![s()], 403),
        (Method::PUT, "/bkt/a", vec![], 400),
        (
            Method::PUT,
            "/bkt/a",
            vec![("x-bz-content-sha1", "do_not_verify".into())],
            400,
        ),
        (
            Method::PUT,
            "/bkt/a",
            vec![("x-bz-content-sha1", "a".repeat(39))],
            400,
        ),
        (Method::PUT, "/bkt/a", vec![s(), s()], 400),
        (
            Method::PUT,
            "/bkt/a",
            vec![s(), ("x-bz-info-author", "me".into())],
            403,
        ),
        (
            Method::PUT,
            "/bkt/a",
            vec![s(), ("x-bz-server-side-encryption", "AES256".into())],
            403,
        ),
        (
            Method::PUT,
            "/bkt/a",
            vec![
                s(),
                ("x-bz-server-side-encryption-customer-key", "k".into()),
            ],
            403,
        ),
        (
            Method::PUT,
            "/bkt/a",
            vec![s(), ("content-encoding", "gzip".into())],
            403,
        ),
        (
            Method::PUT,
            "/bkt/a",
            vec![
                s(),
                ("x-bz-info-src_last_modified_millis", "yesterday".into()),
            ],
            400,
        ),
    ] {
        let r = send(m.clone(), p, headers).await.unwrap();
        assert_eq!(
            r.status().as_u16(),
            code,
            "{m} {p}: {}",
            r.text().await.unwrap()
        );
    }
    // a chunked body (no Content-Length): B2 takes none
    let chunked = reqwest::Body::wrap_stream(futures_util::stream::once(async {
        Ok::<_, std::io::Error>(Bytes::from_static(b"x"))
    }));
    let r = c
        .put(format!("{}/upload/bkt/a", env.base))
        .header("authorization", format!("Bearer {tok}"))
        .header("x-bz-content-sha1", &sha)
        .body(chunked)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 411);
    assert_eq!(env.st(|s| (s.authorizes, s.hits)), (0, 0));
    assert!(env.status().contains("b2: locked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_upload_says_whether_to_retry_and_drops_its_url() {
    let env = setup("23h").await;
    let body = b"payload".to_vec();
    let sha = sha1_hex(&body);
    let put = || {
        env.put(
            "/my-bkt/sessions/s1/in/p",
            body.clone(),
            vec![("x-bz-content-sha1", sha.to_string())],
        )
    };
    assert_eq!(put().await.0, 200);
    for (status, code, urls) in [
        (503, "service_unavailable", 2),
        (401, "expired_auth_token", 3),
        (408, "request_timeout", 4),
    ] {
        env.st(|s| s.upload_fail = Some((status, code)));
        let (c, reply) = put().await;
        assert_eq!(c, 503, "{reply}");
        assert!(
            reply.contains(&format!("upload not stored (B2: {status} {code}): retry")),
            "{reply}"
        );
        // the upload token's end isn't the account token's: still unlocked
        assert!(env.status().contains("b2: unlocked"));
        assert_eq!(put().await.0, 200);
        assert_eq!(
            env.st(|s| s.upload_tokens.len()),
            urls,
            "a new upload URL after {status}"
        );
    }
    // B2's other refusals are passed on (scrubbed); the URL is dropped too
    env.st(|s| s.upload_fail = Some((400, "bad_request")));
    let (c, reply) = put().await;
    assert_eq!(c, 400);
    assert!(reply.contains("bad_request"), "{reply}");
    let (c, reply) = env
        .put(
            "/my-bkt/sessions/s1/in/p",
            body.clone(),
            vec![("x-bz-content-sha1", "0".repeat(40).to_string())],
        )
        .await;
    assert_eq!(c, 400);
    assert!(reply.contains("Sha1 did not match"), "{reply}");
    assert_eq!(put().await.0, 200);
    assert_eq!(env.st(|s| s.upload_tokens.len()), 6);
    // a bucket the account doesn't have
    let (c, reply) = env
        .put(
            "/missing/x",
            body.clone(),
            vec![("x-bz-content-sha1", sha.to_string())],
        )
        .await;
    assert_eq!(c, 404, "{reply}");
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_uploads_get_their_own_upload_urls() {
    let env = setup("23h").await;
    env.st(|s| s.upload_delay = Duration::from_millis(800));
    // the lookup and the first URL come from one upload; then two at once
    let body = b"a".to_vec();
    let sha = sha1_hex(&body);
    assert_eq!(
        env.put(
            "/my-bkt/x/0",
            body.clone(),
            vec![("x-bz-content-sha1", sha.to_string())]
        )
        .await
        .0,
        200
    );
    let (a, b) = tokio::join!(
        env.put(
            "/my-bkt/x/1",
            body.clone(),
            vec![("x-bz-content-sha1", sha.to_string())]
        ),
        env.put(
            "/my-bkt/x/2",
            body.clone(),
            vec![("x-bz-content-sha1", sha.to_string())]
        )
    );
    assert_eq!((a.0, b.0), (200, 200), "{a:?} {b:?}");
    assert_eq!(env.st(|s| (s.upload_tokens.len(), s.list_lookups)), (2, 1));
    // both went back to the pool
    let (a, b) = tokio::join!(
        env.put(
            "/my-bkt/x/3",
            body.clone(),
            vec![("x-bz-content-sha1", sha.to_string())]
        ),
        env.put(
            "/my-bkt/x/4",
            body.clone(),
            vec![("x-bz-content-sha1", sha.to_string())]
        )
    );
    assert_eq!((a.0, b.0), (200, 200));
    assert_eq!(env.st(|s| s.upload_tokens.len()), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ended_account_token_during_an_upload_locks() {
    let env = setup("23h").await;
    assert_eq!(env.call("b2_list_buckets", "{}").await.0, 200);
    env.st(|s| s.expire = true);
    let body = b"a".to_vec();
    let (c, reply) = env
        .put(
            "/my-bkt/x",
            body.clone(),
            vec![("x-bz-content-sha1", sha1_hex(&body).to_string())],
        )
        .await;
    assert_eq!(c, 503);
    assert!(reply.contains("B2 token expired or revoked"), "{reply}");
    assert!(env.status().contains("b2: locked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_recreated_bucket_is_looked_up_again() {
    let env = setup("23h").await;
    let body = b"a".to_vec();
    let sha = sha1_hex(&body);
    let put = || {
        env.put(
            "/my-bkt/x",
            body.clone(),
            vec![("x-bz-content-sha1", sha.clone())],
        )
    };
    assert_eq!(put().await.0, 200);
    // recreated behind credproxy's back: the pooled URL is refused, nothing stored; the retry looks the id up again
    env.st(|s| s.bucket_gen += 1);
    let (c, reply) = put().await;
    assert_eq!(c, 503, "{reply}");
    assert!(reply.contains("bad_bucket_id"), "{reply}");
    assert_eq!(put().await.0, 200);
    assert_eq!(env.st(|s| (s.list_lookups, s.upload_tokens.len())), (2, 2));
    // no pooled URL but a stale cached id: b2_get_upload_url refuses it, credproxy looks it up again by itself
    env.st(|s| s.upload_fail = Some((503, "service_unavailable")));
    assert_eq!(put().await.0, 503);
    env.st(|s| s.bucket_gen += 1);
    assert_eq!(put().await.0, 200);
    assert_eq!(
        env.st(|s| (s.list_lookups, s.upload_tokens.len())),
        (3, 3),
        "the refused b2_get_upload_url handed out no URL"
    );
    // a refused delete keeps the cache: the next upload needs no lookup and no new URL
    let id = format!("bidmybktg{}", env.st(|s| s.bucket_gen));
    env.st(|s| s.delete_fail = true);
    let (c, _) = env
        .call("b2_delete_bucket", &format!(r#"{{"bucketId": "{id}"}}"#))
        .await;
    assert_eq!(c, 400);
    env.st(|s| s.delete_fail = false);
    assert_eq!(put().await.0, 200);
    assert_eq!(env.st(|s| (s.list_lookups, s.upload_tokens.len())), (3, 3));
    // deleted through credproxy: its id and URLs are forgotten at once
    let id = format!("bidmybktg{}", env.st(|s| s.bucket_gen));
    let (c, _) = env
        .call("b2_delete_bucket", &format!(r#"{{"bucketId": "{id}"}}"#))
        .await;
    assert_eq!(c, 200);
    env.st(|s| s.bucket_gen += 1);
    assert_eq!(put().await.0, 200);
    assert_eq!(env.st(|s| (s.list_lookups, s.upload_tokens.len())), (4, 4));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upload_that_breaks_off_says_whether_it_was_stored() {
    let env = setup("23h").await;
    let body = b"payload".to_vec();
    let sha = sha1_hex(&body);
    assert_eq!(
        env.put(
            "/my-bkt/x",
            body.clone(),
            vec![("x-bz-content-sha1", sha.clone())]
        )
        .await
        .0,
        200
    );
    // B2 drops the connection after the whole body: maybe stored
    env.st(|s| s.drop_after_body = true);
    let (c, reply) = env
        .put(
            "/my-bkt/x",
            body.clone(),
            vec![("x-bz-content-sha1", sha.clone())],
        )
        .await;
    assert_eq!(c, 502, "{reply}");
    assert!(
        reply.contains("outcome is unknown") && reply.contains("b2_list_file_names"),
        "{reply}"
    );
    env.st(|s| s.drop_after_body = false);
    // the client hangs up mid-body: not stored (credproxy's reply goes nowhere, the log has it)
    let addr = env
        .base
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap()
        .to_string();
    {
        use tokio::io::AsyncWriteExt;
        let mut s = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let head = format!(
            "PUT /b2/upload/my-bkt/cut HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\nX-Bz-Content-Sha1: {sha}\r\nContent-Length: 1000\r\n\r\n0123456789",
            env.token()
        );
        s.write_all(head.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let mut logged = false;
    for _ in 0..50 {
        if env.log().contains("b2 PUT /upload/my-bkt/cut 503") {
            logged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(logged, "{}", env.log());
    assert!(env.st(|s| s.stored.clone()).unwrap().0 != "cut");
}
