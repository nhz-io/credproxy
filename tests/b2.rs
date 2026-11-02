//! End to end for B2 services: real daemon, real `age` with a throwaway identity, a fake key pair, a fake B2
//! (authorize, API calls, downloads) on 127.0.0.1.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
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

fn json_reply(status: u16, v: Value) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(v.to_string())))
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
                        let h = |n: &str| {
                            req.headers()
                                .get(n)
                                .map(|v| v.to_str().unwrap().to_string())
                        };
                        let (auth, range) = (h("authorization"), h("range"));
                        let method = req.method().to_string();
                        let path = req.uri().path().to_string();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let body = String::from_utf8_lossy(&body).to_string();
                        let mut s = state.lock().unwrap();
                        if path == "/b2api/v3/b2_authorize_account" {
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
                        if s.expire {
                            return Ok(json_reply(
                                401,
                                json!({"status": 401, "code": "expired_auth_token", "message": "expired"}),
                            ));
                        }
                        if auth.as_deref() != Some(s.token.as_str()) {
                            return Ok(json_reply(
                                401,
                                json!({"status": 401, "code": "bad_auth_token", "message": "bad"}),
                            ));
                        }
                        if let Some(call) = path.strip_prefix("/b2api/v3/") {
                            let mut v = json!({"call": call, "got": serde_json::from_str::<Value>(&body).unwrap_or(Value::Null), "echo": s.token});
                            if call == "b2_create_key" {
                                v["applicationKey"] = json!("K005NEWKEYSECRET");
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
    let cfg = d.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"listen = "127.0.0.1:{listen}"
identity = "{d}/id.txt"
secrets_dir = "{d}/secrets"
runtime_dir = "{d}/run"
log = "{d}/credproxy.log"

[services.b2]
secret = "backblaze/master"
auth = {{ b2 = {{ relock_after = "{relock}", authorize_url = "http://127.0.0.1:{port}/b2api/v3/b2_authorize_account" }} }}

[[services.b2.routes]]
prefix = "/b2api/v3"
b2 = {{ calls = ["b2_list_buckets", "b2_create_key", "b2_list_keys", "b2_list_file_names"] }}

[[services.b2.routes]]
prefix = "/file"
b2 = {{ download = true }}
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
            .post(format!("{}/b2api/v3/{call}", self.base))
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
    // a HEAD's 401 has no body: still taken as an expired token
    let r = c
        .head(format!("{}/file/my-bkt/x.bin", env.base))
        .header("authorization", format!("Bearer {tok}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 503);
    assert_eq!(env.st(|s| s.authorizes), 2);
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
