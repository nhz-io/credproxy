//! End to end: real daemon, real `age` with a throwaway identity, fake key, fake upstream on 127.0.0.1.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_credproxy");

struct Env {
    dir: tempfile::TempDir,
    cfg: PathBuf,
    key: String,
    base: String,
    hits: Arc<AtomicUsize>,
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

/// Fake upstream: echoes what it received (including the auth header, to prove scrubbing).
async fn upstream(hits: Arc<AtomicUsize>) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (c, _) = l.accept().await.unwrap();
            let hits = hits.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let h = |n: &str| {
                            req.headers()
                                .get(n)
                                .map(|v| v.to_str().unwrap().to_string())
                        };
                        let v = serde_json::json!({
                            "method": req.method().as_str(), "path": req.uri().path(), "query": req.uri().query(),
                            "auth": h("authorization"), "ua": h("user-agent"), "cookie": h("cookie"), "x": h("x-extra"),
                        });
                        let _ = req.into_body().collect().await;
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(v.to_string())))
                                .unwrap(),
                        )
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

fn sh(cmd: &mut Command) -> Output {
    let o = cmd.output().unwrap();
    assert!(
        o.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    o
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn setup(idle: &str) -> Env {
    let dir = tempfile::Builder::new().prefix("cp").tempdir().unwrap();
    let d = dir.path();
    let hits = Arc::new(AtomicUsize::new(0));
    let port = upstream(hits.clone()).await;
    let listen = free_port();
    let mut rnd = [0u8; 12];
    getrandom::fill(&mut rnd).unwrap();
    let key = format!(
        "fk_{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );

    sh(Command::new("age-keygen").arg("-o").arg(d.join("id.txt")));
    let public =
        String::from_utf8(sh(Command::new("age-keygen").arg("-y").arg(d.join("id.txt"))).stdout)
            .unwrap();
    std::fs::create_dir_all(d.join("secrets/fake")).unwrap();
    let mut age = Command::new("age")
        .args(["-r", public.trim(), "-o"])
        .arg(d.join("secrets/fake/api-key.age"))
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(age.stdin.as_mut().unwrap(), format!("{key}\n").as_bytes()).unwrap();
    assert!(age.wait().unwrap().success());

    let cfg = d.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"idle_lock = "{idle}"
listen = "127.0.0.1:{listen}"
identity = "{d}/id.txt"
secrets_dir = "{d}/secrets"
runtime_dir = "{d}/run"
log = "{d}/credproxy.log"

[services.fake]
secret = "fake/api-key"
token = "test-local-token"

[[services.fake.routes]]
prefix = "/graphql"
upstream = "http://127.0.0.1:{port}/gql"
graphql_queries = ["gpuTypes"]

[[services.fake.routes]]
prefix = "/v1"
upstream = "http://127.0.0.1:{port}/v1"
allow = ["GET /pods", "GET /pods/{{id}}", "POST /pods", "GET /billing/pods"]
"#,
            d = d.display()
        ),
    )
    .unwrap();
    let daemon = Command::new(BIN)
        .arg("serve")
        .env("CREDPROXY_CONFIG", &cfg)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut env = Env {
        dir,
        cfg,
        key,
        base: format!("http://127.0.0.1:{listen}/fake"),
        hits,
        daemon: Some(daemon),
    };
    for _ in 0..100 {
        if String::from_utf8_lossy(&env.cli(&["status"]).stdout).starts_with("running") {
            return env;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    env.daemon.take().unwrap().kill().unwrap();
    panic!("daemon did not start");
}

impl Env {
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .env("CREDPROXY_CONFIG", &self.cfg)
            .output()
            .unwrap()
    }

    /// The token clients send, as `credproxy token` prints it.
    fn token(&self) -> String {
        let out = sh(Command::new(BIN)
            .args(["token", "fake"])
            .env("CREDPROXY_CONFIG", &self.cfg))
        .stdout;
        String::from_utf8(out).unwrap().trim().to_string()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("credproxy.log")).unwrap_or_default()
    }

    fn unlocked(&self) -> bool {
        String::from_utf8_lossy(&self.cli(&["status"]).stdout).contains("fake: unlocked")
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

async fn get(url: &str, token: Option<&str>) -> (u16, String) {
    let mut r = reqwest::Client::new()
        .get(url)
        .header("cookie", "session=leak")
        .header("x-extra", "1");
    if let Some(t) = token {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let r = r.send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

async fn post(url: &str, token: &str, body: serde_json::Value) -> (u16, String) {
    let r = reqwest::Client::new()
        .post(url)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn proxies_allowed_calls_only() {
    let env = setup("12h").await;
    let (base, tok) = (env.base.clone(), env.token());
    assert_eq!(tok, "test-local-token");

    // a request that names another host (DNS rebinding) is refused before anything else, and never unlocks
    let port = base
        .trim_start_matches("http://127.0.0.1:")
        .split('/')
        .next()
        .unwrap()
        .to_string();
    let r = reqwest::Client::new()
        .get(format!("{base}/v1/pods"))
        .header("host", format!("evil.example:{port}"))
        .header("authorization", format!("Bearer {tok}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);
    assert!(r.text().await.unwrap().contains("Host"));

    // no token / wrong token: 401, and no unlock (no Touch ID for strangers)
    assert_eq!(get(&format!("{base}/v1/pods"), None).await.0, 401);
    assert_eq!(
        get(&format!("{base}/v1/pods"), Some(&"0".repeat(64)))
            .await
            .0,
        401
    );
    // right token but refused path: 403, still no unlock
    assert_eq!(
        get(&format!("{base}/v1/endpoints"), Some(&tok)).await.0,
        403
    );
    assert!(!env.unlocked(), "refused calls must not unlock");
    assert_eq!(env.hits.load(Ordering::SeqCst), 0);

    // allowed: unlocks on demand, token replaced by the key, own User-Agent, other client headers dropped,
    // query passed, key scrubbed from the reply
    let (s, body) = get(&format!("{base}/v1/pods/abc-1?x=1"), Some(&tok)).await;
    assert_eq!(s, 200, "{body}");
    assert!(env.unlocked());
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["path"], "/v1/pods/abc-1");
    assert_eq!(v["query"], "x=1");
    assert_eq!(v["auth"], "Bearer [REDACTED]");
    assert!(v["ua"].as_str().unwrap().starts_with("credproxy/"));
    assert!(v["cookie"].is_null() && v["x"].is_null());
    assert!(!body.contains(&env.key) && !body.contains(&tok));
    assert_eq!(
        get(
            &format!("{base}/v1/billing/pods?podId=abc&bucketSize=hour"),
            Some(&tok)
        )
        .await
        .0,
        200
    );

    // denied before reaching upstream
    let before = env.hits.load(Ordering::SeqCst);
    for p in [
        "/v1/pods/a/b",
        "/v1/endpoints",
        "/v1/pods/%2e%2e",
        "/v1",
        "/",
        "/v2/pods",
        "/pods",
    ] {
        assert_eq!(get(&format!("{base}{p}"), Some(&tok)).await.0, 403, "{p}");
    }
    let r = reqwest::Client::new()
        .delete(format!("{base}/v1/pods/x"))
        .header("authorization", format!("Bearer {tok}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);
    assert_eq!(
        env.hits.load(Ordering::SeqCst),
        before,
        "denied calls must not reach upstream"
    );

    // GraphQL: listed query passes, mutation and other fields don't
    let (s, body) = post(
        &format!("{base}/graphql"),
        &tok,
        serde_json::json!({"query": "query { gpuTypes { id } }"}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert!(body.contains("\"/gql\""));
    for q in [
        "mutation { podTerminate(input: {podId: \"x\"}) }",
        "{ myself { pubKey } }",
    ] {
        assert_eq!(
            post(
                &format!("{base}/graphql"),
                &tok,
                serde_json::json!({"query": q})
            )
            .await
            .0,
            403,
            "{q}"
        );
    }

    // unknown service
    let root = &base[..base.rfind('/').unwrap()];
    assert_eq!(
        get(&format!("{root}/other/v1/pods"), Some(&tok)).await.0,
        404
    );

    // log: method/path/status only — no key, token or query
    let log = env.log();
    assert!(log.contains("fake GET /v1/pods/abc-1 200"), "{log}");
    assert!(log.contains("fake GET /v1/pods 401"), "{log}");
    assert!(log.contains("fake DELETE /v1/pods/x 403"), "{log}");
    assert!(
        !log.contains(&env.key)
            && !log.contains(&tok)
            && !log.contains("x=1")
            && !log.contains("podId"),
        "{log}"
    );

    // lock: same token keeps working (unlocks again)
    assert!(String::from_utf8_lossy(&env.cli(&["lock", "fake"]).stdout).contains("locked: fake"));
    assert!(!env.unlocked());
    assert_eq!(get(&format!("{base}/v1/pods"), Some(&tok)).await.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn key_not_in_argv_env_or_files() {
    let env = setup("12h").await;
    let tok = env.token();
    assert_eq!(
        get(&format!("{}/v1/pods", env.base), Some(&tok)).await.0,
        200
    );
    assert!(env.unlocked());
    // ps -E shows argv + environment of every process we can see
    let o = Command::new("ps")
        .args(["-E", "-ww", "-ax", "-o", "pid=,command="])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(!out.contains(&env.key), "key visible in ps -E");
    // not vacuous: the daemon is in the listing, with its environment
    assert!(
        out.lines()
            .any(|l| l.contains("credproxy serve") && l.contains("CREDPROXY_CONFIG=")),
        "daemon not in ps -E output"
    );
    // nothing on disk holds it (state, runtime dir, log, config)
    for entry in walk(env.path()) {
        if entry.extension().is_some_and(|e| e == "age") {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&entry) {
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&env.key),
                "{}",
                entry.display()
            );
        }
    }
}

fn walk(p: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(p).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p))
        } else {
            out.push(p)
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_lock() {
    let env = setup("1s").await;
    let tok = env.token();
    assert_eq!(
        get(&format!("{}/v1/pods", env.base), Some(&tok)).await.0,
        200
    );
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(!env.unlocked(), "should have locked after 1s idle");
    assert!(env.log().contains("fake locked (idle)"));
    assert_eq!(
        get(&format!("{}/v1/pods", env.base), Some(&tok)).await.0,
        200,
        "next call unlocks again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_unlock_backs_off() {
    let env = setup("12h").await;
    let tok = env.token();
    std::fs::write(env.path().join("secrets/fake/api-key.age"), b"not age").unwrap();
    let (s, body) = get(&format!("{}/v1/pods", env.base), Some(&tok)).await;
    assert_eq!(s, 503);
    assert!(body.contains("could not decrypt"), "{body}");
    let (s, body) = get(&format!("{}/v1/pods", env.base), Some(&tok)).await;
    assert_eq!(s, 503);
    assert!(
        body.contains("retry in"),
        "no new prompt during back-off: {body}"
    );
    let o = env.cli(&["unlock", "fake"]);
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("could not decrypt"),
        "explicit unlock ignores back-off"
    );
    assert!(
        String::from_utf8_lossy(&env.cli(&["unlock", "nope"]).stderr).contains("unknown service")
    );
}
