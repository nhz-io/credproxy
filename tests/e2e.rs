//! End to end: real daemon, real `age` with a throwaway identity, fake key, fake upstream on 127.0.0.1.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_credproxy");

struct Env {
    dir: tempfile::TempDir,
    cfg: PathBuf,
    key: String,
    hits: Arc<AtomicUsize>,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.cli(&["stop"]);
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

async fn setup(idle: &str) -> Env {
    let dir = tempfile::Builder::new().prefix("cp").tempdir().unwrap();
    let d = dir.path();
    let hits = Arc::new(AtomicUsize::new(0));
    let port = upstream(hits.clone()).await;
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
identity = "{d}/id.txt"
secrets_dir = "{d}/secrets"
runtime_dir = "{d}/run"
log = "{d}/credproxy.log"

[services.fake]
secret = "fake/api-key"
env = "FAKE_PROXY"

[[services.fake.routes]]
prefix = "/graphql"
upstream = "http://127.0.0.1:{port}/gql"
graphql_queries = ["gpuTypes"]

[[services.fake.routes]]
prefix = "/"
upstream = "http://127.0.0.1:{port}/v1"
allow = ["GET /pods", "GET /pods/{{id}}", "POST /pods", "GET /billing/pods"]
"#,
            d = d.display()
        ),
    )
    .unwrap();
    Env {
        dir,
        cfg,
        key,
        hits,
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

    /// Run a shell snippet through `credproxy run fake`, return its stdout.
    fn run(&self, script: &str) -> String {
        let o = self.cli(&["run", "fake", "--", "sh", "-c", script]);
        assert!(
            o.status.success(),
            "run failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap()
    }

    fn url(&self) -> String {
        self.run("printf %s \"$FAKE_PROXY\"")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("credproxy.log")).unwrap_or_default()
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

async fn get(url: &str) -> (u16, String) {
    let r = reqwest::Client::new()
        .get(url)
        .header("cookie", "session=leak")
        .header("authorization", "Bearer client-supplied")
        .header("x-extra", "1")
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

async fn post(url: &str, body: serde_json::Value) -> (u16, String) {
    let r = reqwest::Client::new()
        .post(url)
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
    let base = env.url();
    assert!(base.starts_with("http://127.0.0.1:"), "{base}");
    assert_eq!(
        env.url(),
        base,
        "second run reuses the unlocked key and token"
    );

    // allowed: key added, own User-Agent, client auth/cookie/extra headers dropped, query passed, key scrubbed from reply
    let (s, body) = get(&format!("{base}/pods/abc-1?x=1")).await;
    assert_eq!(s, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["path"], "/v1/pods/abc-1");
    assert_eq!(v["query"], "x=1");
    assert_eq!(v["auth"], "Bearer [REDACTED]");
    assert!(v["ua"].as_str().unwrap().starts_with("credproxy/"));
    assert!(v["cookie"].is_null() && v["x"].is_null());
    assert!(!body.contains(&env.key));
    let (s, _) = get(&format!("{base}/billing/pods?podId=abc&bucketSize=hour")).await;
    assert_eq!(s, 200);

    // denied before reaching upstream
    let before = env.hits.load(Ordering::SeqCst);
    for p in [
        "/pods/a/b",
        "/endpoints",
        "/pods/..",
        "/pods/%2e%2e",
        "/user",
        "/",
    ] {
        let (s, _) = get(&format!("{base}{p}")).await;
        assert_eq!(s, 403, "{p}");
    }
    let r = reqwest::Client::new()
        .delete(format!("{base}/pods/x"))
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
        serde_json::json!({"query": "query { gpuTypes { id } }"}),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert!(body.contains("\"/gql\""));
    for q in [
        "mutation { podTerminate(input: {podId: \"x\"}) }",
        "{ myself { pubKey } }",
    ] {
        let (s, _) = post(&format!("{base}/graphql"), serde_json::json!({"query": q})).await;
        assert_eq!(s, 403, "{q}");
    }
    let (s, _) = get(&format!("{base}/graphql")).await;
    assert_eq!(s, 403);

    // wrong or missing token
    let port_base = &base[..base.rfind('/').unwrap()];
    let (s, _) = get(&format!("{port_base}/{}/pods", "0".repeat(64))).await;
    assert_eq!(s, 404);
    let (s, _) = get(&format!("{port_base}/pods")).await;
    assert_eq!(s, 404);

    // log: method/path/status only — no key, token or query
    let log = env.log();
    assert!(log.contains("fake GET /pods/abc-1 200"), "{log}");
    assert!(log.contains("fake DELETE /pods/x 403"), "{log}");
    let token = &base[base.rfind('/').unwrap() + 1..];
    assert!(
        !log.contains(&env.key)
            && !log.contains(token)
            && !log.contains("x=1")
            && !log.contains("podId"),
        "{log}"
    );

    // explicit lock: the old URL stops working, a new run unlocks with a new token
    let o = env.cli(&["lock", "fake"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("locked: fake"));
    let (s, _) = get(&format!("{base}/pods")).await;
    assert_eq!(s, 404);
    assert_ne!(env.url(), base);
}

#[tokio::test(flavor = "multi_thread")]
async fn key_not_in_argv_env_or_files() {
    let env = setup("12h").await;
    // the child sees the proxy URL, not the key; ps -E shows argv + environment of every process we can see
    let out = env.run("echo \"$FAKE_PROXY\"; ps -E -ww -ax -o pid=,command=");
    assert!(
        out.contains("FAKE_PROXY=http://127.0.0.1:"),
        "child env should carry the URL"
    );
    assert!(!out.contains(&env.key), "key visible in ps -E");
    // not vacuous: the daemon is in the listing, with its environment
    assert!(
        out.lines()
            .any(|l| l.contains("credproxy serve") && l.contains("CREDPROXY_CONFIG=")),
        "daemon not in ps -E output"
    );
    let status = String::from_utf8(env.cli(&["status"]).stdout).unwrap();
    assert!(status.contains("fake: unlocked"), "{status}");
    assert!(!status.contains(&env.key));
    // nothing on disk holds it (runtime dir, log, config)
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
    let base = env.url();
    let (s, _) = get(&format!("{base}/pods")).await;
    assert_eq!(s, 200);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let (s, _) = get(&format!("{base}/pods")).await;
    assert_eq!(s, 404, "should have locked after 1s idle");
    assert!(env.log().contains("fake locked (idle)"));
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_secret_fails_cleanly() {
    let env = setup("12h").await;
    std::fs::write(env.path().join("secrets/fake/api-key.age"), b"not age").unwrap();
    let o = env.cli(&["run", "fake", "--", "true"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("could not decrypt"));
    let o = env.cli(&["run", "nope", "--", "true"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("unknown service"));
}
