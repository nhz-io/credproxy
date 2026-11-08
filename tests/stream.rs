//! Stream routes (`stream = true`, LLM APIs) end to end: real daemon, real `age`, fake key, a scripted upstream that
//! sends its reply in timed chunks.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

mod common;
use common::{BIN, age_identity, free_port, seal, sh, start_daemon};

type Chunks = Vec<(Duration, Vec<u8>)>;

/// Upstream body sent as `chunks` (each after its delay), then held open forever if `hang`.
fn timed_body(
    chunks: Chunks,
    hang: bool,
) -> http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        for (d, c) in chunks {
            tokio::time::sleep(d).await;
            if tx.send(Bytes::from(c)).await.is_err() {
                return;
            }
        }
        if hang {
            std::future::pending::<()>().await;
        }
    });
    let s = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|b| (Ok::<_, std::convert::Infallible>(Frame::data(b)), rx))
    });
    BodyExt::boxed(StreamBody::new(s))
}

/// The scripted upstream; counts requests.
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
                        let auth = h("authorization").unwrap_or_default();
                        let path = req.uri().path().to_string();
                        let ms = Duration::from_millis;
                        let sse = |b: hyper::http::response::Builder| {
                            b.header("content-type", "text/event-stream")
                        };
                        let r = hyper::Response::builder();
                        let res = match path.as_str() {
                            "/v1/sse" => sse(r).body(timed_body(
                                (0..5)
                                    .map(|i| {
                                        (
                                            ms(if i == 0 { 0 } else { 400 }),
                                            format!("data: {i}\n\n").into_bytes(),
                                        )
                                    })
                                    .collect(),
                                false,
                            )),
                            "/v1/split" => {
                                // the key as the upstream got it, cut across chunks in several ways
                                let k = auth.strip_prefix("Bearer ").unwrap().as_bytes().to_vec();
                                let n = k.len();
                                let mut chunks: Chunks = vec![
                                    (ms(0), [b"a:".as_slice(), &k[..7]].concat()),
                                    (ms(50), [&k[7..], b"\n".as_slice()].concat()),
                                    (ms(50), [b"b:".as_slice(), &k[..1]].concat()),
                                ];
                                for i in 1..n {
                                    chunks.push((ms(5), k[i..i + 1].to_vec()));
                                }
                                chunks.push((ms(50), [b"\nc:".as_slice(), &k[..5]].concat()));
                                chunks.push((ms(50), b"zz\n".to_vec()));
                                chunks.push((ms(50), [b"d:".as_slice(), &k, &k, b"\n"].concat()));
                                r.body(timed_body(chunks, false))
                            }
                            "/v1/stall" => sse(r)
                                .body(timed_body(vec![(ms(0), b"data: 0\n\n".to_vec())], true)),
                            "/v1/late" => {
                                tokio::time::sleep(ms(1500)).await;
                                sse(r).body(timed_body(
                                    (0..4)
                                        .map(|i| (ms(1500), format!("data: {i}\n\n").into_bytes()))
                                        .collect(),
                                    false,
                                ))
                            }
                            "/v1/silent" => {
                                std::future::pending::<()>().await;
                                unreachable!()
                            }
                            "/v1/gzip" => r
                                .header("content-encoding", "gzip")
                                .body(Full::new(Bytes::from_static(b"x")).boxed()),
                            "/v1/limited" => r
                                .status(429)
                                .header("retry-after", "7")
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from_static(b"{}")).boxed()),
                            _ => {
                                let seen = serde_json::json!({
                                    "auth": auth,
                                    "anthropic_version": h("anthropic-version"),
                                    "anthropic_beta": h("anthropic-beta"),
                                    "x_other": h("x-other"),
                                    "cookie": h("cookie"),
                                    "ctype": h("content-type"),
                                    "accept": h("accept"),
                                    "accept_encoding": h("accept-encoding"),
                                    "query": req.uri().query(),
                                });
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                let mut v = seen;
                                v["body_len"] = body.len().into();
                                r.header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(v.to_string())).boxed())
                            }
                        };
                        Ok::<_, std::convert::Infallible>(res.unwrap())
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
    key: String,
    base: String,
    hits: Arc<AtomicUsize>,
    daemon: Option<Child>,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = Command::new(BIN)
            .arg("stop")
            .env("CREDPROXY_CONFIG", &self.cfg)
            .output();
        if let Some(mut d) = self.daemon.take() {
            let _ = d.wait();
        }
    }
}

impl Env {
    fn token(&self) -> String {
        let out = sh(Command::new(BIN)
            .args(["token", "llm"])
            .env("CREDPROXY_CONFIG", &self.cfg))
        .stdout;
        String::from_utf8(out).unwrap().trim().to_string()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("credproxy.log")).unwrap_or_default()
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        reqwest::Client::new()
            .get(format!("{}{path}", self.base))
            .header("authorization", format!("Bearer {}", self.token()))
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        reqwest::Client::new()
            .post(format!("{}{path}", self.base))
            .header("authorization", format!("Bearer {}", self.token()))
    }
}

async fn setup() -> Env {
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
    let public = age_identity(d);
    seal(&public, d.join("secrets/llm/key.age"), &format!("{key}\n"));
    let cfg = d.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"listen = "127.0.0.1:{listen}"
identity = "{d}/id.txt"
secrets_dir = "{d}/secrets"
runtime_dir = "{d}/run"
log = "{d}/credproxy.log"

[services.llm]
secret = "llm/key"

[[services.llm.routes]]
prefix = "/v1"
upstream = "http://127.0.0.1:{port}/v1"
allow = ["GET /sse", "GET /split", "GET /stall", "GET /late", "GET /silent", "GET /gzip", "GET /limited", "POST /echo"]
stream = true
stream_idle = "2s"
max_body = "64KiB"
forward_headers = ["anthropic-version", "Anthropic-Beta"]
"#,
            d = d.display(),
        ),
    )
    .unwrap();
    let daemon = start_daemon(&cfg).await;
    // unlock now, so the timings below aren't the unlock's
    sh(Command::new(BIN)
        .args(["unlock", "llm"])
        .env("CREDPROXY_CONFIG", &cfg));
    Env {
        dir,
        cfg,
        key,
        base: format!("http://127.0.0.1:{listen}/llm"),
        hits,
        daemon: Some(daemon),
    }
}

/// Every chunk as it arrives, with its arrival time since `t0`, until the body ends or fails.
async fn chunks(
    mut r: reqwest::Response,
    t0: Instant,
) -> (Vec<(Duration, Bytes)>, Result<(), reqwest::Error>) {
    let mut v = Vec::new();
    loop {
        match r.chunk().await {
            Ok(Some(c)) => v.push((t0.elapsed(), c)),
            Ok(None) => return (v, Ok(())),
            Err(e) => return (v, Err(e)),
        }
    }
}

/// SSE events arrive one by one as the upstream sends them, in order, not all at the end.
#[tokio::test(flavor = "multi_thread")]
async fn replies_stream_in_order_as_they_come() {
    let env = setup().await;
    let t0 = Instant::now();
    let r = env.get("/v1/sse").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "text/event-stream");
    let (got, end) = chunks(r, t0).await;
    end.unwrap();
    let body: Vec<u8> = got.iter().flat_map(|(_, c)| c.to_vec()).collect();
    assert_eq!(
        String::from_utf8(body).unwrap(),
        (0..5).map(|i| format!("data: {i}\n\n")).collect::<String>()
    );
    // each event on its own, about 400 ms after the previous one
    assert_eq!(got.len(), 5, "{got:?}");
    assert!(got[0].0 < Duration::from_millis(300), "{got:?}");
    for w in got.windows(2) {
        let gap = w[1].0 - w[0].0;
        assert!(
            gap > Duration::from_millis(250) && gap < Duration::from_millis(1000),
            "{got:?}"
        );
    }
}

/// The key is replaced however the upstream cuts it across chunks: in two, byte by byte, twice in a row. A chunk
/// ending in what could start the key is held only until the next one shows it isn't.
#[tokio::test(flavor = "multi_thread")]
async fn key_split_across_chunks_is_scrubbed() {
    let env = setup().await;
    let r = env.get("/v1/split").send().await.unwrap();
    assert_eq!(r.status(), 200);
    let body = r.text().await.unwrap();
    assert!(!body.contains(&env.key), "{body}");
    assert_eq!(
        body,
        format!(
            "a:[REDACTED]\nb:[REDACTED]\nc:{}zz\nd:[REDACTED][REDACTED]\n",
            &env.key[..5]
        )
    );
}

/// No overall limit: a reply whose start takes 1.5 s and whose chunks come 1.5 s apart (6 s in all) passes under a
/// 2 s stream_idle.
#[tokio::test(flavor = "multi_thread")]
async fn slow_replies_live_while_bytes_move() {
    let env = setup().await;
    let t0 = Instant::now();
    let r = env.get("/v1/late").send().await.unwrap();
    assert_eq!(r.status(), 200);
    let (got, end) = chunks(r, t0).await;
    end.unwrap();
    assert_eq!(got.len(), 4);
    assert!(t0.elapsed() > Duration::from_secs(6));
}

/// A reply that stops moving is cut stream_idle after its last bytes, as an error (never a short success), and
/// logged; one that never starts is cut too.
#[tokio::test(flavor = "multi_thread")]
async fn stalled_replies_are_cut_after_stream_idle() {
    let env = setup().await;
    let t0 = Instant::now();
    let r = env.get("/v1/stall").send().await.unwrap();
    assert_eq!(r.status(), 200);
    let (got, end) = chunks(r, t0).await;
    assert_eq!(got.len(), 1);
    assert!(end.is_err(), "a cut-off reply must fail");
    let t = t0.elapsed();
    assert!(
        t >= Duration::from_secs(2) && t < Duration::from_secs(5),
        "{t:?}"
    );
    let t0 = Instant::now();
    assert!(env.get("/v1/silent").send().await.is_err());
    let t = t0.elapsed();
    assert!(
        t >= Duration::from_secs(2) && t < Duration::from_secs(5),
        "{t:?}"
    );
    let log = env.log();
    assert!(
        log.contains("llm GET /v1/stall cut off: no progress for 2s"),
        "{log}"
    );
    assert!(
        log.contains("llm GET /v1/silent cut off: no progress for 2s"),
        "{log}"
    );
}

/// Bodies up to max_body pass whole; one byte more is refused before it reaches the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn request_body_cap() {
    let env = setup().await;
    let r = env
        .post("/v1/echo")
        .header("content-type", "application/json")
        .body(vec![b'x'; 64 << 10])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let v: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    assert_eq!(v["body_len"], 64 << 10);
    let before = env.hits.load(Ordering::SeqCst);
    let r = env
        .post("/v1/echo")
        .body(vec![b'x'; (64 << 10) + 1])
        .send()
        .await;
    // refused before the body is read: a 413, or a reset while the client is still sending
    if let Ok(r) = r {
        assert_eq!(r.status(), 413);
    }
    assert_eq!(env.hits.load(Ordering::SeqCst), before);
}

/// Only Content-Type, Accept and the route's forward_headers go upstream (with the key in place of the token,
/// scrubbed on the way back); identity encoding is asked for and a compressed reply refused; refused paths never
/// reach the upstream; Retry-After comes back.
#[tokio::test(flavor = "multi_thread")]
async fn headers_and_refusals() {
    let env = setup().await;
    let r = env
        .post("/v1/echo?beta=true")
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", "a")
        .header("x-other", "1")
        .header("cookie", "s=1")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body = r.text().await.unwrap();
    assert!(!body.contains(&env.key) && !body.contains(&env.token()));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["auth"], "Bearer [REDACTED]");
    assert_eq!(v["anthropic_version"], "2023-06-01");
    assert_eq!(v["anthropic_beta"], "a");
    assert!(v["x_other"].is_null() && v["cookie"].is_null());
    assert_eq!(v["ctype"], "application/json");
    assert_eq!(v["accept"], "text/event-stream");
    assert_eq!(v["accept_encoding"], "identity");
    assert_eq!(v["query"], "beta=true");

    assert_eq!(env.get("/v1/gzip").send().await.unwrap().status(), 502);
    let r = env.get("/v1/limited").send().await.unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers()["retry-after"], "7");

    let before = env.hits.load(Ordering::SeqCst);
    assert_eq!(env.get("/v1/echo").send().await.unwrap().status(), 403);
    assert_eq!(env.post("/v1/other").send().await.unwrap().status(), 403);
    let r = reqwest::Client::new()
        .get(format!("{}/v1/sse", env.base))
        .header("authorization", "Bearer nope")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(env.hits.load(Ordering::SeqCst), before);
}
