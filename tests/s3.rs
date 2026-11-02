//! S3 with SigV4 end to end: real daemon, real `age`, and an S3 server (s3s-fs, in process) that checks every
//! signature and payload hash. The client only ever has the credproxy token.

use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::Digest;
use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::time::Duration;

mod common;
use common::{BIN, age_identity, free_port, seal, start_daemon};
const ACCESS_KEY: &str = "AKIDCREDPROXYTEST";

struct Env {
    dir: tempfile::TempDir,
    cfg: PathBuf,
    secret: String,
    base: String,
    daemon: Option<Child>,
    /// tokens fetched so far (fixed for the daemon's life): one `credproxy token` per service, not per call
    tokens: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.cli(&["stop"]);
        if let Some(mut d) = self.daemon.take() {
            let _ = d.wait();
        }
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

    fn token(&self, service: &str) -> String {
        let mut tokens = self.tokens.lock().unwrap();
        tokens
            .entry(service.to_string())
            .or_insert_with(|| {
                let o = self.cli(&["token", service]);
                assert!(o.status.success());
                String::from_utf8(o.stdout).unwrap().trim().to_string()
            })
            .clone()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("credproxy.log")).unwrap_or_default()
    }
}

/// s3s-fs on a free port, serving `root` (each directory is a bucket), accepting only ACCESS_KEY/`secret`.
async fn s3_server(root: PathBuf, secret: String) -> u16 {
    let fs = s3s_fs::FileSystem::new(root).unwrap();
    let mut b = s3s::service::S3ServiceBuilder::new(fs);
    b.set_auth(s3s::auth::SimpleAuth::from_single(ACCESS_KEY, secret));
    let service = b.build();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (c, _) = l.accept().await.unwrap();
            let service = service.clone();
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(c), service)
                    .await;
            });
        }
    });
    port
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A scripted upstream (no signature check). Every request is recorded in `<dir>/raw-<last path segment>.txt`:
/// its head, then how many body bytes arrived out of Content-Length and their SHA-256. The last path segment picks
/// the reply: `truncate-cl` (says 1000 bytes, sends 500, closes), `truncate-chunked` (one chunk, then closes
/// without the final one), `chunked-ok`, `stall` (10 of 1000 bytes, then nothing for 90 s), `error-echo` (403
/// quoting the access key id), `complete-error` (200 with an <Error> body), `complete-ok`, `not-modified` (304), `redirect` (307), `no-read` (never reads the body or replies), `slow-reply` (replies after 10 s), `pause-reply` (after 2.5 s), `complete-trickle` (keep-alive spaces, then the result), `complete-late` (headers late, then spaces: 5 s in all), `close-delimited` (200, no length), `complete-empty`, `complete-cut` (says 1000 bytes, sends 3), `reset-after-body` (closes without replying), `throttle` (503 with Retry-After), anything else 200
/// with no body.
async fn raw_server(dir: PathBuf) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = l.accept().await.unwrap();
            let dir = dir.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = vec![0u8; 1 << 16];
                let end = loop {
                    let n = c.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(i) = find(&buf, b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                let name = path
                    .split('?')
                    .next()
                    .unwrap()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .to_string();
                let cl: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                let mut body = buf[end..].to_vec();
                while body.len() < cl && name != "no-read" {
                    let n = c.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
                std::fs::write(
                    dir.join(format!("raw-{name}.txt")),
                    format!(
                        "{head}--- body {} of {cl} sha256 {}\n",
                        body.len(),
                        hex_sha256(&body)
                    ),
                )
                .unwrap();
                let mut out: Vec<u8> = match name.as_str() {
                    "truncate-cl" => {
                        let mut v = b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n".to_vec();
                        v.extend_from_slice(&[7u8; 500]);
                        v
                    }
                    "truncate-chunked" => {
                        let mut v = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n1f4\r\n".to_vec();
                        v.extend_from_slice(&[7u8; 500]);
                        v.extend_from_slice(b"\r\n");
                        v
                    }
                    "chunked-ok" => b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec(),
                    "stall" => {
                        let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n0123456789").await;
                        tokio::time::sleep(Duration::from_secs(90)).await;
                        return;
                    }
                    "pause-reply" => {
                        tokio::time::sleep(Duration::from_millis(2500)).await;
                        b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec()
                    }
                    "throttle" => b"HTTP/1.1 503 Slow Down\r\nretry-after: 5\r\ncontent-type: application/xml\r\nconnection: close\r\n\r\n<Error><Code>SlowDown</Code></Error>".to_vec(),
                    "close-delimited" => b"HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\nconnection: close\r\n\r\nhello".to_vec(),
                    "complete-empty" => b"HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\nconnection: close\r\n\r\n".to_vec(),
                    "complete-cut" => b"HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\ncontent-length: 1000\r\n\r\n<Co".to_vec(),
                    "reset-after-body" => return,
                    "complete-late" => {
                        // headers after 2 s, then keep-alive spaces for 3 s more: 5 s in all, past the 4 s a
                        // completion gets (s3_reply_wait 3 s + s3_connect_timeout 1 s)
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        let _ = c
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\nconnection: close\r\n\r\n")
                            .await;
                        for _ in 0..6 {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            let _ = c.write_all(b" ").await;
                        }
                        b"<CompleteMultipartUploadResult><ETag>\"t-2\"</ETag></CompleteMultipartUploadResult>".to_vec()
                    }
                    "complete-trickle" => {
                        // headers at once, then a keep-alive space every 0.5 s for 2.5 s (past s3_idle), then the result
                        let _ = c
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\nconnection: close\r\n\r\n")
                            .await;
                        for _ in 0..5 {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            let _ = c.write_all(b" ").await;
                        }
                        b"<CompleteMultipartUploadResult><ETag>\"t-2\"</ETag></CompleteMultipartUploadResult>".to_vec()
                    }
                    "slow-reply" => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec()
                    }
                    "no-read" => {
                        // never reads the body, never replies (the body read above stops at what was sent so far)
                        tokio::time::sleep(Duration::from_secs(200)).await;
                        return;
                    }
                    "not-modified" => b"HTTP/1.1 304 Not Modified\r\netag: \"e1\"\r\nlast-modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nconnection: close\r\n\r\n".to_vec(),
                    "redirect" => b"HTTP/1.1 307 Temporary Redirect\r\nlocation: http://127.0.0.1:1/vol1/redirected-target\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec(),
                    "complete-error" => b"HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\nconnection: close\r\n\r\n<?xml version=\"1.0\"?>\n<Error><Code>InternalError</Code><Message>We encountered an internal error.</Message></Error>".to_vec(),
                    "complete-ok" => b"HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\nconnection: close\r\n\r\n<CompleteMultipartUploadResult><ETag>\"x-2\"</ETag></CompleteMultipartUploadResult>".to_vec(),
                    "error-echo" => format!(
                        "HTTP/1.1 403 Forbidden\r\ncontent-type: application/xml\r\nconnection: close\r\n\r\n<Error><Code>SignatureDoesNotMatch</Code><AWSAccessKeyId>{ACCESS_KEY}</AWSAccessKeyId></Error>"
                    )
                    .into_bytes(),
                    _ => b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec(),
                };
                let _ = c.write_all(&out).await;
                out.clear();
            });
        }
    });
    port
}

async fn setup() -> Env {
    let dir = tempfile::Builder::new().prefix("cps3").tempdir().unwrap();
    let d = dir.path();
    let mut rnd = [0u8; 16];
    getrandom::fill(&mut rnd).unwrap();
    let secret = format!(
        "sk{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    std::fs::create_dir_all(d.join("store/vol1")).unwrap();
    let s3 = s3_server(d.join("store"), secret.clone()).await;
    let listen = free_port();
    let raw = raw_server(d.to_path_buf()).await;
    // nothing listens here: an upstream that is down
    let down = free_port();

    let public = age_identity(d);
    seal(
        &public,
        d.join("secrets/s3/key.age"),
        &format!("{ACCESS_KEY}\n{secret}\n"),
    );
    // same secret, another access key id: the server refuses it
    seal(
        &public,
        d.join("secrets/s3/wrong.age"),
        &format!("AKIDWRONG\n{secret}\n"),
    );

    let cfg = d.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"listen = "127.0.0.1:{listen}"
# short S3 timeouts so the tests that wait them out take seconds (defaults: 60s, 2h, 30s)
s3_idle = "2s"
s3_reply_wait = "3s"
s3_connect_timeout = "1s"
identity = "{d}/id.txt"
secrets_dir = "{d}/secrets"
runtime_dir = "{d}/run"
log = "{d}/credproxy.log"

[services.store]
secret = "s3/key"
auth = {{ sigv4 = {{ service = "s3" }} }}

[[services.store.routes]]
prefix = "/dc-1"
upstream = "http://127.0.0.1:{s3}"
s3 = {{ region = "dc-1", ops = ["GetObject", "HeadObject", "PutObject", "DeleteObject", "HeadBucket", "ListObjectsV2", "CreateMultipartUpload", "UploadPart", "CompleteMultipartUpload", "AbortMultipartUpload", "ListParts"] }}

[[services.store.routes]]
prefix = "/ro"
upstream = "http://127.0.0.1:{s3}"
s3 = {{ region = "dc-1", ops = ["GetObject", "ListObjectsV2"], key_prefixes = ["pub/"] }}

[[services.store.routes]]
prefix = "/raw"
upstream = "http://127.0.0.1:{raw}"
s3 = {{ region = "dc-1", ops = ["GetObject", "HeadObject", "PutObject", "CreateMultipartUpload", "UploadPart", "CompleteMultipartUpload"], unsigned_payload = true }}

[[services.store.routes]]
prefix = "/down"
upstream = "http://127.0.0.1:{down}"
s3 = {{ region = "dc-1", ops = ["DeleteObject", "CompleteMultipartUpload", "PutObject"] }}

[[services.store.routes]]
prefix = "/unsigned"
upstream = "http://127.0.0.1:{s3}"
s3 = {{ region = "dc-1", ops = ["GetObject", "PutObject"], unsigned_payload = true }}

[services.wrong]
secret = "s3/wrong"
auth = {{ sigv4 = {{}} }}

[[services.wrong.routes]]
prefix = "/dc-1"
upstream = "http://127.0.0.1:{s3}"
s3 = {{ region = "dc-1", ops = ["GetObject"] }}
"#,
            d = d.display(),
        ),
    )
    .unwrap();
    let daemon = start_daemon(&cfg).await;
    Env {
        dir,
        cfg,
        secret,
        base: format!("http://127.0.0.1:{listen}"),
        daemon: Some(daemon),
        tokens: Default::default(),
    }
}

fn hex_sha256(b: &[u8]) -> String {
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn data(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31) ^ seed).collect()
}

struct Reply {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A call through the proxy: `hash` true sends the body's SHA-256 in x-amz-content-sha256.
async fn call(
    env: &Env,
    method: &str,
    path: &str,
    body: Vec<u8>,
    hash: bool,
    extra: &[(&str, &str)],
) -> Reply {
    let mut r = reqwest::Client::new()
        .request(method.parse().unwrap(), format!("{}{path}", env.base))
        .header("authorization", format!("Bearer {}", env.token("store")));
    if hash {
        r = r.header("x-amz-content-sha256", hex_sha256(&body));
    }
    for (n, v) in extra {
        r = r.header(*n, *v);
    }
    if !body.is_empty() {
        r = r.body(body);
    }
    let res = r.send().await.unwrap();
    let (status, headers) = (res.status().as_u16(), res.headers().clone());
    let body = res.bytes().await.unwrap().to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

fn between<'a>(s: &'a str, a: &str, b: &str) -> &'a str {
    let i = s.find(a).unwrap_or_else(|| panic!("no {a} in {s}")) + a.len();
    &s[i..i + s[i..].find(b).unwrap()]
}

#[tokio::test(flavor = "multi_thread")]
async fn objects_round_trip() {
    let env = setup().await;
    // small body without a hash: the proxy hashes it
    let r = call(
        &env,
        "PUT",
        "/store/dc-1/vol1/dir/a.txt",
        b"hello".to_vec(),
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let r = call(
        &env,
        "GET",
        "/store/dc-1/vol1/dir/a.txt",
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
    assert!(r.headers.get("etag").is_some());

    // a key that needs encoding
    let r = call(
        &env,
        "PUT",
        "/store/dc-1/vol1/sp%20ace+plus.txt",
        b"x".to_vec(),
        true,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(env.dir.path().join("store/vol1/sp ace+plus.txt").exists());

    // over 1 MiB: streamed with the client's hash
    let big = data(5 << 20, 7);
    let r = call(
        &env,
        "PUT",
        "/store/dc-1/vol1/big.bin",
        big.clone(),
        true,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let r = call(&env, "HEAD", "/store/dc-1/vol1/big.bin", vec![], false, &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.headers["content-length"],
        (5u64 << 20).to_string().as_str()
    );
    let r = call(&env, "GET", "/store/dc-1/vol1/big.bin", vec![], false, &[]).await;
    assert_eq!(r.status, 200);
    assert!(r.body == big, "GET returned other bytes");
    let r = call(
        &env,
        "GET",
        "/store/dc-1/vol1/big.bin",
        vec![],
        false,
        &[("range", "bytes=10-19")],
    )
    .await;
    assert_eq!((r.status, r.body.as_slice()), (206, &big[10..20]));

    // a wrong hash: the server checks it against the body
    let r = reqwest::Client::new()
        .put(format!("{}/store/dc-1/vol1/bad.bin", env.base))
        .header("authorization", format!("Bearer {}", env.token("store")))
        .header("x-amz-content-sha256", hex_sha256(b"something else"))
        .body(data(2 << 20, 1))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error(), "{}", r.status());
    let text = r.text().await.unwrap();
    assert!(!text.contains(&env.secret));
    assert!(!env.dir.path().join("store/vol1/bad.bin").exists());

    // big body without a hash: refused before it is read (the client may see the 413 or, still writing, a reset)
    let r = reqwest::Client::new()
        .put(format!("{}/store/dc-1/vol1/nohash.bin", env.base))
        .header("authorization", format!("Bearer {}", env.token("store")))
        .body(data(2 << 20, 2))
        .send()
        .await;
    if let Ok(r) = r {
        assert_eq!(r.status(), 413);
    }
    assert!(!env.dir.path().join("store/vol1/nohash.bin").exists());

    let r = call(
        &env,
        "GET",
        "/store/dc-1/vol1?list-type=2&prefix=dir/",
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().contains("<Key>dir/a.txt</Key>") && !r.text().contains("big.bin"));
    let r = call(&env, "HEAD", "/store/dc-1/vol1", vec![], false, &[]).await;
    assert_eq!(r.status, 200);

    let r = call(
        &env,
        "DELETE",
        "/store/dc-1/vol1/big.bin",
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 204, "{}", r.text());
    let r = call(&env, "GET", "/store/dc-1/vol1/big.bin", vec![], false, &[]).await;
    assert_eq!(r.status, 404);
    assert!(!r.text().contains(&env.secret) && !r.text().contains(ACCESS_KEY));

    let log = env.log();
    assert!(log.contains("store PUT /dc-1/vol1/big.bin 200"), "{log}");
    assert!(!log.contains(&env.secret) && !log.contains(ACCESS_KEY));
}

#[tokio::test(flavor = "multi_thread")]
async fn multipart_upload() {
    let env = setup().await;
    let p = "/store/dc-1/vol1/ckpt/model.safetensors";
    let r = call(&env, "POST", &format!("{p}?uploads"), vec![], false, &[]).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let id = between(&r.text(), "<UploadId>", "</UploadId>").to_string();
    let enc: String = url_encode(&id);

    let parts = [data(5 << 20, 3), data(5 << 20, 4), data(1234, 5)];
    let mut done = String::new();
    for (i, part) in parts.iter().enumerate() {
        let n = i + 1;
        let r = call(
            &env,
            "PUT",
            &format!("{p}?partNumber={n}&uploadId={enc}"),
            part.clone(),
            true,
            &[],
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.text());
        let etag = r.headers["etag"].to_str().unwrap().to_string();
        done.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        ));
    }
    let r = call(
        &env,
        "GET",
        &format!("{p}?uploadId={enc}"),
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().contains("<PartNumber>3</PartNumber>"));
    let xml = format!("<CompleteMultipartUpload>{done}</CompleteMultipartUpload>");
    let r = call(
        &env,
        "POST",
        &format!("{p}?uploadId={enc}"),
        xml.into_bytes(),
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());

    let r = call(&env, "GET", p, vec![], false, &[]).await;
    assert_eq!(r.status, 200);
    assert!(r.body == parts.concat(), "assembled object differs");

    // abort
    let r = call(
        &env,
        "POST",
        "/store/dc-1/vol1/tmp.bin?uploads",
        vec![],
        false,
        &[],
    )
    .await;
    let id = url_encode(between(&r.text(), "<UploadId>", "</UploadId>"));
    let r = call(
        &env,
        "DELETE",
        &format!("/store/dc-1/vol1/tmp.bin?uploadId={id}"),
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 204, "{}", r.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn bodiless_post_says_content_length_zero() {
    let env = setup().await;
    let r = call(
        &env,
        "POST",
        "/store/raw/vol1/k?uploads",
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let head = std::fs::read_to_string(env.dir.path().join("raw-k.txt")).unwrap();
    let head = head.to_ascii_lowercase();
    assert!(head.starts_with("post /vol1/k?uploads= http/1.1"), "{head}");
    assert!(head.contains("\r\ncontent-length: 0\r\n"), "{head}");
    assert!(head.contains("authorization: aws4-hmac-sha256 credential=akidcredproxytest/"));
    assert!(!head.contains("bearer") && !head.contains(&env.secret.to_ascii_lowercase()));
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_what_is_not_allowed() {
    let env = setup().await;
    std::fs::create_dir_all(env.dir.path().join("store/vol1/pub")).unwrap();
    std::fs::write(env.dir.path().join("store/vol1/pub/p.txt"), "p").unwrap();
    std::fs::write(env.dir.path().join("store/vol1/private.txt"), "s").unwrap();
    for (m, p, status) in [
        ("GET", "/store/dc-1/", 403),        // ListBuckets
        ("PUT", "/store/dc-1/vol2", 403),    // CreateBucket
        ("DELETE", "/store/dc-1/vol1", 403), // DeleteBucket
        ("GET", "/store/dc-1/vol1?acl", 403),
        ("GET", "/store/dc-1/vol1", 403),         // ListObjects v1
        ("POST", "/store/dc-1/vol1?delete", 403), // DeleteObjects
        ("GET", "/store/dc-1/vol1/a%2F..%2Fprivate.txt", 403),
        ("GET", "/store/dc-2/vol1/private.txt", 403), // no such route
        ("PUT", "/store/ro/vol1/pub/x", 403),         // op not on this route
        ("GET", "/store/ro/vol1/private.txt", 403),   // outside key_prefixes
        ("GET", "/store/ro/vol1?list-type=2", 403),
    ] {
        let r = call(&env, m, p, vec![], false, &[]).await;
        assert_eq!(r.status, status, "{m} {p}: {}", r.text());
    }
    let r = call(&env, "GET", "/store/ro/vol1/pub/p.txt", vec![], false, &[]).await;
    assert_eq!((r.status, r.body.as_slice()), (200, &b"p"[..]));

    for (v, status) in [
        ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", 400),
        ("STREAMING-UNSIGNED-PAYLOAD-TRAILER", 400),
        ("UNSIGNED-PAYLOAD", 403),
    ] {
        let r = call(
            &env,
            "PUT",
            "/store/dc-1/vol1/x",
            b"abc".to_vec(),
            false,
            &[("x-amz-content-sha256", v)],
        )
        .await;
        assert_eq!(r.status, status, "{v}: {}", r.text());
    }

    // header-selected variants are refused, not turned into something else (CopyObject would become an empty
    // PutObject over the destination)
    std::fs::write(env.dir.path().join("store/vol1/dst.txt"), "keep").unwrap();
    for h in [
        ("x-amz-copy-source", "/vol1/private.txt"),
        ("x-amz-meta-a", "1"),
        ("x-amz-tagging", "a=1"),
        ("x-amz-server-side-encryption", "AES256"),
        ("x-amz-checksum-crc32", "AAAAAA=="),
    ] {
        let r = call(&env, "PUT", "/store/dc-1/vol1/dst.txt", vec![], false, &[h]).await;
        assert_eq!(r.status, 403, "{h:?}: {}", r.text());
    }
    assert_eq!(
        std::fs::read(env.dir.path().join("store/vol1/dst.txt")).unwrap(),
        b"keep"
    );

    // no token, another service's token
    let r = reqwest::get(format!("{}/store/dc-1/vol1/pub/p.txt", env.base))
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = reqwest::Client::new()
        .get(format!("{}/store/dc-1/vol1/pub/p.txt", env.base))
        .header("authorization", format!("Bearer {}", env.token("wrong")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // the server refuses the other access key id; its error reply never shows it
    let r = reqwest::Client::new()
        .get(format!("{}/wrong/dc-1/vol1/pub/p.txt", env.base))
        .header("authorization", format!("Bearer {}", env.token("wrong")))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error(), "{}", r.status());
    let text = r.text().await.unwrap();
    assert!(
        !text.contains("AKIDWRONG") && !text.contains(&env.secret),
        "{text}"
    );
}

/// 600 MB up (one 500 MB part + rest) and down through the proxy; prints the daemon's peak RSS.
/// `cargo test --release --test s3 -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn big_transfer_memory() {
    let env = setup().await;
    let pid = env.daemon.as_ref().unwrap().id().to_string();
    let rss = move || -> u64 {
        let o = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout)
            .trim()
            .parse()
            .unwrap_or(0)
    };
    let peak = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let watcher = {
        let (peak, rss) = (peak.clone(), rss.clone());
        tokio::spawn(async move {
            loop {
                peak.fetch_max(rss(), std::sync::atomic::Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    };
    let before = rss();
    let p = "/store/dc-1/vol1/big600.bin";
    let r = call(&env, "POST", &format!("{p}?uploads"), vec![], false, &[]).await;
    let id = url_encode(between(&r.text(), "<UploadId>", "</UploadId>"));
    let parts = [data(500_000_000, 1), data(100_000_000, 2)];
    let mut done = String::new();
    let t = std::time::Instant::now();
    for (i, part) in parts.iter().enumerate() {
        let n = i + 1;
        let r = call(
            &env,
            "PUT",
            &format!("{p}?partNumber={n}&uploadId={id}"),
            part.clone(),
            true,
            &[],
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.text());
        let etag = r.headers["etag"].to_str().unwrap().to_string();
        done.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        ));
    }
    let xml = format!("<CompleteMultipartUpload>{done}</CompleteMultipartUpload>");
    let r = call(
        &env,
        "POST",
        &format!("{p}?uploadId={id}"),
        xml.into_bytes(),
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let up = t.elapsed();
    let t = std::time::Instant::now();
    let r = call(&env, "GET", p, vec![], false, &[]).await;
    assert_eq!((r.status, r.body.len()), (200, 600_000_000));
    assert_eq!(
        hex_sha256(&r.body),
        hex_sha256(&parts.concat()),
        "600 MB came back different"
    );
    let down = t.elapsed();
    let fast_peak = peak.load(std::sync::atomic::Ordering::Relaxed);
    // a slow reader: the proxy must hold back, not buffer the object
    peak.store(0, std::sync::atomic::Ordering::Relaxed);
    let mut res = reqwest::Client::new()
        .get(format!("{}{p}", env.base))
        .header("authorization", format!("Bearer {}", env.token("store")))
        .header("range", "bytes=0-199999999")
        .send()
        .await
        .unwrap();
    let mut slow = sha2::Sha256::new();
    let mut n = 0usize;
    while let Some(c) = res.chunk().await.unwrap() {
        n += c.len();
        slow.update(&c);
        tokio::time::sleep(Duration::from_micros(300)).await;
    }
    let slow_peak = peak.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(n, 200_000_000);
    let want: String = sha2::Sha256::digest(&parts.concat()[..200_000_000])
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    let got: String = slow.finalize().iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(got, want);
    assert!(
        slow_peak < 64 * 1024,
        "daemon grew to {} MiB under a slow reader",
        slow_peak / 1024
    );
    watcher.abort();
    println!(
        "daemon RSS: {} MiB before, peak {} MiB (slow reader: {} MiB); up {:.1}s, down {:.1}s",
        before / 1024,
        fast_peak / 1024,
        slow_peak / 1024,
        up.as_secs_f64(),
        down.as_secs_f64()
    );
}

// ---- Data integrity: what goes in comes out byte for byte, and failures are errors, never short files. ----

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).unwrap();
    v
}

fn on_disk(env: &Env, rel: &str) -> Vec<u8> {
    std::fs::read(env.dir.path().join("store").join(rel)).unwrap()
}

/// The raw upstream's record of its last request named `name`, waiting up to 5 s for it.
async fn raw_record(env: &Env, name: &str) -> String {
    let f = env.dir.path().join(format!("raw-{name}.txt"));
    for _ in 0..100 {
        if let Ok(s) = std::fs::read_to_string(&f) {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("upstream never saw {name}");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_size_and_byte_value_survives() {
    let env = setup().await;
    let mib = 1usize << 20;
    for (i, n) in [0, 1, 255, mib - 1, mib, mib + 1, 3 * mib + 7]
        .into_iter()
        .enumerate()
    {
        let body = random_bytes(n);
        let sum = hex_sha256(&body);
        // with the client's hash (streamed), and without (hashed here) where that's allowed
        for hashed in [true, false] {
            if !hashed && n > mib {
                continue;
            }
            let key = format!("sizes/{i}-{hashed}.bin");
            let r = call(
                &env,
                "PUT",
                &format!("/store/dc-1/vol1/{key}"),
                body.clone(),
                hashed,
                &[],
            )
            .await;
            assert_eq!(r.status, 200, "PUT {n} hashed={hashed}: {}", r.text());
            assert_eq!(
                hex_sha256(&on_disk(&env, &format!("vol1/{key}"))),
                sum,
                "stored {n}"
            );
            let r = call(
                &env,
                "GET",
                &format!("/store/dc-1/vol1/{key}"),
                vec![],
                false,
                &[],
            )
            .await;
            assert_eq!((r.status, r.body.len()), (200, n));
            assert_eq!(hex_sha256(&r.body), sum, "GET {n} hashed={hashed}");
            let r = call(
                &env,
                "HEAD",
                &format!("/store/dc-1/vol1/{key}"),
                vec![],
                false,
                &[],
            )
            .await;
            assert_eq!(r.status, 200);
            assert_eq!(r.headers["content-length"], n.to_string().as_str());
        }
    }
    // an overwrite replaces the whole object, no old tail left behind
    let p = "/store/dc-1/vol1/over.bin";
    call(&env, "PUT", p, random_bytes(3 * mib), true, &[]).await;
    let r = call(&env, "PUT", p, b"short".to_vec(), true, &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        call(&env, "GET", p, vec![], false, &[]).await.body,
        b"short"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_multipart_is_byte_exact() {
    let env = std::sync::Arc::new(setup().await);
    let p = "/store/dc-1/vol1/ckpt/step-1000/model.safetensors";
    let r = call(&env, "POST", &format!("{p}?uploads"), vec![], false, &[]).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let id = url_encode(between(&r.text(), "<UploadId>", "</UploadId>"));
    let parts: Vec<Vec<u8>> = (0..6)
        .map(|i| random_bytes((5 << 20) + i * 1234 + 1))
        .collect();

    // a part sent with the wrong hash is refused by the server; its retry succeeds
    let r = reqwest::Client::new()
        .put(format!("{}{p}?partNumber=3&uploadId={id}", env.base))
        .header("authorization", format!("Bearer {}", env.token("store")))
        .header("x-amz-content-sha256", hex_sha256(b"not this"))
        .body(parts[2].clone())
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error(), "{}", r.status());

    let mut set = tokio::task::JoinSet::new();
    for (i, part) in parts.iter().enumerate() {
        let (env, part, id) = (env.clone(), part.clone(), id.clone());
        set.spawn(async move {
            let n = i + 1;
            let r = call(
                &env,
                "PUT",
                &format!("{p}?partNumber={n}&uploadId={id}"),
                part,
                true,
                &[],
            )
            .await;
            assert_eq!(r.status, 200, "part {n}: {}", r.text());
            (n, r.headers["etag"].to_str().unwrap().to_string())
        });
    }
    let mut etags = set.join_all().await;
    etags.sort();
    let xml: String = etags
        .iter()
        .map(|(n, e)| format!("<Part><PartNumber>{n}</PartNumber><ETag>{e}</ETag></Part>"))
        .collect();
    let r = call(
        &env,
        "POST",
        &format!("{p}?uploadId={id}"),
        format!("<CompleteMultipartUpload>{xml}</CompleteMultipartUpload>").into_bytes(),
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());

    let whole = parts.concat();
    let r = call(&env, "GET", p, vec![], false, &[]).await;
    assert_eq!(r.body.len(), whole.len());
    assert_eq!(
        hex_sha256(&r.body),
        hex_sha256(&whole),
        "assembled object differs"
    );
    // ranges across every part boundary
    let mut at = 0;
    for part in &parts[..parts.len() - 1] {
        at += part.len();
        let (a, b) = (at - 3, at + 2);
        let r = call(
            &env,
            "GET",
            p,
            vec![],
            false,
            &[("range", &format!("bytes={a}-{b}"))],
        )
        .await;
        assert_eq!((r.status, r.body.as_slice()), (206, &whole[a..=b]));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_gets_exactly_the_client_bytes() {
    let env = setup().await;
    let body = random_bytes((2 << 20) + 3);
    let sum = hex_sha256(&body);
    let r = call(&env, "PUT", "/store/raw/vol1/rec1", body.clone(), true, &[]).await;
    assert_eq!(r.status, 200);
    let rec = raw_record(&env, "rec1").await;
    let lower = rec.to_ascii_lowercase();
    assert!(
        rec.contains(&format!(
            "--- body {} of {} sha256 {sum}",
            body.len(),
            body.len()
        )),
        "{rec}"
    );
    assert!(
        lower.contains(&format!("x-amz-content-sha256: {sum}")),
        "{rec}"
    );
    assert!(!lower.contains("bearer") && !rec.contains(&env.secret));
    // small body, no client hash: the proxy's hash is the body's
    let r = call(
        &env,
        "PUT",
        "/store/raw/vol1/rec2",
        b"small body".to_vec(),
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200);
    let rec = raw_record(&env, "rec2").await.to_ascii_lowercase();
    let sum = hex_sha256(b"small body");
    assert!(
        rec.contains(&format!("x-amz-content-sha256: {sum}")),
        "{rec}"
    );
    assert!(
        rec.contains(&format!("--- body 10 of 10 sha256 {sum}")),
        "{rec}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn truncated_downloads_fail_loudly() {
    let env = setup().await;
    for name in ["truncate-cl", "truncate-chunked"] {
        let res = reqwest::Client::new()
            .get(format!("{}/store/raw/vol1/{name}", env.base))
            .header("authorization", format!("Bearer {}", env.token("store")))
            .send()
            .await;
        // either the reply fails outright or its body does; never a short body that looks complete
        if let Ok(r) = res {
            assert!(
                r.bytes().await.is_err(),
                "{name}: a short body arrived as if complete"
            );
        }
    }
    let r = call(
        &env,
        "GET",
        "/store/raw/vol1/chunked-ok",
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello world"[..]));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log = env.log();
    assert!(
        log.contains("/raw/vol1/truncate-cl reply broke off"),
        "{log}"
    );
    assert!(
        log.contains("/raw/vol1/truncate-chunked reply broke off"),
        "{log}"
    );

    let r = call(
        &env,
        "GET",
        "/store/raw/vol1/error-echo",
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 403);
    assert!(
        r.text().contains("[REDACTED]") && !r.text().contains(ACCESS_KEY),
        "{}",
        r.text()
    );
}

/// Sends `head` then `body` straight to the proxy; `close_after` bytes of body, then hangs up if given.
async fn raw_client(env: &Env, head: String, body: &[u8], close_after: Option<usize>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = env.base.strip_prefix("http://").unwrap();
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(head.as_bytes()).await.unwrap();
    let n = close_after.unwrap_or(body.len());
    let _ = c.write_all(&body[..n]).await;
    if close_after.is_some() {
        return String::new();
    }
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

fn put_head(env: &Env, path: &str, len: usize, sum: &str, extra: &str) -> String {
    format!(
        "PUT {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: {len}\r\nx-amz-content-sha256: {sum}\r\n{extra}\r\n",
        env.base.strip_prefix("http://").unwrap(),
        env.token("store")
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn client_that_hangs_up_mid_upload_never_completes_one() {
    let env = setup().await;
    let body = random_bytes(4 << 20);
    let sum = hex_sha256(&body);
    // upstream sees a short body and a closed connection, not a complete request
    // also UNSIGNED-PAYLOAD, where no hash would catch a short body: only the framing does
    for (name, hash) in [("abort1", sum.as_str()), ("abort2", "UNSIGNED-PAYLOAD")] {
        let head = put_head(
            &env,
            &format!("/store/raw/vol1/{name}"),
            body.len(),
            hash,
            "",
        );
        raw_client(&env, head, &body, Some(1 << 20)).await;
        let rec = raw_record(&env, name).await;
        let got: usize = between(&rec, "--- body ", " of").parse().unwrap();
        let declared: usize = between(&rec, " of ", " sha256").parse().unwrap();
        assert_eq!(
            declared,
            body.len(),
            "upstream was told another length: {rec}"
        );
        assert!(got < body.len(), "upstream got the whole body: {rec}");
    }

    // against a real S3 server: an existing object is left as it was
    let p = "/store/dc-1/vol1/abort.bin";
    call(&env, "PUT", p, b"keep".to_vec(), true, &[]).await;
    raw_client(
        &env,
        put_head(&env, p, body.len(), &sum, ""),
        &body,
        Some(1 << 20),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r = call(&env, "GET", p, vec![], false, &[]).await;
    assert_eq!((r.status, r.body.as_slice()), (200, &b"keep"[..]));
}

#[tokio::test(flavor = "multi_thread")]
async fn expect_100_continue_uploads() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // what the AWS CLI and boto3 send for uploads
    let env = setup().await;
    let body = random_bytes((1 << 20) + 5);
    let sum = hex_sha256(&body);
    let head = put_head(
        &env,
        "/store/dc-1/vol1/expect.bin",
        body.len(),
        &sum,
        "Expect: 100-continue\r\n",
    );
    let mut c = tokio::net::TcpStream::connect(env.base.strip_prefix("http://").unwrap())
        .await
        .unwrap();
    c.write_all(head.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(10), c.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 100 Continue"));
    c.write_all(&body).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    assert_eq!(hex_sha256(&on_disk(&env, "vol1/expect.bin")), sum);
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[tokio::test(flavor = "multi_thread")]
async fn odd_keys_round_trip_and_list_completely() {
    let env = setup().await;
    const CHARS: &[char] = &[
        'a', 'Z', '0', '-', '.', '_', '~', ' ', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';',
        '=', ':', '@', '%', '#', '?', '[', ']', '"', '^', '`', '{', '}', '|', 'é', 'ж', '中', '😀',
    ];
    let mut rnd = random_bytes(8192).into_iter().cycle();
    let mut keys = std::collections::BTreeSet::new();
    while keys.len() < 60 {
        let dir = if rnd.next().unwrap().is_multiple_of(2) {
            "odd/"
        } else {
            "odd/sub dir/"
        };
        let len = 1 + rnd.next().unwrap() as usize % 20;
        let name: String = (0..len)
            .map(|_| CHARS[rnd.next().unwrap() as usize % CHARS.len()])
            .collect();
        if name == "." || name == ".." {
            continue;
        }
        keys.insert(format!("{dir}{name}"));
    }
    for k in &keys {
        let enc = k.split('/').map(url_encode).collect::<Vec<_>>().join("/");
        let r = call(
            &env,
            "PUT",
            &format!("/store/dc-1/vol1/{enc}"),
            k.as_bytes().to_vec(),
            true,
            &[],
        )
        .await;
        assert_eq!(r.status, 200, "PUT {k:?}: {}", r.text());
        let r = call(
            &env,
            "GET",
            &format!("/store/dc-1/vol1/{enc}"),
            vec![],
            false,
            &[],
        )
        .await;
        assert_eq!(
            (r.status, r.body.as_slice()),
            (200, k.as_bytes()),
            "GET {k:?}"
        );
    }
    // paginated listing finds every key exactly once
    let mut seen = Vec::new();
    let mut token: Option<String> = None;
    for _ in 0..100 {
        let mut q = "list-type=2&prefix=odd%2F&max-keys=7".to_string();
        if let Some(t) = &token {
            q.push_str(&format!("&continuation-token={}", url_encode(t)));
        }
        let r = call(
            &env,
            "GET",
            &format!("/store/dc-1/vol1?{q}"),
            vec![],
            false,
            &[],
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.text());
        let t = r.text();
        for chunk in t.split("<Key>").skip(1) {
            seen.push(xml_unescape(chunk.split("</Key>").next().unwrap()));
        }
        if t.contains("<IsTruncated>true</IsTruncated>") {
            token = Some(xml_unescape(between(
                &t,
                "<NextContinuationToken>",
                "</NextContinuationToken>",
            )));
        } else {
            break;
        }
    }
    let unique: std::collections::BTreeSet<String> = seen.iter().cloned().collect();
    assert_eq!(unique.len(), seen.len(), "a key was listed twice");
    assert_eq!(unique, keys);
}

/// An upstream that stops sending mid-body is cut off (s3_idle) and the client sees an error.
#[tokio::test(flavor = "multi_thread")]
async fn stalled_download_is_cut_off() {
    let env = setup().await;
    let t = std::time::Instant::now();
    let r = reqwest::Client::new()
        .get(format!("{}/store/raw/vol1/stall", env.base))
        .header("authorization", format!("Bearer {}", env.token("store")))
        .send()
        .await
        .unwrap();
    assert!(
        r.bytes().await.is_err(),
        "a stalled body arrived as if complete"
    );
    let waited = t.elapsed().as_secs();
    assert!(
        (1..6).contains(&waited),
        "cut off after {waited}s (s3_idle is 2s)"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let log = env.log();
    assert!(
        log.contains("store GET /raw/vol1/stall cut off: no progress for 2s"),
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn chunked_upload_without_length_is_refused() {
    let env = setup().await;
    let sum = hex_sha256(b"hello");
    let head = format!(
        "PUT /store/dc-1/vol1/chunked.bin HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nTransfer-Encoding: chunked\r\nx-amz-content-sha256: {sum}\r\n\r\n",
        env.base.strip_prefix("http://").unwrap(),
        env.token("store")
    );
    let out = raw_client(&env, head, b"5\r\nhello\r\n0\r\n\r\n", None).await;
    assert!(out.starts_with("HTTP/1.1 411"), "{out}");
    assert!(!env.dir.path().join("store/vol1/chunked.bin").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn unsigned_payload_round_trip_is_byte_exact() {
    let env = setup().await;
    let body = random_bytes((3 << 20) + 11);
    let p = "/store/unsigned/vol1/u.bin";
    let r = call(
        &env,
        "PUT",
        p,
        body.clone(),
        false,
        &[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(hex_sha256(&on_disk(&env, "vol1/u.bin")), hex_sha256(&body));
    let r = call(&env, "GET", p, vec![], false, &[]).await;
    assert_eq!(hex_sha256(&r.body), hex_sha256(&body));
}

#[tokio::test(flavor = "multi_thread")]
async fn complete_with_error_body_is_not_a_success() {
    let env = setup().await;
    let xml = b"<CompleteMultipartUpload/>".to_vec();
    let r = call(
        &env,
        "POST",
        "/store/raw/vol1/complete-error?uploadId=u1",
        xml.clone(),
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 502, "{}", r.text());
    assert!(r.text().contains("InternalError"));
    let r = call(
        &env,
        "POST",
        "/store/raw/vol1/complete-ok?uploadId=u1",
        xml,
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().contains("<CompleteMultipartUploadResult>"));
}

#[tokio::test(flavor = "multi_thread")]
async fn conditional_and_object_headers_reach_upstream() {
    let env = setup().await;
    let cond = [
        ("range", "bytes=100-"),
        ("if-range", "\"etag-1\""),
        ("if-unmodified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ("if-match", "\"etag-1\""),
    ];
    call(&env, "GET", "/store/raw/vol1/cond", vec![], false, &cond).await;
    let rec = raw_record(&env, "cond").await.to_ascii_lowercase();
    let signed = between(&rec, "signedheaders=", ",").to_string();
    for (n, v) in cond {
        assert!(
            rec.contains(&format!("{n}: {}", v.to_ascii_lowercase())),
            "{n} missing:\n{rec}"
        );
        assert!(
            signed.split(';').any(|h| h == n),
            "{n} not signed: {signed}"
        );
    }
    let obj = [
        ("content-encoding", "gzip"),
        ("content-disposition", "attachment; filename=\"a.bin\""),
        ("cache-control", "no-cache"),
        ("content-type", "application/octet-stream"),
    ];
    call(
        &env,
        "PUT",
        "/store/raw/vol1/objhdr",
        b"x".to_vec(),
        true,
        &obj,
    )
    .await;
    let rec = raw_record(&env, "objhdr").await.to_ascii_lowercase();
    for (n, v) in obj {
        assert!(
            rec.contains(&format!("{n}: {}", v.to_ascii_lowercase())),
            "{n} missing:\n{rec}"
        );
    }

    // against the real server (s3s-fs checks preconditions on writes): a failed one stops the call
    let p = "/store/dc-1/vol1/cond.bin";
    call(&env, "PUT", p, b"version 2".to_vec(), true, &[]).await;
    for h in [("if-match", "\"not-the-etag\""), ("if-none-match", "*")] {
        let r = call(&env, "PUT", p, b"version 3".to_vec(), true, &[h]).await;
        assert_eq!(r.status, 412, "{h:?}: {}", r.text());
    }
    // refused: aws-chunked bodies, a header given twice
    let r = call(
        &env,
        "PUT",
        p,
        b"abc".to_vec(),
        true,
        &[("content-encoding", "aws-chunked")],
    )
    .await;
    assert_eq!(r.status, 400, "{}", r.text());
    let r = call(
        &env,
        "GET",
        p,
        vec![],
        false,
        &[("range", "bytes=0-1"), ("range", "bytes=5-6")],
    )
    .await;
    assert_eq!(r.status, 400, "{}", r.text());
    assert_eq!(
        call(&env, "GET", p, vec![], false, &[]).await.body,
        b"version 2"
    );
}

// ---- Claims, edge replies, interruptions, load ----

fn status_of(env: &Env, service: &str) -> String {
    let out = String::from_utf8_lossy(&env.cli(&["status"]).stdout).into_owned();
    out.lines()
        .find(|l| l.trim_start().starts_with(&format!("{service}:")))
        .unwrap_or("")
        .trim()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_calls_never_unlock() {
    let env = setup().await;
    assert!(status_of(&env, "store").starts_with("store: locked"));
    let bad_hash = "0".repeat(63);
    type Case<'a> = (&'a str, &'a str, Vec<u8>, Vec<(&'a str, &'a str)>);
    let cases: Vec<Case> = vec![
        ("GET", "/store/dc-1/", vec![], vec![]), // ListBuckets
        ("GET", "/store/dc-1/vol1?acl", vec![], vec![]), // not an operation we allow
        ("PUT", "/store/ro/vol1/pub/x", b"x".to_vec(), vec![]), // not on this route
        ("GET", "/store/ro/vol1/other", vec![], vec![]), // outside key_prefixes
        ("GET", "/store/dc-1/vol1/a%2F..%2Fb", vec![], vec![]), // bad key
        ("GET", "/store/dc-9/vol1/a", vec![], vec![]), // no such route
        (
            "PUT",
            "/store/dc-1/vol1/a",
            b"x".to_vec(),
            vec![("x-amz-copy-source", "/vol1/b")],
        ),
        (
            "PUT",
            "/store/dc-1/vol1/a",
            b"x".to_vec(),
            vec![("x-amz-content-sha256", &bad_hash)],
        ),
        (
            "PUT",
            "/store/dc-1/vol1/a",
            b"x".to_vec(),
            vec![("x-amz-content-sha256", "UNSIGNED-PAYLOAD")],
        ),
        (
            "PUT",
            "/store/dc-1/vol1/a",
            b"x".to_vec(),
            vec![("content-encoding", "aws-chunked")],
        ),
        (
            "GET",
            "/store/dc-1/vol1/a",
            vec![],
            vec![("range", "bytes=0-1"), ("range", "bytes=2-3")],
        ),
    ];
    for (m, p, body, h) in &cases {
        let r = call(&env, m, p, body.clone(), false, h).await;
        assert!(
            r.status == 400 || r.status == 403,
            "{m} {p}: {} {}",
            r.status,
            r.text()
        );
    }
    // a header value that isn't ASCII would be dropped on the way: refused instead
    let head = put_head(
        &env,
        "/store/dc-1/vol1/a",
        1,
        &hex_sha256(b"x"),
        "Content-Disposition: attachment; filename=\"модель.bin\"\r\n",
    );
    let out = raw_client(&env, head, b"x", None).await;
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    assert!(out.contains("content-disposition"), "{out}");
    // a wrong or missing token never gets that far either
    let r = reqwest::get(format!("{}/store/dc-1/vol1/a", env.base))
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(
        status_of(&env, "store").starts_with("store: locked"),
        "{}",
        status_of(&env, "store")
    );
    assert!(!env.log().contains("store unlocked"));
    // the first allowed call does unlock
    let r = call(&env, "PUT", "/store/dc-1/vol1/a", b"x".to_vec(), false, &[]).await;
    assert_eq!(r.status, 200);
    assert!(status_of(&env, "store").starts_with("store: unlocked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_replies_pass_through_correctly() {
    let env = setup().await;
    // 304 keeps its validators
    let r = call(
        &env,
        "GET",
        "/store/raw/vol1/not-modified",
        vec![],
        false,
        &[("if-none-match", "\"e1\"")],
    )
    .await;
    assert_eq!(r.status, 304);
    assert_eq!(r.headers["etag"], "\"e1\"");
    assert!(r.headers.get("last-modified").is_some());
    // a redirect is passed back, not followed, and without its Location
    let r = call(&env, "GET", "/store/raw/vol1/redirect", vec![], false, &[]).await;
    assert_eq!(r.status, 307);
    assert!(r.headers.get("location").is_none());
    // against the real server: a range past the end, a missing object by HEAD
    call(
        &env,
        "PUT",
        "/store/dc-1/vol1/ten",
        b"0123456789".to_vec(),
        true,
        &[],
    )
    .await;
    let r = call(
        &env,
        "GET",
        "/store/dc-1/vol1/ten",
        vec![],
        false,
        &[("range", "bytes=100-200")],
    )
    .await;
    assert_eq!(r.status, 416, "{}", r.text());
    let r = call(
        &env,
        "GET",
        "/store/dc-1/vol1/ten",
        vec![],
        false,
        &[("range", "bytes=-3")],
    )
    .await;
    assert_eq!((r.status, r.body.as_slice()), (206, &b"789"[..]));
    let r = call(&env, "HEAD", "/store/dc-1/vol1/missing", vec![], false, &[]).await;
    assert_eq!((r.status, r.body.len()), (404, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn log_shows_paths_but_never_queries_or_secrets() {
    let env = setup().await;
    let p = "/store/dc-1/vol1/logged.bin";
    let r = call(&env, "POST", &format!("{p}?uploads"), vec![], false, &[]).await;
    let id = url_encode(between(&r.text(), "<UploadId>", "</UploadId>"));
    let r = call(
        &env,
        "PUT",
        &format!("{p}?partNumber=1&uploadId={id}"),
        b"part".to_vec(),
        true,
        &[],
    )
    .await;
    assert_eq!(r.status, 200);
    call(
        &env,
        "GET",
        "/store/dc-1/vol1?list-type=2&prefix=secret-prefix/",
        vec![],
        false,
        &[],
    )
    .await;
    let log = env.log();
    assert!(log.contains("store PUT /dc-1/vol1/logged.bin 200"), "{log}");
    for bad in [
        "uploadId",
        "partNumber",
        "secret-prefix",
        "?",
        ACCESS_KEY,
        &env.secret,
        &env.token("store"),
    ] {
        assert!(!log.contains(bad), "log contains {bad:?}:\n{log}");
    }
}

/// Writes the head and the first half of `body`, runs `between_halves`, then the rest; returns the reply.
async fn upload_in_two_halves(
    env: &Env,
    path: &str,
    body: &[u8],
    between_halves: impl FnOnce(),
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let head = put_head(env, path, body.len(), &hex_sha256(body), "");
    let mut c = tokio::net::TcpStream::connect(env.base.strip_prefix("http://").unwrap())
        .await
        .unwrap();
    c.write_all(head.as_bytes()).await.unwrap();
    c.write_all(&body[..body.len() / 2]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    between_halves();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = c.write_all(&body[body.len() / 2..]).await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_during_an_upload_lets_it_finish_intact() {
    let env = setup().await;
    let body = random_bytes(4 << 20);
    let out = upload_in_two_halves(&env, "/store/dc-1/vol1/locked.bin", &body, || {
        assert!(env.cli(&["lock"]).status.success());
    })
    .await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert_eq!(
        hex_sha256(&on_disk(&env, "vol1/locked.bin")),
        hex_sha256(&body)
    );
    assert!(status_of(&env, "store").starts_with("store: locked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_stop_during_an_upload_never_completes_it() {
    let mut env = setup().await;
    let body = random_bytes(4 << 20);
    let out = upload_in_two_halves(&env, "/store/raw/vol1/stopped", &body, || {
        assert!(env.cli(&["stop"]).status.success());
    })
    .await;
    assert!(!out.starts_with("HTTP/1.1 200"), "{out}");
    let rec = raw_record(&env, "stopped").await;
    let got: usize = between(&rec, "--- body ", " of").parse().unwrap();
    assert!(got < body.len(), "upstream got the whole body: {rec}");
    if let Some(mut d) = env.daemon.take() {
        let _ = d.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn parts_refused_at_the_connection_limit_retry_and_assemble_exactly() {
    let env = std::sync::Arc::new(setup().await);
    let p = "/store/dc-1/vol1/many.bin";
    let r = call(&env, "POST", &format!("{p}?uploads"), vec![], false, &[]).await;
    let id = url_encode(between(&r.text(), "<UploadId>", "</UploadId>"));
    let parts: Vec<Vec<u8>> = (0..6).map(|i| random_bytes((5 << 20) + i)).collect();
    let token = env.token("store");
    // fill all 64 connection slots with idle connections (the proxy gives them 10 s to send their headers)
    let addr = env.base.strip_prefix("http://").unwrap().to_string();
    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(tokio::net::TcpStream::connect(&addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut set = tokio::task::JoinSet::new();
    for (i, part) in parts.iter().enumerate() {
        let (base, part, id, token) = (env.base.clone(), part.clone(), id.clone(), token.clone());
        set.spawn(async move {
            let n = i + 1;
            for attempt in 0..200 {
                let r = reqwest::Client::new()
                    .put(format!("{base}{p}?partNumber={n}&uploadId={id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-amz-content-sha256", hex_sha256(&part))
                    .body(part.clone())
                    .send()
                    .await;
                if let Ok(r) = r
                    && r.status() == 200
                {
                    return (
                        n,
                        r.headers()["etag"].to_str().unwrap().to_string(),
                        attempt,
                    );
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("part {n} never went through");
        });
    }
    // free the slots after a second
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(held);
    let mut etags = set.join_all().await;
    etags.sort();
    assert!(
        etags.iter().all(|(_, _, a)| *a > 0),
        "every part should have been refused at first: {etags:?}"
    );
    assert!(
        env.log().contains("connection limit (64) reached"),
        "{}",
        env.log()
    );
    let xml: String = etags
        .iter()
        .map(|(n, e, _)| format!("<Part><PartNumber>{n}</PartNumber><ETag>{e}</ETag></Part>"))
        .collect();
    let r = call(
        &env,
        "POST",
        &format!("{p}?uploadId={id}"),
        format!("<CompleteMultipartUpload>{xml}</CompleteMultipartUpload>").into_bytes(),
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let r = call(&env, "GET", p, vec![], false, &[]).await;
    assert_eq!(hex_sha256(&r.body), hex_sha256(&parts.concat()));
}

/// A client that stops sending mid-upload is cut off (s3_idle); upstream never gets a complete request.
#[tokio::test(flavor = "multi_thread")]
async fn stalled_upload_is_cut_off() {
    use tokio::io::AsyncWriteExt;
    let env = setup().await;
    let body = random_bytes(2 << 20);
    let head = put_head(
        &env,
        "/store/raw/vol1/stalled-up",
        body.len(),
        &hex_sha256(&body),
        "",
    );
    let mut c = tokio::net::TcpStream::connect(env.base.strip_prefix("http://").unwrap())
        .await
        .unwrap();
    c.write_all(head.as_bytes()).await.unwrap();
    c.write_all(&body[..1 << 20]).await.unwrap();
    let t = std::time::Instant::now();
    let rec = loop {
        if let Ok(s) = std::fs::read_to_string(env.dir.path().join("raw-stalled-up.txt")) {
            break s;
        }
        assert!(
            t.elapsed() < Duration::from_secs(15),
            "upstream request never ended"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let waited = t.elapsed().as_secs();
    let got: usize = between(&rec, "--- body ", " of").parse().unwrap();
    assert!(got < body.len(), "{rec}");
    assert!(
        (1..6).contains(&waited),
        "cut off after {waited}s (s3_idle is 2s)"
    );
    drop(c);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let log = env.log();
    assert!(
        log.contains("store PUT /raw/vol1/stalled-up cut off: no progress for 2s"),
        "{log}"
    );
}

/// boto3 configured as the README says, through the proxy (put, get, head, multipart upload_file and
/// download_file, ranged get, list, delete; copy refused). Runs when CREDPROXY_TEST_PYTHON is a python with boto3.
#[tokio::test(flavor = "multi_thread")]
async fn boto3_through_the_proxy() {
    let Ok(python) = std::env::var("CREDPROXY_TEST_PYTHON") else {
        eprintln!("skipped: set CREDPROXY_TEST_PYTHON to a python with boto3");
        return;
    };
    let env = setup().await;
    // the proxy unlocks on boto3's first call; the client only has the token
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/boto3_client.py");
    let scratch = env.dir.path().join("boto");
    std::fs::create_dir_all(&scratch).unwrap();
    let out = tokio::process::Command::new(python)
        .arg("-I")
        .arg(script)
        .arg(format!("{}/store/dc-1", env.base))
        .arg("dc-1")
        .arg("vol1")
        .arg(env.token("store"))
        .arg(&scratch)
        .output()
        .await
        .unwrap();
    let (so, se) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        out.status.success() && so.trim() == "ok",
        "stdout:\n{so}\nstderr:\n{se}\nlog:\n{}",
        env.log()
    );
}

/// A client that stops reading a download is cut off (the watchdog: nothing polls the stream then).
#[tokio::test(flavor = "multi_thread")]
async fn client_that_stops_reading_is_cut_off() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let env = setup().await;
    let body = random_bytes(64 << 20);
    let r = call(
        &env,
        "PUT",
        "/store/dc-1/vol1/unread.bin",
        body.clone(),
        true,
        &[],
    )
    .await;
    assert_eq!(r.status, 200);
    let mut c = tokio::net::TcpStream::connect(env.base.strip_prefix("http://").unwrap())
        .await
        .unwrap();
    let head = format!(
        "GET /store/dc-1/vol1/unread.bin HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n\r\n",
        env.base.strip_prefix("http://").unwrap(),
        env.token("store")
    );
    c.write_all(head.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut got = Vec::new();
    let done = tokio::time::timeout(Duration::from_secs(20), c.read_to_end(&mut got)).await;
    assert!(done.is_ok(), "the proxy kept the stalled download open");
    assert!(got.len() < body.len(), "the whole body arrived anyway");
    let log = env.log();
    assert!(
        log.contains("store GET /dc-1/vol1/unread.bin cut off: no progress for 2s"),
        "{log}"
    );
}

/// An upstream that stops accepting an upload's bytes (and never replies) is cut off.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_that_stops_reading_is_cut_off() {
    let env = setup().await;
    let body = random_bytes(64 << 20);
    let t = std::time::Instant::now();
    let r = reqwest::Client::new()
        .put(format!("{}/store/raw/vol1/no-read", env.base))
        .header("authorization", format!("Bearer {}", env.token("store")))
        .header("x-amz-content-sha256", hex_sha256(&body))
        .body(body)
        .send()
        .await;
    let waited = t.elapsed().as_secs();
    assert!(r.is_err() || !r.unwrap().status().is_success());
    assert!(
        (1..10).contains(&waited),
        "cut off after {waited}s (s3_idle is 2s)"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let log = env.log();
    assert!(
        log.contains("store PUT /raw/vol1/no-read cut off: no progress for 2s"),
        "{log}"
    );
}

/// An upstream silent for too long after the request gets a 504 saying the outcome is unknown, not a hang: after
/// s3_idle (2 s here) for a read, after s3_reply_wait (3 s) for an upload or a completion.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_too_slow_to_reply_is_a_504() {
    let env = setup().await;
    // unlock first, so the timings below are the proxy's waits only
    assert_eq!(
        call(&env, "GET", "/store/raw/vol1/warm-up", vec![], false, &[])
            .await
            .status,
        200
    );
    for (method, path, body, min, max) in [
        // a small request's clock includes connecting (s3_connect_timeout, 1 s here): s3_idle (2 s) + 1 s for a
        // read, s3_reply_wait (3 s) + 1 s for a completion
        ("GET", "/store/raw/vol1/slow-reply", vec![], 2900, 3900),
        (
            "POST",
            "/store/raw/vol1/slow-reply?uploadId=u1",
            b"<CompleteMultipartUpload/>".to_vec(),
            3900,
            5500,
        ),
    ] {
        let t = std::time::Instant::now();
        let r = call(&env, method, path, body, false, &[]).await;
        let waited = t.elapsed().as_millis();
        assert_eq!(r.status, 504, "{method} {path}: {}", r.text());
        assert!(r.text().contains("outcome is unknown"), "{}", r.text());
        assert!(
            (min..max).contains(&waited),
            "{method} {path}: 504 after {waited} ms"
        );
    }
}

/// A CompleteMultipartUpload reply that trickles in (headers, keep-alive spaces past s3_idle, then the result) is
/// the upstream working, not a stall.
#[tokio::test(flavor = "multi_thread")]
async fn trickling_complete_reply_is_not_cut() {
    let env = setup().await;
    let r = call(
        &env,
        "POST",
        "/store/raw/vol1/complete-trickle?uploadId=u1",
        b"<CompleteMultipartUpload/>".to_vec(),
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(
        r.text().contains("<CompleteMultipartUploadResult>"),
        "{}",
        r.text()
    );
}

/// s3_reply_wait (+ s3_connect_timeout: 4 s here) bounds the whole completion reply, counted from the request:
/// late headers don't buy the body another full wait.
#[tokio::test(flavor = "multi_thread")]
async fn completion_reply_is_bounded_from_the_request() {
    let env = setup().await;
    assert_eq!(
        call(&env, "GET", "/store/raw/vol1/warm-up", vec![], false, &[])
            .await
            .status,
        200
    );
    let t = std::time::Instant::now();
    let r = call(
        &env,
        "POST",
        "/store/raw/vol1/complete-late?uploadId=u1",
        b"<CompleteMultipartUpload/>".to_vec(),
        false,
        &[],
    )
    .await;
    let waited = t.elapsed().as_millis();
    assert_eq!(r.status, 504, "{}", r.text());
    assert!(r.text().contains("outcome is unknown"));
    assert!((3900..4900).contains(&waited), "504 after {waited} ms");
}

/// A streamed upload whose upstream stays silent past s3_reply_wait gets a 504 (the outcome is unknown).
#[tokio::test(flavor = "multi_thread")]
async fn upload_with_no_reply_is_a_504() {
    let env = setup().await;
    let t = std::time::Instant::now();
    let r = call(
        &env,
        "PUT",
        "/store/raw/vol1/slow-reply",
        random_bytes(3 << 20),
        true,
        &[],
    )
    .await;
    let waited = t.elapsed().as_secs();
    assert_eq!(r.status, 504, "{}", r.text());
    assert!((3..8).contains(&waited), "504 after {waited}s");
}

/// After a streamed upload the upstream may be silent past s3_idle (2 s here) while it works, as long as it replies
/// within s3_reply_wait (3 s): that silence is not a stall.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_working_after_an_upload_is_not_a_stall() {
    let env = setup().await;
    let body = random_bytes(3 << 20);
    let r = call(
        &env,
        "PUT",
        "/store/raw/vol1/pause-reply",
        body.clone(),
        true,
        &[],
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let rec = raw_record(&env, "pause-reply").await;
    assert!(
        rec.contains(&format!("--- body {} of {}", body.len(), body.len())),
        "{rec}"
    );
}

/// Replies that can't prove they're complete are refused: a 200 with no length (a cut connection would look the
/// same), a completion reply that's empty or cut off, a request whose upstream hung up after it was sent. Where the
/// call changes state, the refusal says the outcome is unknown.
#[tokio::test(flavor = "multi_thread")]
async fn replies_that_cannot_prove_completeness_are_refused() {
    let env = setup().await;
    let r = call(
        &env,
        "GET",
        "/store/raw/vol1/close-delimited",
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 502, "{}", r.text());
    assert!(
        r.text().contains("no length") && !r.text().contains("outcome is unknown"),
        "{}",
        r.text()
    );
    for name in ["complete-empty", "complete-cut"] {
        let r = call(
            &env,
            "POST",
            &format!("/store/raw/vol1/{name}?uploadId=u1"),
            b"<CompleteMultipartUpload/>".to_vec(),
            false,
            &[],
        )
        .await;
        assert_eq!(r.status, 502, "{name}: {}", r.text());
        assert!(
            r.text().contains("outcome is unknown"),
            "{name}: {}",
            r.text()
        );
    }
    let r = call(
        &env,
        "PUT",
        "/store/raw/vol1/reset-after-body",
        random_bytes(2 << 20),
        true,
        &[],
    )
    .await;
    assert_eq!(r.status, 502, "{}", r.text());
    assert!(r.text().contains("outcome is unknown"), "{}", r.text());
    // a read that fails isn't "unknown": nothing changed
    let r = call(
        &env,
        "GET",
        "/store/raw/vol1/reset-after-body",
        vec![],
        false,
        &[],
    )
    .await;
    assert_eq!(r.status, 502, "{}", r.text());
    assert!(!r.text().contains("outcome is unknown"), "{}", r.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn throttling_and_broken_bodies_are_reported_as_such() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let env = setup().await;
    // a throttled client gets told how long to back off
    let r = call(
        &env,
        "PUT",
        "/store/raw/vol1/throttle",
        b"x".to_vec(),
        true,
        &[],
    )
    .await;
    assert_eq!(r.status, 503);
    assert_eq!(r.headers["retry-after"], "5");
    // a client that stops mid-body (half-closes after 10 of 100 bytes) is a broken body, not a too-large one
    let addr = env.base.strip_prefix("http://").unwrap();
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /store/raw/vol1/brokenbody?uploadId=u1 HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\nContent-Length: 100\r\n\r\n<Complete",
        env.token("store")
    );
    c.write_all(head.as_bytes()).await.unwrap();
    c.shutdown().await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log = env.log();
    assert!(log.contains("store POST /raw/vol1/brokenbody 400"), "{log}");
}

/// A state-changing request that can't even connect reached nothing: "cannot connect", not "outcome unknown".
#[tokio::test(flavor = "multi_thread")]
async fn failing_to_connect_is_not_an_unknown_outcome() {
    let env = setup().await;
    for (m, p, body, hash) in [
        ("DELETE", "/store/down/vol1/k", vec![], false),
        (
            "POST",
            "/store/down/vol1/k?uploadId=u1",
            b"<CompleteMultipartUpload/>".to_vec(),
            false,
        ),
        ("PUT", "/store/down/vol1/k", random_bytes(2 << 20), true),
    ] {
        let r = call(&env, m, p, body, hash, &[]).await;
        assert_eq!(r.status, 502, "{m} {p}: {}", r.text());
        assert!(r.text().contains("cannot connect"), "{m} {p}: {}", r.text());
        assert!(
            !r.text().contains("outcome is unknown"),
            "{m} {p}: {}",
            r.text()
        );
    }
}
