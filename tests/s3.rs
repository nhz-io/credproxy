//! S3 with SigV4 end to end: real daemon, real `age`, and an S3 server (s3s-fs, in process) that checks every
//! signature and payload hash. The client only ever has the credproxy token.

use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::Digest;
use std::path::PathBuf;
use std::process::{Child, Command, Output};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_credproxy");
const ACCESS_KEY: &str = "AKIDCREDPROXYTEST";

struct Env {
    dir: tempfile::TempDir,
    cfg: PathBuf,
    secret: String,
    base: String,
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

impl Env {
    fn cli(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .env("CREDPROXY_CONFIG", &self.cfg)
            .output()
            .unwrap()
    }

    fn token(&self, service: &str) -> String {
        let o = self.cli(&["token", service]);
        assert!(o.status.success());
        String::from_utf8(o.stdout).unwrap().trim().to_string()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("credproxy.log")).unwrap_or_default()
    }
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

fn seal(public: &str, file: PathBuf, content: &str) {
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let mut age = Command::new("age")
        .args(["-r", public, "-o"])
        .arg(file)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(age.stdin.as_mut().unwrap(), content.as_bytes()).unwrap();
    assert!(age.wait().unwrap().success());
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

/// Records the head of each request it gets in `file`, answers 200 with an empty body.
async fn raw_server(file: PathBuf) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 16384];
            let n = c.read(&mut buf).await.unwrap_or(0);
            std::fs::write(&file, &buf[..n]).unwrap();
            let _ = c
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
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
    let raw = raw_server(d.join("raw-request.txt")).await;

    sh(Command::new("age-keygen").arg("-o").arg(d.join("id.txt")));
    let public =
        String::from_utf8(sh(Command::new("age-keygen").arg("-y").arg(d.join("id.txt"))).stdout)
            .unwrap();
    seal(
        public.trim(),
        d.join("secrets/s3/key.age"),
        &format!("{ACCESS_KEY}\n{secret}\n"),
    );
    // same secret, another access key id: the server refuses it
    seal(
        public.trim(),
        d.join("secrets/s3/wrong.age"),
        &format!("AKIDWRONG\n{secret}\n"),
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
s3 = {{ region = "dc-1", ops = ["CreateMultipartUpload"] }}

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
    let daemon = Command::new(BIN)
        .arg("serve")
        .env("CREDPROXY_CONFIG", &cfg)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut env = Env {
        dir,
        cfg,
        secret,
        base: format!("http://127.0.0.1:{listen}"),
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
    let head = std::fs::read_to_string(env.dir.path().join("raw-request.txt")).unwrap();
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
    let down = t.elapsed();
    watcher.abort();
    println!(
        "daemon RSS: {} MiB before, peak {} MiB; up {:.1}s, down {:.1}s",
        before / 1024,
        peak.load(std::sync::atomic::Ordering::Relaxed) / 1024,
        up.as_secs_f64(),
        down.as_secs_f64()
    );
}
