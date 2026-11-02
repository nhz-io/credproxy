//! The daemon: HTTP on the fixed loopback address for proxied calls, Unix control socket (0700 dir) for
//! unlock/lock/status. Normally run by launchd (`credproxy install`).

use crate::config::{self, Config};
use crate::log;
use crate::proxy;
use crate::vault::{Vault, private_dir};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{Notify, Semaphore};

pub fn socket_path(cfg: &Config) -> PathBuf {
    cfg.runtime_dir.join("ctl.sock")
}

/// No core dumps (they would hold the key) and, on macOS, no debugger attach.
fn harden() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    #[cfg(target_os = "macos")]
    unsafe {
        const PT_DENY_ATTACH: libc::c_int = 31;
        libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

pub fn run(cfg_path: &Path) -> Result<(), String> {
    let cfg = config::load(cfg_path)?;
    harden();
    // Any panic ends the process: launchd restarts it after a crash. Without this a panic could leave a daemon
    // that runs but fails every request (e.g. a poisoned lock) and is never restarted.
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        std::process::abort();
    }));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(serve(cfg))
}

/// At most this many client connections at once; more are closed right away.
const MAX_CONNECTIONS: usize = 64;
/// One request per connection, and no connection lives longer than this (unlock wait + upstream + slack)...
const CONNECTION_LIFETIME: Duration = Duration::from_secs(300);
/// ...unless it is an S3 call: the longest upstream call (a transfer) plus the same slack.
const S3_CONNECTION_LIFETIME: Duration = proxy::S3_TIMEOUT.saturating_add(CONNECTION_LIFETIME);
/// How long to keep trying the port when it's busy (e.g. the previous daemon still releasing it).
const BIND_RETRY: Duration = Duration::from_secs(30);

/// Run a connection until it ends or its lifetime is up: CONNECTION_LIFETIME, or S3_CONNECTION_LIFETIME once
/// `long` says it carries an S3 call. Dropping the future closes the connection.
async fn within_lifetime<F: std::future::Future>(conn: F, long: &std::sync::atomic::AtomicBool) {
    tokio::pin!(conn);
    if tokio::time::timeout(CONNECTION_LIFETIME, &mut conn)
        .await
        .is_err()
        && long.load(std::sync::atomic::Ordering::Relaxed)
    {
        let _ = tokio::time::timeout(S3_CONNECTION_LIFETIME - CONNECTION_LIFETIME, conn).await;
    }
}

/// Bind the port, retrying while something else holds it. If it's our own daemon, give up at once.
async fn bind(cfg: &Config, sock: &Path) -> Result<TcpListener, String> {
    let start = std::time::Instant::now();
    loop {
        match TcpListener::bind(cfg.listen).await {
            Ok(l) => return Ok(l),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                if UnixStream::connect(sock).await.is_ok() {
                    return Err("already running".into());
                }
                if start.elapsed() >= BIND_RETRY {
                    return Err(format!(
                        "{}: still in use after {}s",
                        cfg.listen,
                        BIND_RETRY.as_secs()
                    ));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(format!("{}: {e}", cfg.listen)),
        }
    }
}

async fn serve(cfg: Config) -> Result<(), String> {
    private_dir(&cfg.runtime_dir)?;
    let sock = socket_path(&cfg);
    // The port is the single-instance lock: bind it before touching the socket, so a second instance fails
    // here instead of deleting the running daemon's socket.
    let tcp = bind(&cfg, &sock).await?;
    if UnixStream::connect(&sock).await.is_ok() {
        return Err("already running".into());
    }
    let _ = std::fs::remove_file(&sock);
    let ctl = UnixListener::bind(&sock).map_err(|e| format!("{}: {e}", sock.display()))?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;

    let vault = Arc::new(Vault::new(cfg));
    let http = proxy::clients();
    let stop = Arc::new(Notify::new());
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut full_logged: Option<std::time::Instant> = None;
    log::line(
        &vault.cfg.log,
        &format!(
            "- started pid {} on {}",
            std::process::id(),
            vault.cfg.listen
        ),
    );

    let sweeper = {
        let vault = vault.clone();
        let every =
            (vault.cfg.idle_lock / 4).clamp(Duration::from_millis(200), Duration::from_secs(30));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                for s in vault.sweep() {
                    log::line(&vault.cfg.log, &format!("{s} locked (idle)"));
                }
            }
        })
    };

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    loop {
        tokio::select! {
            a = tcp.accept() => {
                let Ok((conn, _)) = a else {
                    // e.g. out of file descriptors: don't spin
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    if full_logged.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                        log::line(&vault.cfg.log, &format!("- connection limit ({MAX_CONNECTIONS}) reached: refusing connections"));
                        full_logged = Some(std::time::Instant::now());
                    }
                    continue;
                };
                let (vault, http) = (vault.clone(), http.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    let long = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let is_long = long.clone();
                    let svc = service_fn(move |req| {
                        let (vault, http, long) = (vault.clone(), http.clone(), long.clone());
                        async move { Ok::<_, std::convert::Infallible>(proxy::handle(vault, http, req, long).await) }
                    });
                    let conn = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(10))
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(conn), svc);
                    within_lifetime(conn, &is_long).await;
                });
            }
            a = ctl.accept() => {
                let Ok((conn, _)) = a else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let (vault, stop) = (vault.clone(), stop.clone());
                tokio::spawn(async move { control(conn, vault, stop).await });
            }
            _ = stop.notified() => break,
            _ = term.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    sweeper.abort();
    vault.lock(None);
    let _ = std::fs::remove_file(&sock);
    log::line(&vault.cfg.log, "- stopped");
    Ok(())
}

async fn control(conn: UnixStream, vault: Arc<Vault>, stop: Arc<Notify>) {
    match conn.peer_cred() {
        Ok(c) if c.uid() == unsafe { libc::getuid() } => {}
        _ => return,
    }
    let (r, mut w) = conn.into_split();
    let mut line = String::new();
    let mut r = BufReader::new(r.take(4096));
    if r.read_line(&mut line).await.is_err() {
        return;
    }
    let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
    let service = req.get("service").and_then(|s| s.as_str());
    let res = match (req.get("op").and_then(|o| o.as_str()), service) {
        (Some("unlock"), Some(s)) => match vault.key(s, true).await {
            Ok(_) => json!({"ok": true}),
            Err(e) => json!({"ok": false, "error": e}),
        },
        (Some("token"), Some(s)) => match vault.token(s) {
            Some(t) => json!({"ok": true, "token": t}),
            None => json!({"ok": false, "error": format!("unknown service {s:?}")}),
        },
        (Some("lock"), _) => {
            let locked = vault.lock(service);
            for s in &locked {
                log::line(&vault.cfg.log, &format!("{s} locked"));
            }
            json!({"ok": true, "locked": locked})
        }
        (Some("status"), _) => {
            let services: Vec<Value> = vault
                .status()
                .into_iter()
                .map(|(name, state, left)| json!({"name": name, "state": state, "locks_in_secs": left}))
                .collect();
            json!({"ok": true, "pid": std::process::id(), "listen": vault.cfg.listen.to_string(), "services": services})
        }
        (Some("stop"), _) => {
            stop.notify_one();
            json!({"ok": true})
        }
        _ => json!({"ok": false, "error": "bad request"}),
    };
    let _ = w.write_all(format!("{res}\n").as_bytes()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    async fn lifetime(long: bool, set_after: Option<Duration>) -> Duration {
        let flag = Arc::new(AtomicBool::new(false));
        if let Some(d) = set_after {
            let f = flag.clone();
            tokio::spawn(async move {
                tokio::time::sleep(d).await;
                f.store(long, Ordering::Relaxed);
            });
        }
        let start = tokio::time::Instant::now();
        within_lifetime(std::future::pending::<()>(), &flag).await;
        start.elapsed()
    }

    #[tokio::test(start_paused = true)]
    async fn connections_live_5_minutes_s3_ones_65() {
        assert_eq!(lifetime(false, None).await, Duration::from_secs(300));
        // an S3 call is known within the first 5 minutes (it is marked once its route is found)
        assert_eq!(
            lifetime(true, Some(Duration::from_secs(1))).await,
            Duration::from_secs(3900)
        );
        assert_eq!(
            lifetime(false, Some(Duration::from_secs(1))).await,
            Duration::from_secs(300)
        );
        // a connection that ends sooner is not held
        let flag = AtomicBool::new(true);
        let start = tokio::time::Instant::now();
        within_lifetime(tokio::time::sleep(Duration::from_secs(10)), &flag).await;
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }
}
