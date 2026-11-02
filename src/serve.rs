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
/// How long to keep trying the port when it's busy (e.g. the previous daemon still releasing it).
const BIND_RETRY: Duration = Duration::from_secs(30);

/// Run a connection until it ends, or until it outlives CONNECTION_LIFETIME, or (once it carries an allowed S3
/// call, which has no overall limit) until it stops making progress: no bytes for `idle` outside expected
/// silence. The watchdog sees what the streams' own idle timers can't: a client that stops reading or an upstream
/// that stops accepting, where nothing polls those streams. Dropping the future closes the connection, and with
/// it any upstream request in flight.
async fn within_lifetime<F: std::future::Future>(
    conn: F,
    progress: &proxy::Progress,
    idle: Duration,
) {
    tokio::pin!(conn);
    let start = tokio::time::Instant::now();
    let every = (idle / 4).clamp(Duration::from_millis(50), Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = &mut conn => return,
            _ = tokio::time::sleep(every) => {
                let over = if progress.is_s3() {
                    progress.stalled(idle)
                } else {
                    start.elapsed() >= CONNECTION_LIFETIME
                };
                if over {
                    return;
                }
            }
        }
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
                let s3_idle = vault.cfg.s3_idle;
                tokio::spawn(async move {
                    let _permit = permit;
                    let progress = Arc::new(proxy::Progress::default());
                    let watched = progress.clone();
                    let svc = service_fn(move |req| {
                        let (vault, http, progress) = (vault.clone(), http.clone(), progress.clone());
                        async move { Ok::<_, std::convert::Infallible>(proxy::handle(vault, http, req, progress).await) }
                    });
                    let conn = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(10))
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(conn), svc);
                    // boxed to a concrete type: passed generically, the connection future trips a rustc
                    // limitation when proving the spawned task Send
                    let conn: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> = Box::pin(conn);
                    within_lifetime(conn, &watched, s3_idle).await;
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
    use proxy::Progress;

    /// How long a never-ending connection lives, with `drive` acting on its progress meanwhile.
    async fn lives(
        progress: Arc<Progress>,
        drive: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Duration {
        tokio::spawn(drive);
        let start = tokio::time::Instant::now();
        within_lifetime(
            std::future::pending::<()>(),
            &progress,
            Duration::from_secs(60),
        )
        .await;
        start.elapsed()
    }

    #[tokio::test(start_paused = true)]
    async fn other_connections_live_5_minutes() {
        let p = Arc::new(Progress::default());
        assert_eq!(lives(p, async {}).await, Duration::from_secs(300));
    }

    #[tokio::test(start_paused = true)]
    async fn s3_connections_live_while_they_move() {
        // bytes every 59 s for 3 hours, then nothing: cut 60 s after the last bytes, not at any fixed time
        let p = Arc::new(Progress::default());
        p.mark_s3();
        let q = p.clone();
        let t = lives(p, async move {
            for _ in 0..183 {
                tokio::time::sleep(Duration::from_secs(59)).await;
                q.touch();
            }
        })
        .await;
        assert_eq!(t, Duration::from_secs(183 * 59 + 60));
    }

    #[tokio::test(start_paused = true)]
    async fn s3_connection_stalled_from_the_start_is_cut_after_a_minute() {
        let p = Arc::new(Progress::default());
        p.mark_s3();
        assert_eq!(lives(p, async {}).await, Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn expected_silence_is_not_a_stall() {
        // e.g. the upstream assembling a big multipart upload: quiet for up to 2 h, then 60 s more of nothing
        let p = Arc::new(Progress::default());
        p.mark_s3();
        p.quiet_for(Duration::from_secs(7200));
        assert_eq!(lives(p.clone(), async {}).await, Duration::from_secs(7200));
        // and bytes arriving during it end the quiet period early
        let p = Arc::new(Progress::default());
        p.mark_s3();
        p.quiet_for(Duration::from_secs(7200));
        let q = p.clone();
        let t = lives(p, async move {
            tokio::time::sleep(Duration::from_secs(100)).await;
            q.touch();
        })
        .await;
        assert_eq!(t, Duration::from_secs(160));
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_ends_is_not_held() {
        let p = Progress::default();
        p.mark_s3();
        let start = tokio::time::Instant::now();
        within_lifetime(
            tokio::time::sleep(Duration::from_secs(10)),
            &p,
            Duration::from_secs(60),
        )
        .await;
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }
}
