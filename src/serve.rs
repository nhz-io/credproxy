//! The daemon: TCP listener on 127.0.0.1 for proxied calls, Unix control socket (0700 dir) for unlock/lock/status.

use crate::config::{self, Config};
use crate::log;
use crate::proxy;
use crate::vault::Vault;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::Notify;

pub fn socket_path(cfg: &Config) -> PathBuf {
    cfg.runtime_dir.join("ctl.sock")
}

/// The runtime dir must be ours and private: anyone who can reach the socket can use unlocked keys.
pub fn private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let m = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if m.uid() != unsafe { libc::getuid() } || m.mode() & 0o077 != 0 {
        return Err(format!(
            "{}: must be owned by you with mode 700",
            dir.display()
        ));
    }
    Ok(())
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
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(serve(cfg))
}

async fn serve(cfg: Config) -> Result<(), String> {
    private_dir(&cfg.runtime_dir)?;
    let sock = socket_path(&cfg);
    if UnixStream::connect(&sock).await.is_ok() {
        return Err("already running".into());
    }
    let _ = std::fs::remove_file(&sock);
    let tcp = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let port = tcp.local_addr().map_err(|e| e.to_string())?.port();
    let ctl = UnixListener::bind(&sock).map_err(|e| format!("{}: {e}", sock.display()))?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;

    let vault = Arc::new(Vault::new(cfg));
    let http = proxy::client();
    let stop = Arc::new(Notify::new());
    log::line(
        &vault.cfg.log,
        &format!("- started pid {} port {port}", std::process::id()),
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
                let Ok((conn, _)) = a else { continue };
                let (vault, http) = (vault.clone(), http.clone());
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let (vault, http) = (vault.clone(), http.clone());
                        async move { Ok::<_, std::convert::Infallible>(proxy::handle(vault, http, req).await) }
                    });
                    let _ = http1::Builder::new().serve_connection(TokioIo::new(conn), svc).await;
                });
            }
            a = ctl.accept() => {
                let Ok((conn, _)) = a else { continue };
                let (vault, stop) = (vault.clone(), stop.clone());
                tokio::spawn(async move { control(conn, vault, port, stop).await });
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

async fn control(conn: UnixStream, vault: Arc<Vault>, port: u16, stop: Arc<Notify>) {
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
    let res = match req.get("op").and_then(|o| o.as_str()) {
        Some("unlock") => match service {
            Some(s) => match vault.unlock(s).await {
                Ok(token) => {
                    log::line(&vault.cfg.log, &format!("{s} unlocked"));
                    json!({"ok": true, "url": format!("http://127.0.0.1:{port}/{token}"), "env": vault.cfg.services[s].env})
                }
                Err(e) => json!({"ok": false, "error": e}),
            },
            None => json!({"ok": false, "error": "no service"}),
        },
        Some("lock") => {
            let locked = vault.lock(service);
            for s in &locked {
                log::line(&vault.cfg.log, &format!("{s} locked"));
            }
            json!({"ok": true, "locked": locked})
        }
        Some("status") => {
            let services: Vec<Value> = vault
                .status()
                .into_iter()
                .map(|(name, unlocked, left)| json!({"name": name, "unlocked": unlocked, "locks_in_secs": left}))
                .collect();
            json!({"ok": true, "pid": std::process::id(), "port": port, "services": services})
        }
        Some("stop") => {
            stop.notify_one();
            json!({"ok": true})
        }
        _ => json!({"ok": false, "error": "bad request"}),
    };
    let _ = w.write_all(format!("{res}\n").as_bytes()).await;
}
