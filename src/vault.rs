//! Keys in memory (age decrypts on first use: one Touch ID), idle lock, and per-service tokens that exist only
//! in memory: random at every daemon start, handed out over the control socket.

use crate::config::Config;
use crate::log;
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use zeroize::Zeroizing;

/// After a failed unlock (Touch ID denied, timeout), requests don't prompt again for this long;
/// `credproxy unlock` still does. Stops retrying clients from raising prompt after prompt.
pub const UNLOCK_BACKOFF: Duration = Duration::from_secs(30);
/// How long an unlock waits for the Touch ID / password prompt.
pub const UNLOCK_TIMEOUT: Duration = Duration::from_secs(120);

struct Unlocked {
    key: Zeroizing<String>,
    last_used: Instant,
}

/// Outcome of one unlock job, shared by every request waiting for it.
type Outcome = Option<Result<(), String>>;

/// An unlock in progress. It runs as its own task, so a waiting client that goes away doesn't cancel it;
/// `lock` and `stop` do (they kill age and its plugin, which closes the prompt).
struct Pending {
    id: u64,
    pgid: Option<libc::pid_t>,
    done: Arc<watch::Sender<Outcome>>,
}

#[derive(Default)]
struct Slot {
    token: String,
    unlocked: Option<Unlocked>,
    failed_at: Option<Instant>,
    pending: Option<Pending>,
}

pub struct Vault {
    pub cfg: Config,
    slots: Mutex<HashMap<String, Slot>>,
    next_job: AtomicU64,
}

/// The runtime dir must be ours and private.
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

fn new_token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("getrandom");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn kill_group(pgid: libc::pid_t) {
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
}

/// age output → key: one line of visible ASCII (anything else could split a header).
fn to_key(raw: &[u8]) -> Result<Zeroizing<String>, String> {
    let mut end = raw.len();
    while end > 0 && matches!(raw[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    let k = &raw[..end];
    if k.is_empty() {
        return Err("decrypted secret is empty".into());
    }
    if !k.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err("decrypted secret is not a single line of printable ASCII".into());
    }
    Ok(Zeroizing::new(
        String::from_utf8(k.to_vec()).expect("ascii"),
    ))
}

impl Vault {
    pub fn new(cfg: Config) -> Self {
        let slots = cfg
            .services
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    Slot {
                        token: new_token(),
                        ..Slot::default()
                    },
                )
            })
            .collect();
        Vault {
            cfg,
            slots: Mutex::new(slots),
            next_job: AtomicU64::new(1),
        }
    }

    /// Does `presented` equal the service's token? Constant time; unknown services never match.
    pub fn check_token(&self, service: &str, presented: &[u8]) -> bool {
        let slots = self.slots.lock().unwrap();
        slots
            .get(service)
            .is_some_and(|s| bool::from(s.token.as_bytes().ct_eq(presented)))
    }

    pub fn token(&self, service: &str) -> Option<String> {
        self.slots
            .lock()
            .unwrap()
            .get(service)
            .map(|s| s.token.clone())
    }

    /// The service's key, unlocking first if needed. Requests share one unlock job per service and only wait
    /// for it. `force` (explicit `credproxy unlock`) ignores the back-off after a failed unlock.
    pub async fn key(
        self: &Arc<Self>,
        service: &str,
        force: bool,
    ) -> Result<Zeroizing<String>, String> {
        if !self.cfg.services.contains_key(service) {
            return Err(format!("unknown service {service:?}"));
        }
        loop {
            let mut done = {
                let mut slots = self.slots.lock().unwrap();
                let slot = slots.entry(service.to_string()).or_default();
                if let Some(u) = slot.unlocked.as_mut() {
                    u.last_used = Instant::now();
                    return Ok(u.key.clone());
                }
                match &slot.pending {
                    Some(p) => p.done.subscribe(),
                    None => {
                        if let Some(t) = slot
                            .failed_at
                            .filter(|t| !force && t.elapsed() < UNLOCK_BACKOFF)
                        {
                            let left = (UNLOCK_BACKOFF - t.elapsed()).as_secs() + 1;
                            return Err(format!(
                                "locked: last unlock failed; retry in {left}s or run `credproxy unlock {service}`"
                            ));
                        }
                        let id = self.next_job.fetch_add(1, Ordering::Relaxed);
                        let (tx, rx) = watch::channel(None);
                        let done = Arc::new(tx);
                        slot.pending = Some(Pending {
                            id,
                            pgid: None,
                            done: done.clone(),
                        });
                        tokio::spawn(self.clone().unlock_job(service.to_string(), id, done));
                        rx
                    }
                }
            };
            let outcome = done
                .wait_for(|o| o.is_some())
                .await
                .map_err(|_| "unlock aborted".to_string())?
                .clone()
                .unwrap();
            // Ok: loop round to take the key from the slot (it may already be locked again).
            outcome?;
        }
    }

    async fn unlock_job(
        self: Arc<Self>,
        service: String,
        id: u64,
        done: Arc<watch::Sender<Outcome>>,
    ) {
        let res = self.decrypt(&service, id).await;
        let mut slots = self.slots.lock().unwrap();
        let slot = slots.entry(service.clone()).or_default();
        // A `lock` while we waited removed our job (and already told the waiters): drop the result.
        if slot.pending.as_ref().is_none_or(|p| p.id != id) {
            return;
        }
        slot.pending = None;
        let outcome = match res {
            Ok(key) => {
                slot.failed_at = None;
                slot.unlocked = Some(Unlocked {
                    key,
                    last_used: Instant::now(),
                });
                log::line(&self.cfg.log, &format!("{service} unlocked"));
                Ok(())
            }
            Err(e) => {
                slot.failed_at = Some(Instant::now());
                log::line(&self.cfg.log, &format!("{service} unlock failed: {e}"));
                Err(e)
            }
        };
        done.send_replace(Some(outcome));
    }

    async fn decrypt(&self, service: &str, id: u64) -> Result<Zeroizing<String>, String> {
        let file = self
            .cfg
            .secrets_dir
            .join(&self.cfg.services[service].secret);
        let mut child = tokio::process::Command::new(&self.cfg.age)
            .arg("-d")
            .arg("-i")
            .arg(&self.cfg.identity)
            .arg(&file)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            // own process group: age's plugin (its child) is killed with it
            .process_group(0)
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", self.cfg.age))?;
        let pgid = child.id().map(|p| p as libc::pid_t);
        {
            let mut slots = self.slots.lock().unwrap();
            match slots.get_mut(service).and_then(|s| s.pending.as_mut()) {
                Some(p) if p.id == id => p.pgid = pgid,
                // locked before age even started
                _ => {
                    if let Some(g) = pgid {
                        kill_group(g);
                    }
                    return Err("locked".into());
                }
            }
        }
        // Room for any real key up front: growing the buffer would leave plaintext copies in freed memory.
        let mut out = Zeroizing::new(Vec::with_capacity(64 << 10));
        let mut err = Vec::new();
        let mut so = child.stdout.take().unwrap().take(64 << 10);
        let mut se = child.stderr.take().unwrap().take(64 << 10);
        let wait = async {
            let (a, b) = tokio::join!(so.read_to_end(&mut out), se.read_to_end(&mut err));
            a.and(b).map_err(|e| e.to_string())?;
            // age is done. Forget its process group before reaping it: once reaped, the id can be reused, and
            // `lock` must never signal someone else's group.
            if let Some(p) = self
                .slots
                .lock()
                .unwrap()
                .get_mut(service)
                .and_then(|s| s.pending.as_mut())
                .filter(|p| p.id == id)
            {
                p.pgid = None;
            }
            child.wait().await.map_err(|e| e.to_string())
        };
        let status = match tokio::time::timeout(UNLOCK_TIMEOUT, wait).await {
            Ok(r) => r?,
            Err(_) => {
                if let Some(g) = pgid {
                    kill_group(g);
                }
                return Err("timed out waiting for Touch ID / password".into());
            }
        };
        if !status.success() {
            // age's own message (no plaintext on failure); keep the last line only
            let msg = String::from_utf8_lossy(&err);
            let last = msg
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim();
            return Err(format!("could not decrypt {}: {last}", file.display()));
        }
        to_key(&out)
    }

    /// Lock one service, or all of them: forget the key (zeroed on drop) and abort a pending unlock (kills age
    /// and its plugin, which closes the prompt). Returns the services that were unlocked or unlocking.
    pub fn lock(&self, service: Option<&str>) -> Vec<String> {
        let mut slots = self.slots.lock().unwrap();
        let mut locked = Vec::new();
        for (name, s) in slots.iter_mut() {
            if service.is_some_and(|x| x != name) {
                continue;
            }
            let had_key = s.unlocked.take().is_some();
            let pending = s.pending.take();
            if let Some(p) = &pending {
                if let Some(g) = p.pgid {
                    kill_group(g);
                }
                // same as pressing Cancel: requests don't raise a new prompt for UNLOCK_BACKOFF
                s.failed_at = Some(Instant::now());
                p.done
                    .send_replace(Some(Err("locked while waiting for Touch ID".into())));
            }
            if had_key || pending.is_some() {
                locked.push(name.clone());
            }
        }
        locked
    }

    /// Lock every service unused for `idle_lock`; returns their names.
    pub fn sweep(&self) -> Vec<String> {
        let idle = self.cfg.idle_lock;
        let mut slots = self.slots.lock().unwrap();
        let mut locked = Vec::new();
        for (name, s) in slots.iter_mut() {
            if s.unlocked
                .as_ref()
                .is_some_and(|u| u.last_used.elapsed() >= idle)
            {
                s.unlocked = None;
                locked.push(name.clone());
            }
        }
        locked
    }

    /// (service, "unlocked" | "unlocking" | "locked", seconds until idle lock)
    pub fn status(&self) -> Vec<(String, &'static str, u64)> {
        let slots = self.slots.lock().unwrap();
        self.cfg
            .services
            .keys()
            .map(
                |name| match slots.get(name).and_then(|s| s.unlocked.as_ref()) {
                    Some(u) => (
                        name.clone(),
                        "unlocked",
                        self.cfg
                            .idle_lock
                            .saturating_sub(u.last_used.elapsed())
                            .as_secs(),
                    ),
                    None if slots.get(name).is_some_and(|s| s.pending.is_some()) => {
                        (name.clone(), "unlocking", 0)
                    }
                    None => (name.clone(), "locked", 0),
                },
            )
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_hex() {
        let (a, b) = (new_token(), new_token());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn key_parsing() {
        assert_eq!(to_key(b"rpa_ABC123\n").unwrap().as_str(), "rpa_ABC123");
        assert_eq!(to_key(b"abc\r\n").unwrap().as_str(), "abc");
        assert!(to_key(b"\n").is_err());
        assert!(to_key(b"a b").is_err());
        assert!(to_key(b"abc\nX-Evil: 1").is_err());
        assert!(to_key("ключ".as_bytes()).is_err());
    }
}
