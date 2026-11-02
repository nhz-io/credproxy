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

/// What an unlocked service holds: its key, or for B2 only the session the key was traded for.
#[derive(Clone)]
pub enum Secret {
    Key(Zeroizing<String>),
    B2(Arc<crate::b2::Session>),
}

struct Unlocked {
    secret: Secret,
    last_used: Instant,
    /// B2: the token's end (`relock_after` after the unlock); the service locks then.
    expires: Option<Instant>,
}

impl Unlocked {
    fn expired(&self) -> bool {
        self.expires.is_some_and(|e| Instant::now() >= e)
    }
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
    /// For B2's authorize call.
    http: reqwest::Client,
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

/// age output → key: `lines` lines (1, or 2 for SigV4: access key id, secret) of visible ASCII each (anything
/// else could split a header). Stored joined by `\n`.
fn to_key(raw: &[u8], lines: usize) -> Result<Zeroizing<String>, String> {
    let mut end = raw.len();
    while end > 0 && matches!(raw[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    let k = &raw[..end];
    if k.is_empty() {
        return Err("decrypted secret is empty".into());
    }
    let parts: Vec<&[u8]> = k
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect();
    let what = if lines == 1 {
        "a single line of printable ASCII"
    } else {
        "two lines of printable ASCII (key id, secret)"
    };
    if parts.len() != lines
        || parts
            .iter()
            .any(|l| l.is_empty() || !l.iter().all(|b| (0x21..=0x7e).contains(b)))
    {
        return Err(format!("decrypted secret is not {what}"));
    }
    let mut out = Zeroizing::new(String::with_capacity(k.len()));
    for (i, l) in parts.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(std::str::from_utf8(l).expect("ascii"));
    }
    Ok(out)
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
            http: crate::proxy::api_client(),
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

    /// The service's key, unlocking first if needed.
    pub async fn key(
        self: &Arc<Self>,
        service: &str,
        force: bool,
    ) -> Result<Zeroizing<String>, String> {
        match self.secret(service, force).await? {
            Secret::Key(k) => Ok(k),
            Secret::B2(_) => Err("a B2 service has no key in memory".into()),
        }
    }

    /// The B2 service's session, unlocking (and authorizing) first if needed.
    pub async fn b2(self: &Arc<Self>, service: &str) -> Result<Arc<crate::b2::Session>, String> {
        match self.secret(service, false).await? {
            Secret::B2(s) => Ok(s),
            Secret::Key(_) => Err("not a B2 service".into()),
        }
    }

    /// B2 said the session's token is no longer good: lock the service, unless it already holds a newer session.
    pub fn expire(&self, service: &str, session: &Arc<crate::b2::Session>) {
        let mut slots = self.slots.lock().unwrap();
        if let Some(s) = slots.get_mut(service)
            && matches!(&s.unlocked, Some(Unlocked { secret: Secret::B2(x), .. }) if Arc::ptr_eq(x, session))
        {
            s.unlocked = None;
            log::line(
                &self.cfg.log,
                &format!("{service} locked (B2 token no longer valid)"),
            );
        }
    }

    /// The service's secret, unlocking first if needed. Requests share one unlock job per service and only wait
    /// for it. `force` (explicit `credproxy unlock`) ignores the back-off after a failed unlock.
    pub async fn secret(self: &Arc<Self>, service: &str, force: bool) -> Result<Secret, String> {
        if !self.cfg.services.contains_key(service) {
            return Err(format!("unknown service {service:?}"));
        }
        loop {
            let mut done = {
                let mut slots = self.slots.lock().unwrap();
                let slot = slots.entry(service.to_string()).or_default();
                if slot.unlocked.as_ref().is_some_and(Unlocked::expired) {
                    slot.unlocked = None;
                    log::line(
                        &self.cfg.log,
                        &format!("{service} locked (B2 token expired)"),
                    );
                }
                if let Some(u) = slot.unlocked.as_mut() {
                    u.last_used = Instant::now();
                    return Ok(u.secret.clone());
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
        let res = match self.decrypt(&service, id).await {
            Ok(key) => match &self.cfg.services[&service].b2 {
                // the key is dropped (zeroed) as soon as the authorize call is done, whatever its outcome
                Some(b) => crate::b2::authorize(&self.http, b, key).await.map(|s| {
                    (
                        Secret::B2(Arc::new(s)),
                        Some(Instant::now() + b.relock_after),
                    )
                }),
                None => Ok((Secret::Key(key), None)),
            },
            Err(e) => Err(e),
        };
        let mut slots = self.slots.lock().unwrap();
        let slot = slots.entry(service.clone()).or_default();
        // A `lock` while we waited removed our job (and already told the waiters): drop the result.
        if slot.pending.as_ref().is_none_or(|p| p.id != id) {
            return;
        }
        slot.pending = None;
        let outcome = match res {
            Ok((secret, expires)) => {
                slot.failed_at = None;
                slot.unlocked = Some(Unlocked {
                    secret,
                    last_used: Instant::now(),
                    expires,
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
        let svc = &self.cfg.services[service];
        let lines = if svc.sigv4.is_some() || svc.b2.is_some() {
            2
        } else {
            1
        };
        to_key(&out, lines)
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

    /// Lock every service unused for `idle_lock`, and B2 services whose token expires; returns their names.
    pub fn sweep(&self) -> Vec<String> {
        let idle = self.cfg.idle_lock;
        let mut slots = self.slots.lock().unwrap();
        let mut locked = Vec::new();
        for (name, s) in slots.iter_mut() {
            if s.unlocked
                .as_ref()
                .is_some_and(|u| u.last_used.elapsed() >= idle || u.expired())
            {
                s.unlocked = None;
                locked.push(name.clone());
            }
        }
        locked
    }

    /// (service, state, seconds): "unlocked" (seconds until idle lock), "unlocking", "paused" (locked after a
    /// refused or failed unlock: seconds until requests may prompt again), or "locked".
    pub fn status(&self) -> Vec<(String, &'static str, u64)> {
        let slots = self.slots.lock().unwrap();
        self.cfg
            .services
            .keys()
            .map(
                // an expired session is locked, even before the sweep forgets it
                |name| match slots
                    .get(name)
                    .and_then(|s| s.unlocked.as_ref())
                    .filter(|u| !u.expired())
                {
                    Some(u) => {
                        let idle = self.cfg.idle_lock.saturating_sub(u.last_used.elapsed());
                        let left = match u.expires {
                            Some(e) => idle.min(e.saturating_duration_since(Instant::now())),
                            None => idle,
                        };
                        (name.clone(), "unlocked", left.as_secs())
                    }
                    None if slots.get(name).is_some_and(|s| s.pending.is_some()) => {
                        (name.clone(), "unlocking", 0)
                    }
                    None => match slots
                        .get(name)
                        .and_then(|s| s.failed_at)
                        .filter(|t| t.elapsed() < UNLOCK_BACKOFF)
                    {
                        Some(t) => (
                            name.clone(),
                            "paused",
                            (UNLOCK_BACKOFF - t.elapsed()).as_secs() + 1,
                        ),
                        None => (name.clone(), "locked", 0),
                    },
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
        assert_eq!(to_key(b"rpa_ABC123\n", 1).unwrap().as_str(), "rpa_ABC123");
        assert_eq!(to_key(b"abc\r\n", 1).unwrap().as_str(), "abc");
        assert!(to_key(b"\n", 1).is_err());
        assert!(to_key(b"a b", 1).is_err());
        assert!(to_key(b"abc\nX-Evil: 1", 1).is_err());
        assert!(to_key(b"abc\ndef", 1).is_err());
        assert!(to_key("ключ".as_bytes(), 1).is_err());
        assert_eq!(
            to_key(b"user_1\nrps_2\n", 2).unwrap().as_str(),
            "user_1\nrps_2"
        );
        assert_eq!(
            to_key(b"user_1\r\nrps_2\r\n", 2).unwrap().as_str(),
            "user_1\nrps_2"
        );
        assert!(to_key(b"rps_2\n", 2).is_err());
        assert!(to_key(b"user_1\n\nrps_2", 2).is_err());
        assert!(to_key(b"a\nb\nc", 2).is_err());
        assert!(to_key(b"user 1\nrps_2", 2).is_err());
    }
}
