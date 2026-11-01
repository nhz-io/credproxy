//! Keys in memory (age decrypts on first use: one Touch ID), idle lock, and per-service tokens that exist only
//! in memory: random at every daemon start, handed out over the control socket.

use crate::config::Config;
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

/// After a failed unlock (Touch ID denied, timeout), requests don't prompt again for this long;
/// `credproxy unlock` still does. Stops retrying clients from raising prompt after prompt.
pub const UNLOCK_BACKOFF: Duration = Duration::from_secs(30);

struct Unlocked {
    key: Zeroizing<String>,
    last_used: Instant,
}

#[derive(Default)]
struct Slot {
    token: String,
    unlocked: Option<Unlocked>,
    failed_at: Option<Instant>,
}

pub struct Vault {
    pub cfg: Config,
    slots: Mutex<HashMap<String, Slot>>,
    unlocking: tokio::sync::Mutex<()>,
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
            unlocking: tokio::sync::Mutex::new(()),
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

    fn cached(&self, service: &str) -> Option<Zeroizing<String>> {
        let mut slots = self.slots.lock().unwrap();
        let u = slots.get_mut(service)?.unlocked.as_mut()?;
        u.last_used = Instant::now();
        Some(u.key.clone())
    }

    /// The service's key, decrypting first if locked (one at a time). `force` ignores the back-off.
    pub async fn key(&self, service: &str, force: bool) -> Result<Zeroizing<String>, String> {
        if let Some(k) = self.cached(service) {
            return Ok(k);
        }
        let svc = self
            .cfg
            .services
            .get(service)
            .ok_or(format!("unknown service {service:?}"))?;
        let _one = self.unlocking.lock().await;
        if let Some(k) = self.cached(service) {
            return Ok(k);
        }
        let failed = self
            .slots
            .lock()
            .unwrap()
            .get(service)
            .and_then(|s| s.failed_at);
        if let Some(t) = failed.filter(|t| !force && t.elapsed() < UNLOCK_BACKOFF) {
            let left = (UNLOCK_BACKOFF - t.elapsed()).as_secs() + 1;
            return Err(format!(
                "locked: last unlock failed; retry in {left}s or run `credproxy unlock {service}`"
            ));
        }
        let res = self.decrypt(svc.secret.as_path()).await;
        let mut slots = self.slots.lock().unwrap();
        let slot = slots.entry(service.to_string()).or_default();
        match res {
            Ok(key) => {
                slot.failed_at = None;
                slot.unlocked = Some(Unlocked {
                    key: key.clone(),
                    last_used: Instant::now(),
                });
                Ok(key)
            }
            Err(e) => {
                slot.failed_at = Some(Instant::now());
                Err(e)
            }
        }
    }

    async fn decrypt(&self, secret: &Path) -> Result<Zeroizing<String>, String> {
        let file = self.cfg.secrets_dir.join(secret);
        let mut child = tokio::process::Command::new(&self.cfg.age)
            .arg("-d")
            .arg("-i")
            .arg(&self.cfg.identity)
            .arg(&file)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            // own process group: on timeout the age plugin (a child of age) goes too
            .process_group(0)
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", self.cfg.age))?;
        let pgid = child.id().map(|p| p as libc::pid_t);
        let mut out = Zeroizing::new(Vec::new());
        let mut err = Vec::new();
        let mut so = child.stdout.take().unwrap();
        let mut se = child.stderr.take().unwrap();
        let wait = async {
            let (a, b) = tokio::join!(so.read_to_end(&mut out), se.read_to_end(&mut err));
            a.and(b).map_err(|e| e.to_string())?;
            child.wait().await.map_err(|e| e.to_string())
        };
        let status = match tokio::time::timeout(Duration::from_secs(120), wait).await {
            Ok(r) => r?,
            Err(_) => {
                if let Some(g) = pgid {
                    unsafe { libc::kill(-g, libc::SIGKILL) };
                }
                return Err("timed out waiting for age (Touch ID not approved?)".into());
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

    /// Lock one service, or all of them. Dropping the key zeroes it.
    pub fn lock(&self, service: Option<&str>) -> Vec<String> {
        let mut slots = self.slots.lock().unwrap();
        let mut locked = Vec::new();
        for (name, s) in slots.iter_mut() {
            if service.is_none_or(|x| x == name) && s.unlocked.take().is_some() {
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

    /// (service, unlocked, seconds until idle lock)
    pub fn status(&self) -> Vec<(String, bool, u64)> {
        let slots = self.slots.lock().unwrap();
        self.cfg
            .services
            .keys()
            .map(
                |name| match slots.get(name).and_then(|s| s.unlocked.as_ref()) {
                    Some(u) => (
                        name.clone(),
                        true,
                        self.cfg
                            .idle_lock
                            .saturating_sub(u.last_used.elapsed())
                            .as_secs(),
                    ),
                    None => (name.clone(), false, 0),
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
