//! Keys in memory: unlock (age decrypts, one Touch ID), per-unlock token, idle lock.

use crate::config::Config;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

pub struct Unlocked {
    pub key: Zeroizing<String>,
    pub token: String,
    pub last_used: Instant,
}

pub struct Vault {
    pub cfg: Config,
    keys: Mutex<HashMap<String, Unlocked>>,
    unlocking: tokio::sync::Mutex<()>,
}

pub struct Use {
    pub service: String,
    pub key: Zeroizing<String>,
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
        Vault {
            cfg,
            keys: Mutex::new(HashMap::new()),
            unlocking: tokio::sync::Mutex::new(()),
        }
    }

    /// Token of an unlocked service, decrypting first if needed. Unlocks run one at a time.
    pub async fn unlock(&self, service: &str) -> Result<String, String> {
        let svc = self
            .cfg
            .services
            .get(service)
            .ok_or(format!("unknown service {service:?}"))?;
        let _one = self.unlocking.lock().await;
        if let Some(u) = self.keys.lock().unwrap().get_mut(service) {
            u.last_used = Instant::now();
            return Ok(u.token.clone());
        }
        let file = self.cfg.secrets_dir.join(&svc.secret);
        let mut child = tokio::process::Command::new(&self.cfg.age)
            .arg("-d")
            .arg("-i")
            .arg(&self.cfg.identity)
            .arg(&file)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", self.cfg.age))?;
        let mut out = Zeroizing::new(Vec::new());
        let mut err = Vec::new();
        let mut so = child.stdout.take().unwrap();
        let mut se = child.stderr.take().unwrap();
        let wait = async {
            let (a, b) = tokio::join!(so.read_to_end(&mut out), se.read_to_end(&mut err));
            a.and(b).map_err(|e| e.to_string())?;
            child.wait().await.map_err(|e| e.to_string())
        };
        let status = tokio::time::timeout(Duration::from_secs(120), wait)
            .await
            .map_err(|_| "timed out waiting for age (Touch ID not approved?)".to_string())??;
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
        let key = to_key(&out)?;
        let token = new_token();
        self.keys.lock().unwrap().insert(
            service.to_string(),
            Unlocked {
                key,
                token: token.clone(),
                last_used: Instant::now(),
            },
        );
        Ok(token)
    }

    /// Lock one service, or all of them. Dropping `Unlocked` zeroes the key.
    pub fn lock(&self, service: Option<&str>) -> Vec<String> {
        let mut keys = self.keys.lock().unwrap();
        match service {
            Some(s) => keys
                .remove(s)
                .map(|_| vec![s.to_string()])
                .unwrap_or_default(),
            None => keys.drain().map(|(k, _)| k).collect(),
        }
    }

    /// Service for a request token (constant-time compare), marking it used.
    pub fn take(&self, token: &str) -> Option<Use> {
        let mut keys = self.keys.lock().unwrap();
        let mut hit = None;
        for (name, u) in keys.iter() {
            if bool::from(u.token.as_bytes().ct_eq(token.as_bytes())) {
                hit = Some(name.clone());
            }
        }
        let name = hit?;
        let u = keys.get_mut(&name)?;
        u.last_used = Instant::now();
        Some(Use {
            service: name,
            key: u.key.clone(),
        })
    }

    /// Lock every service unused for `idle_lock`; returns their names.
    pub fn sweep(&self) -> Vec<String> {
        let idle = self.cfg.idle_lock;
        let mut keys = self.keys.lock().unwrap();
        let old: Vec<String> = keys
            .iter()
            .filter(|(_, u)| u.last_used.elapsed() >= idle)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &old {
            keys.remove(k);
        }
        old
    }

    /// (service, unlocked, seconds until idle lock)
    pub fn status(&self) -> Vec<(String, bool, u64)> {
        let keys = self.keys.lock().unwrap();
        self.cfg
            .services
            .keys()
            .map(|name| match keys.get(name) {
                Some(u) => (
                    name.clone(),
                    true,
                    self.cfg
                        .idle_lock
                        .saturating_sub(u.last_used.elapsed())
                        .as_secs(),
                ),
                None => (name.clone(), false, 0),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_parsing() {
        assert_eq!(to_key(b"rpa_ABC123\n").unwrap().as_str(), "rpa_ABC123");
        assert_eq!(to_key(b"abc\r\n").unwrap().as_str(), "abc");
        assert!(to_key(b"\n").is_err());
        assert!(to_key(b"a b").is_err());
        assert!(to_key(b"abc\nX-Evil: 1").is_err());
        assert!(to_key("ключ".as_bytes()).is_err());
    }

    #[test]
    fn tokens_are_random_hex() {
        let (a, b) = (new_token(), new_token());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
