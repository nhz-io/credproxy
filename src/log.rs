//! Append-only log: time, service, method, path, status. Never keys, tokens or query strings.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// UTC "YYYY-MM-DDTHH:MM:SSZ" without a date crate (civil-from-days).
pub fn now() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, secs) = ((t / 86400) as i64, t % 86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// One append handle for the process, opened on first use (the daemon only ever logs to one file).
static FILE: Mutex<Option<std::fs::File>> = Mutex::new(None);

pub fn line(path: &Path, msg: &str) {
    let mut f = FILE.lock().unwrap_or_else(|e| e.into_inner());
    if f.is_none() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        *f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .ok();
    }
    if let Some(f) = f.as_mut() {
        let _ = writeln!(f, "{} {msg}", now());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamp_shape() {
        let n = super::now();
        assert_eq!(n.len(), 20);
        assert!(n.starts_with("20") && n.ends_with('Z'));
    }
}
