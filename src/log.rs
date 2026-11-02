//! Append-only log: time, service, method, path, status. Never keys, tokens or query strings.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// A path or name as it may appear in the log or a refusal: visible ASCII only, at most 200 characters.
pub fn printable(p: &str) -> String {
    p.chars()
        .take(200)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

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

/// Rotate at this size into one `.1` file, so the log never takes more than about twice this.
const MAX_LOG: u64 = 1 << 20;

/// One append handle for the process, with the path it belongs to.
static FILE: Mutex<Option<(PathBuf, std::fs::File)>> = Mutex::new(None);

fn open(path: &Path) -> Option<std::fs::File> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .ok()
}

pub fn line(path: &Path, msg: &str) {
    write_line(path, msg, MAX_LOG)
}

fn write_line(path: &Path, msg: &str, max: u64) {
    let mut cur = FILE.lock().unwrap_or_else(|e| e.into_inner());
    // (Re)open when there's no handle, the path changed, or the file was deleted or moved away.
    if cur.as_ref().is_none_or(|(p, _)| p != path) || !path.exists() {
        *cur = open(path).map(|f| (path.to_path_buf(), f));
    }
    if cur
        .as_ref()
        .is_some_and(|(_, f)| f.metadata().is_ok_and(|m| m.len() >= max))
    {
        let mut old = path.as_os_str().to_owned();
        old.push(".1");
        let _ = std::fs::rename(path, old);
        *cur = open(path).map(|f| (path.to_path_buf(), f));
    }
    if let Some((_, f)) = cur.as_mut() {
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

    #[test]
    fn rotates_and_survives_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.log");
        for i in 0..20 {
            super::write_line(&p, &format!("line {i}"), 200);
        }
        let main = std::fs::read_to_string(&p).unwrap();
        let old = std::fs::read_to_string(dir.path().join("x.log.1")).unwrap();
        assert!(
            main.len() < 200 + 40 && old.len() < 200 + 40,
            "both files stay near the limit"
        );
        assert!(main.contains("line 19"));
        std::fs::remove_file(&p).unwrap();
        super::write_line(&p, "after delete", 200);
        assert!(
            std::fs::read_to_string(&p)
                .unwrap()
                .contains("after delete")
        );
    }
}
