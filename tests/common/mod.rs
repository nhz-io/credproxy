//! Shared by the end-to-end suites: the binary, shell helpers, a throwaway age identity, the daemon.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::Duration;

pub const BIN: &str = env!("CARGO_BIN_EXE_credproxy");

pub fn sh(cmd: &mut Command) -> Output {
    let o = cmd.output().unwrap();
    assert!(
        o.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    o
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A throwaway identity in `<dir>/id.txt`; returns its public key.
pub fn age_identity(dir: &Path) -> String {
    sh(Command::new("age-keygen").arg("-o").arg(dir.join("id.txt")));
    let public = sh(Command::new("age-keygen").arg("-y").arg(dir.join("id.txt"))).stdout;
    String::from_utf8(public).unwrap().trim().to_string()
}

/// `content` sealed to `public` as `file` (made with `age -o`, like the real store).
pub fn seal(public: &str, file: PathBuf, content: &str) {
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

pub fn cli(cfg: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("CREDPROXY_CONFIG", cfg)
        .output()
        .unwrap()
}

/// The daemon on `cfg`, once `credproxy status` says it's running; panics if it doesn't come up in 5 s.
pub async fn start_daemon(cfg: &Path) -> Child {
    let mut daemon = Command::new(BIN)
        .arg("serve")
        .env("CREDPROXY_CONFIG", cfg)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if String::from_utf8_lossy(&cli(cfg, &["status"]).stdout).starts_with("running") {
            return daemon;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    daemon.kill().unwrap();
    let _ = daemon.wait();
    panic!("daemon did not start");
}
