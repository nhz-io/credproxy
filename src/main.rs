//! credproxy: a local proxy that holds API keys (age-sealed, unlocked with one Touch ID) and adds them to allowed
//! requests, so the programs using them never see the keys.

mod config;
mod graphql;
mod log;
mod proxy;
mod serve;
mod vault;

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const USAGE: &str = "usage:
  credproxy token <service>       print the token clients send as their API key (new at every daemon start)
  credproxy status                which services are unlocked, and for how long
  credproxy unlock <service>      unlock now (Touch ID); otherwise the first request unlocks
  credproxy lock [<service>]      forget the key(s) now
  credproxy install               LaunchAgent: start at login, restart if it exits
  credproxy uninstall             remove the LaunchAgent
  credproxy restart               restart the daemon (locks everything; reloads the config)
  credproxy stop                  stop the daemon until `restart` or the next login
  credproxy serve                 run the daemon in the foreground

config: $CREDPROXY_CONFIG or ~/.config/credproxy/config.toml";

const LABEL: &str = "io.nhz.credproxy";

fn die(msg: &str) -> ! {
    eprintln!("credproxy: {msg}");
    std::process::exit(1)
}

fn config_path() -> PathBuf {
    std::env::var_os("CREDPROXY_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(config::default_path)
}

fn request(sock: &Path, req: &Value, timeout: Duration) -> Result<Value, String> {
    let mut s =
        UnixStream::connect(sock).map_err(|_| "not running (credproxy install)".to_string())?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    s.write_all(format!("{req}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s)
        .read_line(&mut line)
        .map_err(|e| format!("no answer from daemon: {e}"))?;
    let v: Value = serde_json::from_str(&line).map_err(|_| "bad answer from daemon".to_string())?;
    if v["ok"] == json!(true) {
        Ok(v)
    } else {
        Err(v["error"].as_str().unwrap_or("failed").to_string())
    }
}

fn xml(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

fn plist_path() -> PathBuf {
    home().join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

/// A macOS notification, only when launchd runs us (never from tests or a terminal).
fn notify_if_launchd(msg: &str) {
    if std::env::var("XPC_SERVICE_NAME").as_deref() != Ok(LABEL) {
        return;
    }
    let quoted = msg.replace('\\', "\\\\").replace('"', "\\\"");
    let _ = Command::new("/usr/bin/osascript")
        .args([
            "-e",
            &format!("display notification \"{quoted}\" with title \"credproxy\""),
        ])
        .status();
}

fn launchctl(args: &[&str]) -> bool {
    Command::new("/bin/launchctl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The LaunchAgent: `<exe> serve` at login, restarted if it exits.
fn plist(exe: &str, config: Option<&str>, err_log: &str) -> String {
    let mut env = String::from(
        "\t\t<key>PATH</key>\n\t\t<string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>\n",
    );
    if let Some(c) = config {
        env += &format!(
            "\t\t<key>CREDPROXY_CONFIG</key>\n\t\t<string>{}</string>\n",
            xml(c)
        );
    }
    [
        r#"<?xml version="1.0" encoding="UTF-8"?>"#,
        r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">"#,
        r#"<plist version="1.0">"#,
        "<dict>",
        &format!("\t<key>Label</key>\n\t<string>{LABEL}</string>"),
        "\t<key>ProgramArguments</key>\n\t<array>",
        &format!("\t\t<string>{}</string>\n\t\t<string>serve</string>", xml(exe)),
        "\t</array>",
        &format!("\t<key>EnvironmentVariables</key>\n\t<dict>\n{env}\t</dict>"),
        "\t<key>RunAtLoad</key>\n\t<true/>",
        // Restart only after a crash: a clean exit (stop, or a startup error such as a bad config) stays down.
        "\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>",
        "\t<key>ProcessType</key>\n\t<string>Interactive</string>",
        &format!("\t<key>StandardErrorPath</key>\n\t<string>{}</string>", xml(err_log)),
        "</dict>",
        "</plist>\n",
    ]
    .join("\n")
}

/// The path launchd should run: Homebrew's stable link when it points to this binary, since the resolved
/// path (`Caskroom/credproxy/<version>/…`) disappears on the next upgrade.
fn launch_path(exe: &Path) -> PathBuf {
    let me = std::fs::canonicalize(exe).ok();
    let prefixes = [
        std::env::var("HOMEBREW_PREFIX").ok(),
        Some("/opt/homebrew".into()),
        Some("/usr/local".into()),
    ];
    for p in prefixes.into_iter().flatten() {
        let link = Path::new(&p).join("bin/credproxy");
        if me.is_some() && std::fs::canonicalize(&link).ok() == me {
            return link;
        }
    }
    exe.to_path_buf()
}

fn install(cfg_path: &Path) -> Result<(), String> {
    let exe = launch_path(&std::env::current_exe().map_err(|e| e.to_string())?);
    let config =
        std::env::var_os("CREDPROXY_CONFIG").map(|_| cfg_path.to_string_lossy().into_owned());
    let plist = plist(
        &exe.to_string_lossy(),
        config.as_deref(),
        &home()
            .join("Library/Logs/credproxy.err.log")
            .to_string_lossy(),
    );
    let path = plist_path();
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(&path, plist).map_err(|e| format!("{}: {e}", path.display()))?;
    let domain = format!("gui/{}", unsafe { libc::getuid() });
    launchctl(&["bootout", &format!("{domain}/{LABEL}")]);
    // bootout returns before the old process is gone; bootstrap fails while it still exists
    for _ in 0..50 {
        if launchctl(&["bootstrap", &domain, &path.to_string_lossy()]) {
            println!(
                "installed {} (runs {} serve)",
                path.display(),
                exe.display()
            );
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "launchctl bootstrap {domain} {} failed",
        path.display()
    ))
}

fn uninstall() {
    launchctl(&[
        "bootout",
        &format!("gui/{}/{LABEL}", unsafe { libc::getuid() }),
    ]);
    let _ = std::fs::remove_file(plist_path());
    println!("uninstalled");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    if matches!(cmd, "" | "-h" | "--help" | "help") {
        println!("{USAGE}");
        return;
    }
    if matches!(cmd, "-V" | "--version") {
        println!("credproxy {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let cfg_path = config_path();
    if cmd == "serve" {
        if let Err(e) = serve::run(&cfg_path) {
            // Exit 0 on purpose: launchd restarts only after a crash, and a bad config won't fix itself by
            // restarting every 10 s. The message is in credproxy.err.log, and a notification says so.
            eprintln!("credproxy: {e}");
            notify_if_launchd(&format!("credproxy is not running: {e}"));
        }
        return;
    }
    if cmd == "restart" {
        let target = format!("gui/{}/{LABEL}", unsafe { libc::getuid() });
        if !launchctl(&["kickstart", "-k", &target]) {
            die("not installed (credproxy install)");
        }
        // kickstart returns once launchd started it; check it actually came up (a bad config exits at once)
        let sock = config::load(&cfg_path).map(|c| serve::socket_path(&c));
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(100));
            if sock
                .as_ref()
                .is_ok_and(|s| request(s, &json!({"op": "status"}), Duration::from_secs(2)).is_ok())
            {
                println!("restarted");
                return;
            }
        }
        die("did not come up; see ~/Library/Logs/credproxy.err.log");
    }
    if cmd == "uninstall" {
        uninstall();
        return;
    }
    let cfg = config::load(&cfg_path).unwrap_or_else(|e| die(&e));
    let sock = serve::socket_path(&cfg);
    let short = Duration::from_secs(5);
    let service = args.get(1).map(String::as_str);
    let need_service = || {
        let s = service.unwrap_or_else(|| die(USAGE));
        if !cfg.services.contains_key(s) {
            die(&format!(
                "unknown service {s:?} (see {})",
                cfg_path.display()
            ));
        }
        s
    };
    match cmd {
        "token" => {
            let s = need_service();
            let v = request(&sock, &json!({"op": "token", "service": s}), short)
                .unwrap_or_else(|e| die(&e));
            println!(
                "{}",
                v["token"]
                    .as_str()
                    .unwrap_or_else(|| die("bad answer from daemon"))
            );
        }
        "install" => install(&cfg_path).unwrap_or_else(|e| die(&e)),
        "unlock" => {
            let s = need_service();
            // Long timeout: waits for Touch ID.
            request(
                &sock,
                &json!({"op": "unlock", "service": s}),
                Duration::from_secs(150),
            )
            .unwrap_or_else(|e| die(&e));
            println!("unlocked: {s}");
        }
        "lock" => match request(&sock, &json!({"op": "lock", "service": service}), short) {
            Ok(v) => {
                let locked: Vec<&str> = v["locked"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|s| s.as_str())
                    .collect();
                println!(
                    "locked: {}",
                    if locked.is_empty() {
                        "nothing was unlocked".into()
                    } else {
                        locked.join(", ")
                    }
                );
            }
            Err(_) if UnixStream::connect(&sock).is_err() => {
                println!("not running (nothing unlocked)")
            }
            Err(e) => die(&e),
        },
        "status" => match request(&sock, &json!({"op": "status"}), short) {
            Ok(v) => {
                println!(
                    "running: pid {} on {}",
                    v["pid"],
                    v["listen"].as_str().unwrap_or("?")
                );
                for s in v["services"].as_array().into_iter().flatten() {
                    let name = s["name"].as_str().unwrap_or("?");
                    match s["state"].as_str().unwrap_or("?") {
                        "unlocked" => {
                            let left = s["locks_in_secs"].as_u64().unwrap_or(0);
                            println!(
                                "  {name}: unlocked, locks in {}h{:02}m",
                                left / 3600,
                                left / 60 % 60
                            );
                        }
                        "unlocking" => {
                            println!("  {name}: unlocking (waiting for Touch ID / password)")
                        }
                        other => println!("  {name}: {other}"),
                    }
                }
            }
            Err(_) if UnixStream::connect(&sock).is_err() => println!("not running"),
            Err(e) => die(&e),
        },
        "stop" => match request(&sock, &json!({"op": "stop"}), short) {
            Ok(_) => println!("stopped"),
            Err(_) => println!("not running"),
        },
        _ => die(USAGE),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        for config in [None, Some("/tmp/a & b/config.toml")] {
            let text = super::plist("/opt/homebrew/bin/credproxy", config, "/tmp/err.log");
            assert!(
                !text.contains('\\'),
                "no escape sequences left in the plist"
            );
            assert!(
                text.contains("<key>SuccessfulExit</key>"),
                "restart only after a crash"
            );
            let p = dir.path().join("io.nhz.credproxy.plist");
            std::fs::write(&p, &text).unwrap();
            let lint = std::process::Command::new("/usr/bin/plutil")
                .arg("-lint")
                .arg(&p)
                .output()
                .unwrap();
            assert!(
                lint.status.success(),
                "{}\n{text}",
                String::from_utf8_lossy(&lint.stdout)
            );
        }
    }
}
