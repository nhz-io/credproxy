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
  credproxy env [--launchctl]     client variables (URLs + token) as `export` lines; --launchctl sets them in launchd
  credproxy status                which services are unlocked, and for how long
  credproxy unlock <service>      unlock now (Touch ID); otherwise the first request unlocks
  credproxy lock [<service>]      forget the key(s) now
  credproxy rotate <service>      new token (old one stops working); new shells and apps get it
  credproxy install               LaunchAgent: start at login, restart if it exits
  credproxy uninstall             remove the LaunchAgent and the launchd variables
  credproxy stop                  stop the daemon (locks everything; launchd starts it again)
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

fn sh_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
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

fn launchctl(args: &[&str]) -> bool {
    Command::new("/bin/launchctl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn install(cfg_path: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut env = String::from(
        "\t\t<key>PATH</key>\n\t\t<string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>\n",
    );
    if std::env::var_os("CREDPROXY_CONFIG").is_some() {
        env += &format!(
            "\t\t<key>CREDPROXY_CONFIG</key>\n\t\t<string>{}</string>\n",
            xml(&cfg_path.to_string_lossy())
        );
    }
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>{LABEL}</string>
\t<key>ProgramArguments</key>
\t<array>
\t\t<string>{}</string>
\t\t<string>serve</string>
\t</array>
\t<key>EnvironmentVariables</key>
\t<dict>
{env}\t</dict>
\t<key>RunAtLoad</key>
\t<true/>
\t<key>KeepAlive</key>
\t<true/>
\t<key>ProcessType</key>
\t<string>Interactive</string>
\t<key>StandardErrorPath</key>
\t<string>{}</string>
</dict>
</plist>
"#,
        xml(&exe.to_string_lossy()),
        xml(&home()
            .join("Library/Logs/credproxy.err.log")
            .to_string_lossy()),
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

fn uninstall(cfg: Option<&config::Config>) {
    launchctl(&[
        "bootout",
        &format!("gui/{}/{LABEL}", unsafe { libc::getuid() }),
    ]);
    let _ = std::fs::remove_file(plist_path());
    if let Some(cfg) = cfg {
        for svc in cfg.services.values() {
            for k in svc.env.keys() {
                launchctl(&["unsetenv", k]);
            }
        }
    }
    println!("uninstalled (tokens in the state dir are kept)");
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
            die(&e);
        }
        return;
    }
    if cmd == "uninstall" {
        uninstall(config::load(&cfg_path).ok().as_ref());
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
        "env" => {
            let launchd = service == Some("--launchctl");
            for name in cfg.services.keys() {
                let token = vault::token(&cfg, name).unwrap_or_else(|e| die(&e));
                if launchd {
                    serve::publish_env(&cfg, name, &token);
                } else {
                    for (k, v) in cfg.client_env(name, &token) {
                        println!("export {k}={}", sh_quote(&v));
                    }
                }
            }
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
        "rotate" => {
            let s = need_service();
            match request(&sock, &json!({"op": "rotate", "service": s}), short) {
                Ok(_) => {}
                Err(_) if UnixStream::connect(&sock).is_err() => {
                    vault::rotate_file(&cfg, s).unwrap_or_else(|e| die(&e));
                }
                Err(e) => die(&e),
            }
            println!("rotated: {s} (open a new shell, or `eval \"$(credproxy env)\"`)");
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
                    if s["unlocked"] == json!(true) {
                        let left = s["locks_in_secs"].as_u64().unwrap_or(0);
                        println!(
                            "  {name}: unlocked, locks in {}h{:02}m",
                            left / 3600,
                            left / 60 % 60
                        );
                    } else {
                        println!("  {name}: locked");
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
