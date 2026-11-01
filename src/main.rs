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
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const USAGE: &str = "usage:
  credproxy run <service> [--] <command> [args...]   unlock if needed (Touch ID), run command with $<ENV> = proxy URL
  credproxy lock [<service>]                         forget the key(s) now
  credproxy status                                   which services are unlocked, and for how long
  credproxy stop                                     stop the daemon (locks everything)
  credproxy serve                                    run the daemon in the foreground (normally started by `run`)

config: $CREDPROXY_CONFIG or ~/.config/credproxy/config.toml";

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
    let mut s = UnixStream::connect(sock).map_err(|e| e.to_string())?;
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

fn ensure_daemon(cfg: &config::Config, cfg_path: &Path) -> Result<PathBuf, String> {
    let sock = serve::socket_path(cfg);
    if UnixStream::connect(&sock).is_ok() {
        return Ok(sock);
    }
    serve::private_dir(&cfg.runtime_dir)?;
    if let Some(d) = cfg.log.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let err = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.log)
        .map_err(|e| e.to_string())?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // Own process group: Ctrl-C in this terminal must not take the daemon (and other users of it) down.
    Command::new(exe)
        .arg("serve")
        .env("CREDPROXY_CONFIG", cfg_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(err)
        .process_group(0)
        .spawn()
        .map_err(|e| format!("cannot start daemon: {e}"))?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if UnixStream::connect(&sock).is_ok() {
            return Ok(sock);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("daemon did not start; see {}", cfg.log.display()))
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
    let cfg = config::load(&cfg_path).unwrap_or_else(|e| die(&e));
    let sock = serve::socket_path(&cfg);
    let short = Duration::from_secs(5);
    match cmd {
        "run" => {
            let Some(service) = args.get(1) else {
                die(USAGE)
            };
            let mut rest = &args[2..];
            if rest.first().map(String::as_str) == Some("--") {
                rest = &rest[1..];
            }
            let Some((prog, prog_args)) = rest.split_first() else {
                die(USAGE)
            };
            if !cfg.services.contains_key(service) {
                die(&format!(
                    "unknown service {service:?} (see {})",
                    cfg_path.display()
                ));
            }
            let sock = ensure_daemon(&cfg, &cfg_path).unwrap_or_else(|e| die(&e));
            // Long timeout: the first unlock waits for Touch ID.
            let v = request(
                &sock,
                &json!({"op": "unlock", "service": service}),
                Duration::from_secs(150),
            )
            .unwrap_or_else(|e| die(&e));
            let (Some(env), Some(url)) = (v["env"].as_str(), v["url"].as_str()) else {
                die("bad answer from daemon")
            };
            let e = Command::new(prog).args(prog_args).env(env, url).exec();
            die(&format!("{prog}: {e}"));
        }
        "lock" => match request(&sock, &json!({"op": "lock", "service": args.get(1)}), short) {
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
                println!("running: pid {} port {}", v["pid"], v["port"]);
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
