//! Config file: services, their upstreams and what each may call.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "default_idle")]
    idle_lock: String,
    #[serde(default = "default_age")]
    age: String,
    #[serde(default = "default_identity")]
    identity: String,
    #[serde(default = "default_secrets_dir")]
    secrets_dir: String,
    #[serde(default = "default_runtime_dir")]
    runtime_dir: String,
    #[serde(default = "default_log")]
    log: String,
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    services: BTreeMap<String, RawService>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    secret: String,
    #[serde(default)]
    auth: RawAuth,
    routes: Vec<RawRoute>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuth {
    #[serde(default = "default_header")]
    header: String,
    #[serde(default = "default_format")]
    format: String,
}

impl Default for RawAuth {
    fn default() -> Self {
        RawAuth {
            header: default_header(),
            format: default_format(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    prefix: String,
    upstream: String,
    #[serde(default)]
    allow: Vec<String>,
    graphql_queries: Option<Vec<String>>,
}

fn default_idle() -> String {
    "12h".into()
}
fn default_age() -> String {
    "age".into()
}
fn default_identity() -> String {
    "~/.config/age/se-identity.txt".into()
}
fn default_secrets_dir() -> String {
    "~/.secrets".into()
}
fn default_runtime_dir() -> String {
    "~/Library/Caches/credproxy".into()
}
fn default_log() -> String {
    "~/Library/Logs/credproxy.log".into()
}
fn default_listen() -> String {
    "127.0.0.1:7777".into()
}
fn default_header() -> String {
    "Authorization".into()
}
fn default_format() -> String {
    "Bearer {key}".into()
}

#[derive(Debug)]
pub struct Config {
    pub idle_lock: Duration,
    pub age: String,
    pub identity: PathBuf,
    pub secrets_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub log: PathBuf,
    /// Loopback address clients call: http://<listen>/<service>/<route prefix>/...
    pub listen: SocketAddr,
    pub services: BTreeMap<String, Service>,
}

#[derive(Debug)]
pub struct Service {
    pub secret: PathBuf,
    pub auth_header: String,
    pub auth_format: String,
    pub routes: Vec<Route>,
}

#[derive(Debug)]
pub struct Route {
    /// Client path prefix, without a trailing slash ("" for the root).
    pub prefix: String,
    /// Upstream base URL, without a trailing slash.
    pub upstream: String,
    pub allow: Vec<Rule>,
    /// Some(fields) = GraphQL endpoint: POST only, one `query` operation whose top-level fields are all listed.
    pub graphql_queries: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct Rule {
    pub method: String,
    pub segments: Vec<Segment>,
}

#[derive(Debug, PartialEq)]
pub enum Segment {
    Literal(String),
    Param,
}

pub fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None => PathBuf::from(p),
    }
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

pub fn default_path() -> PathBuf {
    home().join(".config/credproxy/config.toml")
}

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| format!("bad duration {s:?}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return Err(format!("bad duration {s:?} (use e.g. 30s, 15m, 12h)")),
    };
    if secs == 0 {
        return Err("duration must be > 0".into());
    }
    Ok(Duration::from_secs(secs))
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A path segment that may stand in for `{param}`: plain ids only, never `.`/`..` or anything encoded.
pub fn valid_param(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn check_upstream(u: &str) -> Result<String, String> {
    let u = u.trim_end_matches('/');
    let rest = if let Some(r) = u.strip_prefix("https://") {
        r
    } else if let Some(r) = u.strip_prefix("http://") {
        // Plain http only to this machine (tests, local fakes); the key never crosses a network unencrypted.
        let host = r.split(['/', ':']).next().unwrap_or("");
        if host != "127.0.0.1" && host != "localhost" {
            return Err(format!("upstream {u:?}: https required"));
        }
        r
    } else {
        return Err(format!("upstream {u:?}: must start with https://"));
    };
    if rest.is_empty() || rest.contains(['?', '#', '@']) {
        return Err(format!("upstream {u:?}: host and path only"));
    }
    Ok(u.to_string())
}

fn parse_rule(r: &str) -> Result<Rule, String> {
    let (method, path) = r
        .split_once(' ')
        .ok_or(format!("rule {r:?}: expected \"METHOD /path\""))?;
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(format!("rule {r:?}: method must be upper case"));
    }
    let path = path.trim();
    if !path.starts_with('/') {
        return Err(format!("rule {r:?}: path must start with /"));
    }
    let mut segments = Vec::new();
    for s in path.split('/').skip(1) {
        if s.starts_with('{') && s.ends_with('}') && s.len() > 2 {
            segments.push(Segment::Param);
        } else if valid_param(s) {
            segments.push(Segment::Literal(s.to_string()));
        } else {
            return Err(format!("rule {r:?}: bad segment {s:?}"));
        }
    }
    Ok(Rule {
        method: method.to_string(),
        segments,
    })
}

impl Rule {
    pub fn matches(&self, method: &str, path: &str) -> bool {
        if method != self.method {
            return false;
        }
        let Some(rest) = path.strip_prefix('/') else {
            return false;
        };
        let parts: Vec<&str> = rest.split('/').collect();
        parts.len() == self.segments.len()
            && parts.iter().zip(&self.segments).all(|(p, s)| match s {
                Segment::Literal(l) => p == l,
                Segment::Param => valid_param(p),
            })
    }
}

impl Route {
    /// The upstream-relative path ("" or "/…") if this route serves `path`.
    pub fn strip<'a>(&self, path: &'a str) -> Option<&'a str> {
        let rest = path.strip_prefix(self.prefix.as_str())?;
        (rest.is_empty() || rest.starts_with('/')).then_some(rest)
    }
}

impl Service {
    pub fn route(&self, path: &str) -> Option<(&Route, String)> {
        // Longest prefix wins, so "/graphql" beats "".
        self.routes
            .iter()
            .filter_map(|r| r.strip(path).map(|rest| (r, rest)))
            .max_by_key(|(r, _)| r.prefix.len())
            .map(|(r, rest)| (r, rest.to_string()))
    }
}

fn check_listen(s: &str) -> Result<SocketAddr, String> {
    let a: SocketAddr = s
        .parse()
        .map_err(|_| format!("listen {s:?}: expected 127.0.0.1:<port>"))?;
    if !a.ip().is_loopback() {
        return Err(format!("listen {s:?}: loopback addresses only"));
    }
    Ok(a)
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn parse(text: &str) -> Result<Config, String> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut services = BTreeMap::new();
    for (name, s) in raw.services {
        if !valid_name(&name) {
            return Err(format!("service {name:?}: use a-z, 0-9 and -"));
        }
        if s.secret
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(format!(
                "service {name}: secret must be a relative path like \"{name}/api-key\""
            ));
        }
        if !s.auth.format.contains("{key}") {
            return Err(format!("service {name}: auth.format must contain {{key}}"));
        }
        if s.auth.header.is_empty()
            || !s
                .auth
                .header
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(format!("service {name}: bad auth.header"));
        }
        if s.routes.is_empty() {
            return Err(format!("service {name}: no routes"));
        }
        let mut routes = Vec::new();
        for r in s.routes {
            let prefix = r.prefix.trim_end_matches('/').to_string();
            if !(prefix.is_empty() || prefix.starts_with('/')) {
                return Err(format!(
                    "service {name}: prefix {:?} must start with /",
                    r.prefix
                ));
            }
            if routes.iter().any(|x: &Route| x.prefix == prefix) {
                return Err(format!("service {name}: duplicate prefix {:?}", r.prefix));
            }
            let upstream =
                check_upstream(&r.upstream).map_err(|e| format!("service {name}: {e}"))?;
            let allow = r
                .allow
                .iter()
                .map(|a| parse_rule(a))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("service {name}: {e}"))?;
            if allow.is_empty() && r.graphql_queries.is_none() {
                return Err(format!(
                    "service {name}: route {:?} allows nothing",
                    r.prefix
                ));
            }
            if !allow.is_empty() && r.graphql_queries.is_some() {
                return Err(format!(
                    "service {name}: route {:?}: use allow or graphql_queries, not both",
                    r.prefix
                ));
            }
            routes.push(Route {
                prefix,
                upstream,
                allow,
                graphql_queries: r.graphql_queries,
            });
        }
        services.insert(
            name.clone(),
            Service {
                secret: PathBuf::from(format!("{}.age", s.secret)),
                auth_header: s.auth.header,
                auth_format: s.auth.format,
                routes,
            },
        );
    }
    Ok(Config {
        idle_lock: parse_duration(&raw.idle_lock)?,
        age: raw.age,
        identity: expand(&raw.identity),
        secrets_dir: expand(&raw.secrets_dir),
        runtime_dir: expand(&raw.runtime_dir),
        log: expand(&raw.log),
        listen: check_listen(&raw.listen)?,
        services,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNPOD: &str = r#"
[services.runpod]
secret = "runpod/api-key"
[[services.runpod.routes]]
prefix = "/graphql"
upstream = "https://api.runpod.io/graphql"
graphql_queries = ["gpuTypes"]
[[services.runpod.routes]]
prefix = "/"
upstream = "https://rest.runpod.io/v1/"
allow = ["GET /pods", "POST /pods", "GET /pods/{id}", "DELETE /pods/{id}", "GET /billing/pods"]
[[services.runpod.routes]]
prefix = "/v2"
upstream = "https://api.runpod.io/v2"
allow = ["GET /pods", "DELETE /pods/{id}", "GET /catalog/gpus"]
"#;

    #[test]
    fn example_config_parses() {
        let c = parse(include_str!("../examples/runpod.toml")).unwrap();
        let s = &c.services["runpod"];
        assert_eq!(c.listen.to_string(), "127.0.0.1:7777");
        assert_eq!(
            s.route("/v1/pods").unwrap().0.upstream,
            "https://rest.runpod.io/v1"
        );
        assert!(s.route("/graphql").unwrap().0.graphql_queries.is_some());
        assert!(s.route("/v2/pods").is_none() && s.route("/pods").is_none());
    }

    #[test]
    fn longest_prefix_wins() {
        let c = parse(RUNPOD).unwrap();
        let s = &c.services["runpod"];
        let (r, rest) = s.route("/v2/pods").unwrap();
        assert_eq!(
            (r.upstream.as_str(), rest.as_str()),
            ("https://api.runpod.io/v2", "/pods")
        );
        assert_eq!(s.route("/v2").unwrap().0.prefix, "/v2");
        assert_eq!(s.route("/v2x/pods").unwrap().0.prefix, "");
        assert!(allowed(&c, "GET", "/v2/catalog/gpus"));
        assert!(
            !allowed(&c, "GET", "/catalog/gpus"),
            "v1 route has no catalog"
        );
        assert!(!allowed(&c, "POST", "/v2/pods"), "per-route allowlists");
        assert!(!allowed(&c, "GET", "/v2/user"));
    }

    fn allowed(c: &Config, method: &str, path: &str) -> bool {
        let s = &c.services["runpod"];
        match s.route(path) {
            Some((r, rest)) => r.allow.iter().any(|a| a.matches(method, &rest)),
            None => false,
        }
    }

    #[test]
    fn defaults_and_routes() {
        let c = parse(RUNPOD).unwrap();
        assert_eq!(c.idle_lock, Duration::from_secs(12 * 3600));
        let s = &c.services["runpod"];
        assert_eq!(s.secret, PathBuf::from("runpod/api-key.age"));
        assert_eq!(s.auth_format, "Bearer {key}");
        assert_eq!(c.listen.to_string(), "127.0.0.1:7777");
        let (r, rest) = s.route("/graphql").unwrap();
        assert!(r.graphql_queries.is_some());
        assert_eq!(rest, "");
        let (r, rest) = s.route("/pods/abc").unwrap();
        assert_eq!(r.upstream, "https://rest.runpod.io/v1");
        assert_eq!(rest, "/pods/abc");
        // "/graphqlx" is not under "/graphql": falls to the REST route
        assert_eq!(s.route("/graphqlx").unwrap().0.prefix, "");
    }

    #[test]
    fn allowlist() {
        let c = parse(RUNPOD).unwrap();
        for (m, p) in [
            ("GET", "/pods"),
            ("POST", "/pods"),
            ("GET", "/pods/ab12-cd"),
            ("DELETE", "/pods/x"),
            ("GET", "/billing/pods"),
        ] {
            assert!(allowed(&c, m, p), "{m} {p}");
        }
        for (m, p) in [
            ("DELETE", "/pods"),
            ("PATCH", "/pods/x"),
            ("GET", "/pods/x/logs"),
            ("GET", "/pods/"),
            ("GET", "/pods/.."),
            ("GET", "/pods/%2e%2e"),
            ("GET", "/pods//x"),
            ("GET", "/endpoints"),
            ("get", "/pods"),
            ("GET", "/billing/pods/x"),
            ("POST", "/user/apikey"),
        ] {
            assert!(!allowed(&c, m, p), "{m} {p}");
        }
    }

    #[test]
    fn rejects_bad_config() {
        let bad = [
            RUNPOD.replace("https://api.runpod.io", "http://api.runpod.io"),
            RUNPOD.replace("runpod/api-key", "../api-key"),
            format!("listen = \"0.0.0.0:7777\"\n{RUNPOD}"),
            format!("listen = \"7777\"\n{RUNPOD}"),
            RUNPOD.replace("GET /pods/{id}", "GET pods"),
            RUNPOD.replace("prefix = \"/graphql\"", "prefix = \"/\""),
            format!("idle_lock = \"0h\"\n{RUNPOD}"),
            format!("idle_lock = \"12\"\n{RUNPOD}"),
            format!("{RUNPOD}\n[services.runpod.auth]\nformat = \"Bearer\""),
            format!("bogus = 1\n{RUNPOD}"),
        ];
        for b in bad {
            assert!(parse(&b).is_err(), "accepted:\n{b}");
        }
        assert!(parse(&RUNPOD.replace("https://api.runpod.io", "http://127.0.0.1:9")).is_ok());
    }
}
