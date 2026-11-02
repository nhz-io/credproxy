//! Config file: services, their upstreams and what each may call.

use crate::s3::Op;
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
    #[serde(default = "default_s3_idle")]
    s3_idle: String,
    #[serde(default = "default_s3_reply_wait")]
    s3_reply_wait: String,
    #[serde(default = "default_s3_connect_timeout")]
    s3_connect_timeout: String,
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
    /// Sign requests with AWS SigV4 instead of putting the key in `header`.
    sigv4: Option<RawSigv4>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSigv4 {
    #[serde(default = "default_sigv4_service")]
    service: String,
}

impl Default for RawAuth {
    fn default() -> Self {
        RawAuth {
            header: default_header(),
            format: default_format(),
            sigv4: None,
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
    s3: Option<RawS3>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawS3 {
    region: String,
    ops: Vec<String>,
    #[serde(default)]
    key_prefixes: Vec<String>,
    #[serde(default)]
    unsigned_payload: bool,
}

fn default_idle() -> String {
    "12h".into()
}
fn default_s3_idle() -> String {
    "60s".into()
}
fn default_s3_reply_wait() -> String {
    "2h".into()
}
fn default_s3_connect_timeout() -> String {
    "30s".into()
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
fn default_sigv4_service() -> String {
    "s3".into()
}

#[derive(Debug)]
pub struct Config {
    pub idle_lock: Duration,
    /// S3 transfers have no overall limit; one that moves no bytes for this long is cut off.
    pub s3_idle: Duration,
    /// How long an S3 upstream may take to start its reply once the request is sent (a big
    /// CompleteMultipartUpload can take long).
    pub s3_reply_wait: Duration,
    /// Connecting to an S3 upstream (DNS, TCP, TLS): counted as expected silence, and into the reply wait of
    /// requests whose clock starts before the connection exists.
    pub s3_connect_timeout: Duration,
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
    /// How clients send the token (and, without `sigv4`, how the key goes upstream).
    pub auth_header: String,
    pub auth_format: String,
    /// Some(signing service name, e.g. "s3"): requests are signed with SigV4; the sealed file holds two lines,
    /// the access key id and the secret.
    pub sigv4: Option<String>,
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
    /// Some = S3 endpoint (SigV4 services only): only the listed operations, path-style.
    pub s3: Option<S3Route>,
}

#[derive(Debug)]
pub struct S3Route {
    /// Signing region (RunPod: the datacenter id, e.g. "EU-RO-1"; R2: "auto").
    pub region: String,
    pub ops: Vec<Op>,
    /// If not empty, object keys (and list prefixes) must start with one of these.
    pub key_prefixes: Vec<String>,
    /// Pass a client's `x-amz-content-sha256: UNSIGNED-PAYLOAD` through (body not covered by the signature).
    pub unsigned_payload: bool,
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
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return Err(format!("bad duration {s:?} (use e.g. 30s, 15m, 12h)")),
    };
    let secs = n
        .checked_mul(mult)
        .ok_or(format!("duration {s:?} is too large"))?;
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

/// Any HTTP header name (RFC 9110 token), e.g. `Authorization`, `X-API-Key` or `api_key`.
fn valid_header(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Headers the auth header can't be: credproxy sets them itself, forwards them from the client, or they belong to
/// the connection.
const RESERVED_HEADERS: [&str; 14] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "expect",
    "accept-encoding",
    "user-agent",
    "content-type",
    "accept",
];

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
    let parts: Vec<&str> = path.split('/').skip(1).collect();
    for (i, s) in parts.iter().copied().enumerate() {
        if s.is_empty() && i == parts.len() - 1 {
            // a trailing slash is part of the path: "GET /instances/" matches "/instances/", not "/instances"
            // (some APIs, e.g. Vast's, redirect one to the other, and redirects aren't followed)
            segments.push(Segment::Literal(String::new()));
        } else if s.starts_with('{') && s.ends_with('}') && s.len() > 2 {
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

fn check_s3(r: RawS3) -> Result<S3Route, String> {
    if r.region.is_empty()
        || !r
            .region
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!("bad s3.region {:?}", r.region));
    }
    if r.ops.is_empty() {
        return Err("s3.ops is empty".into());
    }
    let ops = r
        .ops
        .iter()
        .map(|o| Op::from_name(o).ok_or(format!("unknown s3 operation {o:?}")))
        .collect::<Result<Vec<_>, _>>()?;
    if r.key_prefixes.iter().any(|p| {
        p.starts_with('/')
            || !p.ends_with('/')
            || p.chars().any(char::is_control)
            || p.strip_suffix('/')
                .unwrap_or(p)
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
    }) {
        return Err(
            "s3.key_prefixes: directories like \"runs/\" (ending in /, no leading /)".into(),
        );
    }
    Ok(S3Route {
        region: r.region,
        ops,
        key_prefixes: r.key_prefixes,
        unsigned_payload: r.unsigned_payload,
    })
}

fn check_listen(s: &str) -> Result<SocketAddr, String> {
    let a: SocketAddr = s
        .parse()
        .map_err(|_| format!("listen {s:?}: expected 127.0.0.1:<port>"))?;
    if !a.ip().is_loopback() {
        return Err(format!("listen {s:?}: loopback addresses only"));
    }
    if a.port() == 0 {
        return Err(format!(
            "listen {s:?}: needs a fixed port (clients use a fixed URL)"
        ));
    }
    Ok(a)
}

fn bounded(s: &str, what: &str, max: Duration) -> Result<Duration, String> {
    let d = parse_duration(s).map_err(|e| format!("{what}: {e}"))?;
    if d > max {
        // in the largest unit that states it exactly, as the config would write it
        let secs = max.as_secs();
        let limit = if secs.is_multiple_of(3600) {
            format!("{}h", secs / 3600)
        } else if secs.is_multiple_of(60) {
            format!("{}m", secs / 60)
        } else {
            format!("{secs}s")
        };
        return Err(format!("{what}: at most {limit}"));
    }
    Ok(d)
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
        if s.auth.format.matches("{key}").count() != 1 {
            return Err(format!(
                "service {name}: auth.format must contain {{key}} exactly once"
            ));
        }
        if !valid_header(&s.auth.header) {
            return Err(format!("service {name}: bad auth.header"));
        }
        if RESERVED_HEADERS.contains(&s.auth.header.to_ascii_lowercase().as_str()) {
            return Err(format!(
                "service {name}: auth.header {:?} is set by credproxy or the connection",
                s.auth.header
            ));
        }
        if s.routes.is_empty() {
            return Err(format!("service {name}: no routes"));
        }
        // for S3 the token header must be one credproxy never forwards upstream (and not an x-amz-* header,
        // which refuses the call)
        let h = s.auth.header.to_ascii_lowercase();
        if s.auth.sigv4.is_some()
            && (h.starts_with("x-amz-") || crate::s3::FORWARDED_HEADERS.contains(&h.as_str()))
        {
            return Err(format!(
                "service {name}: auth.header {:?} can't carry the token for an S3 service",
                s.auth.header
            ));
        }
        if let Some(v) = &s.auth.sigv4
            && (v.service.is_empty()
                || !v
                    .service
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
        {
            return Err(format!("service {name}: bad auth.sigv4.service"));
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
            let s3 = match (r.s3, s.auth.sigv4.is_some()) {
                (Some(x), true) => Some(
                    check_s3(x)
                        .map_err(|e| format!("service {name}: route {:?}: {e}", r.prefix))?,
                ),
                (None, false) => None,
                (Some(_), false) => {
                    return Err(format!(
                        "service {name}: route {:?}: s3 routes need auth.sigv4",
                        r.prefix
                    ));
                }
                (None, true) => {
                    return Err(format!(
                        "service {name}: route {:?}: a sigv4 service has s3 routes only",
                        r.prefix
                    ));
                }
            };
            if s3.is_some() && (!allow.is_empty() || r.graphql_queries.is_some()) {
                return Err(format!(
                    "service {name}: route {:?}: use s3 alone",
                    r.prefix
                ));
            }
            if allow.is_empty() && r.graphql_queries.is_none() && s3.is_none() {
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
                s3,
            });
        }
        services.insert(
            name.clone(),
            Service {
                secret: PathBuf::from(format!("{}.age", s.secret)),
                auth_header: s.auth.header,
                auth_format: s.auth.format,
                sigv4: s.auth.sigv4.map(|v| v.service),
                routes,
            },
        );
    }
    Ok(Config {
        idle_lock: parse_duration(&raw.idle_lock)?,
        // bounded: they are added to clock readings, which must not overflow
        s3_idle: bounded(&raw.s3_idle, "s3_idle", Duration::from_secs(24 * 3600))?,
        s3_connect_timeout: bounded(
            &raw.s3_connect_timeout,
            "s3_connect_timeout",
            Duration::from_secs(300),
        )?,
        s3_reply_wait: bounded(
            &raw.s3_reply_wait,
            "s3_reply_wait",
            Duration::from_secs(7 * 24 * 3600),
        )?,
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
        assert!(
            s.route("/v1/networkvolumes/abc")
                .unwrap()
                .0
                .allow
                .iter()
                .any(|r| r.matches("DELETE", "/networkvolumes/abc"))
        );
        let s3 = &c.services["runpod-s3"];
        assert_eq!(s3.sigv4.as_deref(), Some("s3"));
        assert_eq!(s3.secret, PathBuf::from("runpod/s3-key.age"));
        for (dc, region) in [("eu-ro-1", "EU-RO-1"), ("us-ks-2", "US-KS-2")] {
            let (r, rest) = s3.route(&format!("/{dc}/vol/k")).unwrap();
            assert_eq!(r.upstream, format!("https://s3api-{dc}.runpod.io"));
            assert_eq!(rest, "/vol/k");
            let cfg = r.s3.as_ref().unwrap();
            assert_eq!(cfg.region, region);
            assert!(cfg.ops.contains(&Op::UploadPart) && !cfg.ops.contains(&Op::ListParts));
            assert!(!cfg.unsigned_payload);
        }
        assert!(s3.route("/eu-ro-2/vol/k").is_none());
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
        assert_eq!(
            (c.s3_idle, c.s3_reply_wait),
            (Duration::from_secs(60), Duration::from_secs(7200))
        );
        let c = parse(&format!(
            "s3_idle = \"2s\"\ns3_reply_wait = \"5m\"\n{RUNPOD}"
        ))
        .unwrap();
        assert_eq!(
            (c.s3_idle, c.s3_reply_wait),
            (Duration::from_secs(2), Duration::from_secs(300))
        );
        assert!(parse(&format!("s3_idle = \"0s\"\n{RUNPOD}")).is_err());
        assert!(parse(&format!("s3_idle = \"25h\"\n{RUNPOD}")).is_err());
        assert!(parse(&format!("s3_reply_wait = \"99999999999999h\"\n{RUNPOD}")).is_err());
        assert!(parse(&format!("s3_reply_wait = \"168h\"\n{RUNPOD}")).is_ok());
        assert_eq!(c.s3_connect_timeout, Duration::from_secs(30));
        let err = |extra: &str| parse(&format!("{extra}\n{RUNPOD}")).unwrap_err();
        assert_eq!(
            err("s3_connect_timeout = \"6m\""),
            "s3_connect_timeout: at most 5m"
        );
        assert_eq!(err("s3_idle = \"25h\""), "s3_idle: at most 24h");
        assert_eq!(
            err("s3_reply_wait = \"169h\""),
            "s3_reply_wait: at most 168h"
        );
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
    fn auth_header_names() {
        let with = |h: &str| {
            parse(&format!(
                "{RUNPOD}\n[services.runpod.auth]\nheader = \"{h}\"\nformat = \"{{key}}\""
            ))
        };
        for h in ["api_key", "X-API-Key", "x.token", "Authorization"] {
            assert_eq!(with(h).unwrap().services["runpod"].auth_header, h);
        }
        for h in ["", "api key", "api:key", "ápi", "x\\\"y"] {
            assert!(with(h).is_err(), "accepted {h:?}");
        }
        for h in [
            "Host",
            "content-length",
            "Accept-Encoding",
            "User-Agent",
            "Content-Type",
            "accept",
            "connection",
        ] {
            assert!(with(h).unwrap_err().contains("set by credproxy"), "{h}");
        }
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
        let c2 = parse(&RUNPOD.replace(
            "\"GET /billing/pods\"]",
            "\"GET /billing/pods\", \"GET /instances/\", \"GET /instances/{id}/\", \"POST /instances/{id}/ssh/\"]",
        ))
        .unwrap();
        for (m, p, ok) in [
            ("GET", "/instances/", true),
            ("GET", "/instances", false),
            ("GET", "/instances/7/", true),
            ("GET", "/instances/7", false),
            ("GET", "/instances/7//", false),
            ("GET", "/instances//", false),
            ("POST", "/instances/7/ssh/", true),
            ("POST", "/instances/7/ssh", false),
        ] {
            assert_eq!(allowed(&c2, m, p), ok, "{m} {p}");
        }
        // without a trailing slash in the rule, none in the path either
        assert!(!allowed(&c, "GET", "/pods/"));
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

    const S3: &str = r#"
[services.runpod-s3]
secret = "runpod/s3-key"
auth = { sigv4 = { service = "s3" } }
[[services.runpod-s3.routes]]
prefix = "/eu-ro-1"
upstream = "https://s3api-eu-ro-1.runpod.io"
s3 = { region = "EU-RO-1", ops = ["GetObject", "PutObject"] }
"#;

    #[test]
    fn sigv4_service() {
        let c = parse(S3).unwrap();
        let s = &c.services["runpod-s3"];
        assert_eq!(s.sigv4.as_deref(), Some("s3"));
        assert_eq!(
            s.auth_format, "Bearer {key}",
            "clients still send the token as a Bearer"
        );
        let (r, rest) = s.route("/eu-ro-1/vol/a").unwrap();
        let s3 = r.s3.as_ref().unwrap();
        assert_eq!((s3.region.as_str(), rest.as_str()), ("EU-RO-1", "/vol/a"));
        assert_eq!(s3.ops, [Op::GetObject, Op::PutObject]);
        assert!(!s3.unsigned_payload && s3.key_prefixes.is_empty());
        // a header of its own is fine
        assert!(
            parse(&S3.replace(
                "auth = { sigv4 = { service = \"s3\" } }",
                "auth = { header = \"X-Credproxy-Token\", format = \"{key}\", sigv4 = {} }"
            ))
            .is_ok()
        );
        let bad = [
            S3.replace("auth = { sigv4 = { service = \"s3\" } }", ""),
            S3.replace("\"PutObject\"", "\"CreateBucket\""),
            S3.replace("ops = [\"GetObject\", \"PutObject\"]", "ops = []"),
            S3.replace("EU-RO-1", "eu/ro"),
            S3.replace("service = \"s3\"", "service = \"S3\""),
            S3.replace("s3 = {", "allow = [\"GET /x\"]\ns3 = {"),
            S3.replace("ops = [", "key_prefixes = [\"/x/\"], ops = ["),
            S3.replace("ops = [", "key_prefixes = [\"runs\"], ops = ["),
            S3.replace("ops = [", "key_prefixes = [\"a/../b/\"], ops = ["),
            S3.replace("ops = [", "key_prefixes = [\"/\"], ops = ["),
            S3.replace("ops = [", "key_prefixes = [\"runs//\"], ops = ["),
            S3.replace(
                "auth = { sigv4 = { service = \"s3\" } }",
                "auth = { header = \"If-Match\", format = \"{key}\", sigv4 = {} }",
            ),
            S3.replace(
                "auth = { sigv4 = { service = \"s3\" } }",
                "auth = { header = \"X-Amz-Token\", sigv4 = {} }",
            ),
            S3.replace(
                "auth = { sigv4 = { service = \"s3\" } }",
                "auth = { header = \"Content-Type\", sigv4 = {} }",
            ),
            format!(
                "{S3}[[services.runpod-s3.routes]]\nprefix = \"/v1\"\nupstream = \"https://x\"\nallow = [\"GET /x\"]\n"
            ),
            format!(
                "{RUNPOD}[[services.runpod.routes]]\nprefix = \"/s3\"\nupstream = \"https://x\"\ns3 = {{ region = \"a\", ops = [\"GetObject\"] }}\n"
            ),
        ];
        for b in bad {
            assert!(parse(&b).is_err(), "accepted:\n{b}");
        }
    }

    #[test]
    fn rejects_bad_config() {
        let bad = [
            RUNPOD.replace("https://api.runpod.io", "http://api.runpod.io"),
            RUNPOD.replace("runpod/api-key", "../api-key"),
            format!("listen = \"0.0.0.0:7777\"\n{RUNPOD}"),
            format!("listen = \"7777\"\n{RUNPOD}"),
            format!("listen = \"127.0.0.1:0\"\n{RUNPOD}"),
            RUNPOD.replace("GET /pods/{id}", "GET pods"),
            RUNPOD.replace("GET /pods/{id}", "GET /pods//{id}"),
            RUNPOD.replace("GET /pods/{id}", "GET /pods/{id}//"),
            RUNPOD.replace("prefix = \"/graphql\"", "prefix = \"/\""),
            format!("idle_lock = \"0h\"\n{RUNPOD}"),
            format!("idle_lock = \"12\"\n{RUNPOD}"),
            format!("{RUNPOD}\n[services.runpod.auth]\nformat = \"Bearer\""),
            format!("{RUNPOD}\n[services.runpod.auth]\nformat = \"{{key}}:{{key}}\""),
            format!("idle_lock = \"99999999999999999h\"\n{RUNPOD}"),
            format!("bogus = 1\n{RUNPOD}"),
        ];
        for b in bad {
            assert!(parse(&b).is_err(), "accepted:\n{b}");
        }
        assert!(parse(&RUNPOD.replace("https://api.runpod.io", "http://127.0.0.1:9")).is_ok());
    }
}
