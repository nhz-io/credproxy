//! S3 with SigV4: which operation a request is (method + path + query), the canonical path and query sent
//! upstream, and the signature made with the secret held in memory. Path-style URLs only: /<bucket>/<key>.

use crate::config::valid_param;
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use std::time::SystemTime;

pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Everything but A-Z a-z 0-9 - . _ ~ is percent-encoded (SigV4's URI encoding).
const ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    GetObject,
    HeadObject,
    PutObject,
    DeleteObject,
    HeadBucket,
    ListObjectsV2,
    CreateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    ListParts,
}

const OPS: [(&str, Op); 11] = [
    ("GetObject", Op::GetObject),
    ("HeadObject", Op::HeadObject),
    ("PutObject", Op::PutObject),
    ("DeleteObject", Op::DeleteObject),
    ("HeadBucket", Op::HeadBucket),
    ("ListObjectsV2", Op::ListObjectsV2),
    ("CreateMultipartUpload", Op::CreateMultipartUpload),
    ("UploadPart", Op::UploadPart),
    ("CompleteMultipartUpload", Op::CompleteMultipartUpload),
    ("AbortMultipartUpload", Op::AbortMultipartUpload),
    ("ListParts", Op::ListParts),
];

impl Op {
    pub fn from_name(s: &str) -> Option<Op> {
        OPS.iter().find(|(n, _)| *n == s).map(|(_, o)| *o)
    }

    pub fn name(self) -> &'static str {
        OPS.iter().find(|(_, o)| *o == self).unwrap().0
    }

    /// Operations whose request body is data (streamed); the others carry none or a small XML document.
    pub fn streams_body(self) -> bool {
        matches!(self, Op::PutObject | Op::UploadPart)
    }
}

/// A checked S3 call: the operation, and the path ("/bucket[/key]") and query as they go upstream, re-encoded
/// canonically so the signed and the sent request are the same bytes.
#[derive(Debug, PartialEq)]
pub struct Target {
    pub op: Op,
    pub path: String,
    pub query: String,
}

fn encode(s: &str) -> String {
    utf8_percent_encode(s, ENCODE).to_string()
}

/// Percent-decode strictly: every `%` must start a two-digit hex escape, and the result must be UTF-8.
fn decode(raw: &str) -> Option<String> {
    let b = raw.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || !(b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit()) {
                return None;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

/// An object key: no control characters, no `.`/`..` or empty segments (RunPod keys are file paths), at most
/// one trailing `/` (a "directory").
fn valid_key(k: &str) -> bool {
    if k.is_empty() || k.len() > 1024 || k.chars().any(char::is_control) {
        return false;
    }
    let body = k.strip_suffix('/').unwrap_or(k);
    !body.is_empty()
        && body
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

/// Which allowed S3 call this is, or why not. `prefixes`, if any, limit object keys and list prefixes.
pub fn classify(
    method: &str,
    sub: &str,
    query: Option<&str>,
    prefixes: &[String],
) -> Result<Target, String> {
    let refuse = || format!("{method} {}: not an allowed S3 call", shorten(sub));
    let rest = sub.strip_prefix('/').ok_or_else(refuse)?;
    let (bucket, key_raw) = match rest.split_once('/') {
        Some((b, k)) if !k.is_empty() => (b, Some(k)),
        Some((b, _)) => (b, None),
        None => (rest, None),
    };
    if !valid_param(bucket) {
        // also ListBuckets (no bucket at all)
        return Err(refuse());
    }
    let key = match key_raw {
        Some(raw) => {
            let k = decode(raw)
                .filter(|k| valid_key(k))
                .ok_or("bad object key")?;
            if !prefixes.is_empty() && !prefixes.iter().any(|p| k.starts_with(p.as_str())) {
                return Err("object key outside the allowed prefixes".into());
            }
            Some(k)
        }
        None => None,
    };

    let mut params: Vec<(String, String)> = Vec::new();
    for part in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let k = decode(&k.replace('+', " ")).ok_or_else(refuse)?;
        let v = decode(&v.replace('+', " ")).ok_or_else(refuse)?;
        if params.iter().any(|(x, _)| *x == k) || v.chars().any(char::is_control) {
            return Err(refuse());
        }
        params.push((k, v));
    }
    let get = |n: &str| params.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    // exactly `required` (all present) plus any of `optional`
    let shape = |required: &[&str], optional: &[&str]| {
        required.iter().all(|r| get(r).is_some())
            && params
                .iter()
                .all(|(k, _)| required.contains(&k.as_str()) || optional.contains(&k.as_str()))
    };
    let none = params.is_empty();

    let op = match (method, key.is_some()) {
        ("HEAD", false) if none => Op::HeadBucket,
        ("GET", false)
            if shape(
                &["list-type"],
                &[
                    "prefix",
                    "delimiter",
                    "continuation-token",
                    "max-keys",
                    "start-after",
                    "encoding-type",
                    "fetch-owner",
                ],
            ) && get("list-type") == Some("2") =>
        {
            if !prefixes.is_empty() {
                let p = get("prefix").unwrap_or("");
                if !prefixes.iter().any(|x| p.starts_with(x.as_str())) {
                    return Err("list prefix outside the allowed prefixes".into());
                }
            }
            Op::ListObjectsV2
        }
        ("GET", true) if none => Op::GetObject,
        ("GET", true) if shape(&["uploadId"], &["max-parts", "part-number-marker"]) => {
            Op::ListParts
        }
        ("HEAD", true) if none => Op::HeadObject,
        ("PUT", true) if none => Op::PutObject,
        ("PUT", true)
            if shape(&["partNumber", "uploadId"], &[])
                && get("partNumber").is_some_and(|n| {
                    n.len() <= 5
                        && n.bytes().all(|b| b.is_ascii_digit())
                        && (1..=10000).contains(&n.parse::<u32>().unwrap_or(0))
                }) =>
        {
            Op::UploadPart
        }
        ("POST", true) if shape(&["uploads"], &[]) && get("uploads") == Some("") => {
            Op::CreateMultipartUpload
        }
        ("POST", true) if shape(&["uploadId"], &[]) => Op::CompleteMultipartUpload,
        ("DELETE", true) if none => Op::DeleteObject,
        ("DELETE", true) if shape(&["uploadId"], &[]) => Op::AbortMultipartUpload,
        _ => return Err(refuse()),
    };

    let mut path = format!("/{}", encode(bucket));
    if let Some(k) = &key {
        path.push('/');
        path.push_str(&k.split('/').map(encode).collect::<Vec<_>>().join("/"));
    }
    params.sort();
    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    Ok(Target { op, path, query })
}

fn shorten(p: &str) -> String {
    p.chars()
        .take(200)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

/// A payload hash a client may send in `x-amz-content-sha256`: 64 hex digits (lower-cased here).
pub fn client_hash(v: &str) -> Option<String> {
    (v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())).then(|| v.to_ascii_lowercase())
}

pub fn sha256_hex(body: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// SigV4 headers (authorization, x-amz-date, x-amz-content-sha256) for a request to `url` carrying `headers`
/// (all of them are signed) and a body with SHA-256 `payload` (hex) or UNSIGNED-PAYLOAD.
#[allow(clippy::too_many_arguments)]
pub fn sign_headers(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    payload: &str,
    region: &str,
    service: &str,
    access_key: &str,
    secret: &str,
) -> Result<Vec<(String, String)>, String> {
    let identity: Identity = Credentials::new(access_key, secret, None, None, "credproxy").into();
    let mut settings = SigningSettings::default();
    // The path is already canonical (see classify); S3 signs it as sent, without normalising.
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .map_err(|e| e.to_string())?
        .into();
    let body = if payload == UNSIGNED_PAYLOAD {
        SignableBody::UnsignedPayload
    } else {
        SignableBody::Precomputed(payload.to_string())
    };
    let req = SignableRequest::new(method, url, headers.iter().copied(), body)
        .map_err(|e| e.to_string())?;
    let (instructions, _) = sign(req, &params)
        .map_err(|e| format!("signing failed: {e}"))?
        .into_parts();
    Ok(instructions
        .headers()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(m: &str, p: &str, q: Option<&str>) -> Result<Op, String> {
        classify(m, p, q, &[]).map(|t| t.op)
    }

    #[test]
    fn operations() {
        for (m, p, q, want) in [
            ("GET", "/vol/a/b.bin", None, Op::GetObject),
            ("HEAD", "/vol/a", None, Op::HeadObject),
            ("PUT", "/vol/a", None, Op::PutObject),
            ("DELETE", "/vol/a", None, Op::DeleteObject),
            ("HEAD", "/vol", None, Op::HeadBucket),
            (
                "GET",
                "/vol",
                Some("list-type=2&prefix=a/"),
                Op::ListObjectsV2,
            ),
            ("GET", "/vol/", Some("list-type=2"), Op::ListObjectsV2),
            ("POST", "/vol/a", Some("uploads"), Op::CreateMultipartUpload),
            (
                "POST",
                "/vol/a",
                Some("uploads="),
                Op::CreateMultipartUpload,
            ),
            (
                "PUT",
                "/vol/a",
                Some("partNumber=3&uploadId=u1"),
                Op::UploadPart,
            ),
            (
                "POST",
                "/vol/a",
                Some("uploadId=u1"),
                Op::CompleteMultipartUpload,
            ),
            (
                "DELETE",
                "/vol/a",
                Some("uploadId=u1"),
                Op::AbortMultipartUpload,
            ),
            (
                "GET",
                "/vol/a",
                Some("uploadId=u1&max-parts=10"),
                Op::ListParts,
            ),
            ("PUT", "/vol/dir/", None, Op::PutObject),
        ] {
            assert_eq!(op(m, p, q), Ok(want), "{m} {p} {q:?}");
        }
    }

    #[test]
    fn refusals() {
        for (m, p, q) in [
            ("GET", "/", None), // ListBuckets
            ("GET", "", None),
            ("PUT", "/vol", None),    // CreateBucket
            ("DELETE", "/vol", None), // DeleteBucket
            ("GET", "/vol", None),    // ListObjects v1
            ("GET", "/vol", Some("list-type=1")),
            ("GET", "/vol", Some("acl")),
            ("GET", "/vol/a", Some("acl")),
            ("PUT", "/vol/a", Some("tagging")),
            ("GET", "/vol/a", Some("versionId=1")),
            ("POST", "/vol", Some("delete")), // DeleteObjects
            ("GET", "/vol", Some("uploads")), // ListMultipartUploads
            ("PUT", "/vol/a", Some("partNumber=0&uploadId=u")),
            ("PUT", "/vol/a", Some("partNumber=10001&uploadId=u")),
            ("PUT", "/vol/a", Some("partNumber=1")),
            ("PUT", "/vol/a", Some("partNumber=1&uploadId=u&x=1")),
            ("POST", "/vol/a", Some("uploads=x")),
            ("POST", "/vol/a", None),
            ("PATCH", "/vol/a", None),
            ("get", "/vol/a", None),
            ("GET", "/vol/a", Some("uploadId=a&uploadId=b")),
            ("GET", "/../a", None),
            ("GET", "/vol/../a", None),
            ("GET", "/vol/%2e%2e/a", None),
            ("GET", "/vol/a/./b", None),
            ("GET", "/vol/a//b", None),
            ("GET", "/vol//a", None),
            ("GET", "/vol/a%zz", None),
            ("GET", "/vol/a%", None),
            ("GET", "/vol/a%0a", None),
            ("GET", "/vol/%ff", None),
            ("GET", "/v%6fl/a", None), // bucket must be plain
        ] {
            assert!(op(m, p, q).is_err(), "{m} {p} {q:?}");
        }
    }

    #[test]
    fn canonical_path_and_query() {
        let t = classify("GET", "/vol/dir%20x/a+b%2Bc~(1).bin", None, &[]).unwrap();
        assert_eq!(t.path, "/vol/dir%20x/a%2Bb%2Bc~%281%29.bin");
        assert_eq!(t.query, "");
        let t = classify("PUT", "/vol/k", Some("uploadId=a%2Fb+c&partNumber=2"), &[]).unwrap();
        assert_eq!(t.query, "partNumber=2&uploadId=a%2Fb%20c");
        let t = classify("POST", "/vol/k", Some("uploads"), &[]).unwrap();
        assert_eq!(t.query, "uploads=");
        let t = classify("GET", "/vol/ключ", None, &[]).unwrap();
        assert_eq!(t.path, "/vol/%D0%BA%D0%BB%D1%8E%D1%87");
    }

    #[test]
    fn prefixes() {
        let p = vec!["runs/".to_string()];
        assert!(classify("GET", "/vol/runs/a", None, &p).is_ok());
        assert!(classify("GET", "/vol/other/a", None, &p).is_err());
        assert!(classify("GET", "/vol/runs%2F..%2Fx", None, &p).is_err());
        assert!(classify("GET", "/vol", Some("list-type=2&prefix=runs/x"), &p).is_ok());
        assert!(classify("GET", "/vol", Some("list-type=2"), &p).is_err());
        assert!(classify("GET", "/vol", Some("list-type=2&prefix=r"), &p).is_err());
    }

    #[test]
    fn hashes() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(client_hash(&"A".repeat(64)).is_some());
        assert!(client_hash(UNSIGNED_PAYLOAD).is_none());
        assert!(client_hash("STREAMING-AWS4-HMAC-SHA256-PAYLOAD").is_none());
        assert!(client_hash(&"g".repeat(64)).is_none());
    }

    /// AWS's published example (S3 SigV4 docs, "GET Object" with a Range header).
    #[test]
    fn signs_like_aws() {
        let identity: Identity = Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            None,
            "test",
        )
        .into();
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region("us-east-1")
            .name("s3")
            .time(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1369353600))
            .settings(settings)
            .build()
            .unwrap()
            .into();
        let req = SignableRequest::new(
            "GET",
            "https://examplebucket.s3.amazonaws.com/test.txt",
            [("range", "bytes=0-9")].into_iter(),
            SignableBody::Precomputed(sha256_hex(b"")),
        )
        .unwrap();
        let (ins, _) = sign(req, &params).unwrap().into_parts();
        let auth = ins
            .headers()
            .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .unwrap()
            .1
            .to_string();
        assert!(
            auth.ends_with(
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            ),
            "{auth}"
        );
    }
}
