//! HTTP Basic credentials (`auth.basic`): Azure DevOps and other servers that take a personal access token as the
//! password of `Authorization: Basic base64(user:token)`.

use zeroize::Zeroizing;

/// `Basic base64(<user>:<secret>)`, the whole header value. Both buffers are sized up front and zeroed on drop, so
/// no copy of the secret is left behind by a growing string.
pub fn credential(user: &str, secret: &str) -> Zeroizing<String> {
    let mut pair = Zeroizing::new(String::with_capacity(user.len() + 1 + secret.len()));
    pair.push_str(user);
    pair.push(':');
    pair.push_str(secret);
    let mut out = Zeroizing::new(String::with_capacity(
        PREFIX.len() + pair.len().div_ceil(3) * 4,
    ));
    out.push_str(PREFIX);
    crate::b2::base64_into(pair.as_bytes(), &mut out);
    out
}

/// What precedes the encoded pair in the header value.
pub const PREFIX: &str = "Basic ";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_what_curl_and_base64_send() {
        // curl -u ":tok" / echo -n ":tok" | base64
        assert_eq!(credential("", "tok").as_str(), "Basic OnRvaw==");
        assert_eq!(credential("u", "p").as_str(), "Basic dTpw");
        assert_eq!(
            credential("", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop").as_str(),
            "Basic OmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3A="
        );
    }

    #[test]
    fn sized_up_front() {
        for n in 0..20 {
            let s = "x".repeat(n);
            let c = credential("user", &s);
            assert_eq!(c.capacity(), c.len(), "secret of {n} bytes");
        }
    }
}
