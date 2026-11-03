//! どの機能からも使う小さな道具

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// 暗号論的に安全な乱数の 16 進表記
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::Rng::fill(&mut rand::rng(), buf.as_mut_slice());
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_base64url(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

/// JavaScript の encodeURIComponent と同じ
pub fn encode_uri_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 手元の開発環境のホスト名か
pub fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

/// torosaba.net とそのサブドメインか
pub fn is_toro_host(host: &str) -> bool {
    host == "torosaba.net" || host.ends_with(".torosaba.net")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_like_encode_uri_component() {
        assert_eq!(
            encode_uri_component("07_System/日本語 a&b.md"),
            "07_System%2F%E6%97%A5%E6%9C%AC%E8%AA%9E%20a%26b.md"
        );
        assert_eq!(
            encode_uri_component("a-b_c.d!e~f*g'h(i)"),
            "a-b_c.d!e~f*g'h(i)"
        );
    }

    #[test]
    fn host_checks_do_not_match_lookalikes() {
        assert!(is_toro_host("wiki.torosaba.net"));
        assert!(!is_toro_host("eviltorosaba.net"));
        assert!(!is_toro_host("torosaba.net.evil.example"));
    }

    #[test]
    fn random_hex_has_requested_length() {
        assert_eq!(random_hex(16).len(), 32);
        assert_ne!(random_hex(16), random_hex(16));
    }
}
