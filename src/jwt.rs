//! JWT (HS256)。Worker 版と同じ形式で、同じ秘密鍵なら相互に検証できる

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;

pub type Claims = Map<String, Value>;

const HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn mac(secret: &str) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length")
}

pub fn sign(claims: &Value, secret: &str) -> String {
    let data = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HEADER),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("JSON value serializes"))
    );
    let mut mac = mac(secret);
    mac.update(data.as_bytes());
    format!(
        "{data}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// 署名と有効期限を確かめ、中身を返す
pub fn verify(token: &str, secret: &str) -> Option<Claims> {
    let mut parts = token.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }

    let mut mac = mac(secret);
    mac.update(header.as_bytes());
    mac.update(b".");
    mac.update(payload.as_bytes());
    mac.verify_slice(&URL_SAFE_NO_PAD.decode(signature).ok()?)
        .ok()?;

    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if header != json!({"alg": "HS256", "typ": "JWT"}) {
        return None;
    }

    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    let claims = claims.as_object()?.clone();
    if let Some(exp) = claims.get("exp").and_then(Value::as_f64)
        && (now() as f64) > exp
    {
        return None;
    }
    Some(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";

    #[test]
    fn round_trip() {
        let token = sign(&json!({"id": "1", "exp": now() + 60}), SECRET);
        assert_eq!(verify(&token, SECRET).unwrap()["id"], "1");
    }

    #[test]
    fn verifies_tokens_from_other_implementations() {
        // RFC 7519 の形式の、広く知られた例 (jwt.io)
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert_eq!(
            verify(token, "your-256-bit-secret").unwrap()["name"],
            "John Doe"
        );
    }

    #[test]
    fn rejects_expired_tampered_and_wrong_key() {
        let expired = sign(&json!({"exp": now() - 1}), SECRET);
        assert!(verify(&expired, SECRET).is_none());

        let token = sign(&json!({"can_edit": false}), SECRET);
        assert!(verify(&token, "other").is_none());

        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(r#"{"can_edit":true}"#);
        parts[1] = &forged;
        assert!(verify(&parts.join("."), SECRET).is_none());
    }

    #[test]
    fn rejects_other_algorithms() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"id":"1"}"#);
        assert!(verify(&format!("{header}.{payload}."), SECRET).is_none());
    }
}
