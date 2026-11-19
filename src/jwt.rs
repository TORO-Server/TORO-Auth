//! JWT (HS256)。署名の鍵は、トークンの種類ごとに別の値 (`Keys`)
//!
//! 1 つの鍵が漏れても、他の種類のトークンは偽造できない。種類 A の鍵で署名したトークンは、種類 B の確認では通らない。

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;

pub type Claims = Map<String, Value>;

/// トークンの種類。種類ごとに署名の鍵が違う
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Discord ログインの state
    LoginState,
    /// ブラウザのセッションと、API 用の短い期限のトークン (`api_session`)
    Session,
    /// 90 日トークン (AI コネクタ用)
    Connector,
    /// OAuth の同意 (承認のリンクに入れる)
    Consent,
    /// OAuth の認可コード
    Code,
    /// OAuth のアクセストークン
    Access,
    /// OAuth のリフレッシュトークン
    Refresh,
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Kind::LoginState,
        Kind::Session,
        Kind::Connector,
        Kind::Consent,
        Kind::Code,
        Kind::Access,
        Kind::Refresh,
    ];

    /// 鍵を渡す環境変数の名前
    pub fn env_name(self) -> &'static str {
        match self {
            Kind::LoginState => "JWT_SECRET_STATE",
            Kind::Session => "JWT_SECRET_SESSION",
            Kind::Connector => "JWT_SECRET_CONNECTOR",
            Kind::Consent => "JWT_SECRET_CONSENT",
            Kind::Code => "JWT_SECRET_CODE",
            Kind::Access => "JWT_SECRET_ACCESS",
            Kind::Refresh => "JWT_SECRET_REFRESH",
        }
    }
}

/// 鍵の最小の長さ (バイト)
pub const MIN_KEY_BYTES: usize = 32;

/// 種類ごとの署名の鍵
#[derive(Clone)]
pub struct Keys {
    values: [String; 7],
}

impl Keys {
    /// 7 つの鍵。どれも `MIN_KEY_BYTES` 以上で、互いに違う値でなければならない
    /// (同じ値を使い回すと、分けた意味が無くなる)
    pub fn new(values: [String; 7]) -> Result<Self, String> {
        for (kind, value) in Kind::ALL.iter().zip(&values) {
            if value.len() < MIN_KEY_BYTES {
                return Err(format!(
                    "{} must be at least {MIN_KEY_BYTES} bytes",
                    kind.env_name()
                ));
            }
        }
        for (i, a) in values.iter().enumerate() {
            for (j, b) in values.iter().enumerate().skip(i + 1) {
                if a == b {
                    return Err(format!(
                        "{} and {} must be different values",
                        Kind::ALL[i].env_name(),
                        Kind::ALL[j].env_name()
                    ));
                }
            }
        }
        Ok(Self { values })
    }

    pub fn get(&self, kind: Kind) -> &str {
        &self.values[Kind::ALL
            .iter()
            .position(|k| *k == kind)
            .expect("known kind")]
    }

    /// テスト用: 1 つの値から、種類ごとに違う鍵を作る
    pub fn derived_for_tests(base: &str) -> Self {
        let values = Kind::ALL.map(|kind| format!("{base}-{}", kind.env_name()));
        Self::new(values).expect("derived keys are distinct")
    }
}

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

/// 署名と有効期限を確かめ、中身を返す。発行するトークンには必ず期限を入れるので、期限の無いものは通さない
pub fn verify(token: &str, secret: &str) -> Option<Claims> {
    check(token, secret).ok()
}

/// 確かめて通らなかった理由 (ログの区分に使う。トークンの中身は持たない)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// 3 つの部分に分かれない、または読めない
    Malformed,
    /// この鍵での署名と合わない
    BadSignature,
    /// 署名は合うが、ヘッダーが想定と違う、または期限 (数値の exp) が無い
    Unusable,
    /// 署名は合うが、期限 (exp、UNIX 秒) を過ぎている
    Expired(i64),
}

/// `verify` と同じ確かめ方で、通らなかった理由も返す
pub fn check(token: &str, secret: &str) -> Result<Claims, Reject> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Reject::Malformed);
    };
    if parts.next().is_some() {
        return Err(Reject::Malformed);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| Reject::Malformed)?;

    let mut mac = mac(secret);
    mac.update(header.as_bytes());
    mac.update(b".");
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| Reject::BadSignature)?;

    let header: Value = URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(Reject::Unusable)?;
    if header != json!({"alg": "HS256", "typ": "JWT"}) {
        return Err(Reject::Unusable);
    }

    let claims: Value = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(Reject::Unusable)?;
    let claims = claims.as_object().ok_or(Reject::Unusable)?.clone();
    let exp = claims
        .get("exp")
        .and_then(Value::as_f64)
        .ok_or(Reject::Unusable)?;
    if (now() as f64) > exp {
        return Err(Reject::Expired(exp as i64));
    }
    Ok(claims)
}

/// 署名を確かめずに、本文から期限 (exp) と種類の見当だけを読む。
/// 署名が合わなかったトークンの、ログ用の手がかり (偽造されうる値なので、判断には使わない)
pub fn peek(token: &str) -> (Option<&'static str>, Option<i64>) {
    let claims: Option<Value> = token
        .split('.')
        .nth(1)
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let Some(claims) = claims.as_ref().and_then(Value::as_object) else {
        return (None, None);
    };
    let exp = claims
        .get("exp")
        .and_then(Value::as_f64)
        .map(|exp| exp as i64);
    (kind_hint(claims), exp)
}

/// 本文の type / purpose / sgen から見た、トークンの種類 (access / refresh / connector / session)。分からなければ None
pub fn kind_hint(claims: &Claims) -> Option<&'static str> {
    match (
        claims.get("type").and_then(Value::as_str),
        claims.get("purpose").and_then(Value::as_str),
    ) {
        (Some("mcp_access_token"), _) => Some("access"),
        (Some("mcp_refresh_token"), _) => Some("refresh"),
        (Some(_), _) => None,
        (None, Some("ai_connector")) => Some("connector"),
        (None, _) if claims.contains_key("sgen") => Some("session"),
        _ => None,
    }
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
        // RFC 7519 の形式の、広く知られた例 (jwt.io) に期限を足し、別の実装 (.NET の HMACSHA256) で署名したもの
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjQxMDI0NDQ4MDB9.2rJa0xN9x5QZQTvUhAcOtrF5qH6iGAmgFeTThC4mq8o";
        assert_eq!(
            verify(token, "your-256-bit-secret").unwrap()["name"],
            "John Doe"
        );
    }

    #[test]
    fn rejects_tokens_without_a_numeric_expiry() {
        assert!(verify(&sign(&json!({"id": "1"}), SECRET), SECRET).is_none());
        assert!(verify(&sign(&json!({"id": "1", "exp": "never"}), SECRET), SECRET).is_none());
        assert!(verify(&sign(&json!({"id": "1", "exp": null}), SECRET), SECRET).is_none());
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
    fn a_token_signed_for_one_kind_does_not_verify_as_another() {
        let keys = Keys::derived_for_tests("base-secret-base-secret-base-secret");
        for signer in Kind::ALL {
            let token = sign(&json!({"id": "1", "exp": now() + 60}), keys.get(signer));
            for verifier in Kind::ALL {
                assert_eq!(
                    verify(&token, keys.get(verifier)).is_some(),
                    signer == verifier,
                    "signed as {signer:?}, verified as {verifier:?}"
                );
            }
        }
    }

    #[test]
    fn keys_must_be_long_and_distinct() {
        let long = |c: char| c.to_string().repeat(MIN_KEY_BYTES);
        let distinct: [String; 7] = ['a', 'b', 'c', 'd', 'e', 'f', 'g'].map(long);
        assert!(Keys::new(distinct.clone()).is_ok());

        let mut short = distinct.clone();
        short[3] = "short".into();
        assert!(
            Keys::new(short)
                .err()
                .unwrap()
                .contains("JWT_SECRET_CONSENT")
        );

        let mut repeated = distinct;
        repeated[5] = repeated[1].clone();
        let error = Keys::new(repeated).err().unwrap();
        assert!(error.contains("JWT_SECRET_SESSION") && error.contains("JWT_SECRET_ACCESS"));
    }

    #[test]
    fn rejects_other_algorithms() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"id":"1"}"#);
        assert!(verify(&format!("{header}.{payload}."), SECRET).is_none());
    }
}
