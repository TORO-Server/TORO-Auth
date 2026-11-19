//! 認証の拒否の理由を、秘密を含めずに 1 行の JSON で標準エラーへ出す
//!
//! 出す項目は、時刻 (ts)、要求の種別 (request)、理由の区分 (reason)、トークンの種別 (token_kind。判別できるとき)、
//! トークンの期限 (token_exp。読めたとき) だけ。トークン本体、鍵、共有秘密、IP アドレスは出さない。
//!
//! reason: `signature_mismatch` / `expired` / `revoked` / `shared_secret_mismatch` / `other`、
//! と、拒否ではないが移行期間の旧鍵で通したことを示す `legacy_key_accepted`。
//! `signature_mismatch` の token_kind / token_exp は、署名を確かめられないトークンの本文から読んだ手がかり
//! (期限の前なのに署名が合わないのは、鍵が変わった印になる)。

use std::sync::Mutex;

use serde_json::{Map, Value, json};

use crate::auth::account::iso8601;
use crate::jwt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    SignatureMismatch,
    Expired,
    Revoked,
    SharedSecretMismatch,
    Other,
    /// 拒否ではない: 移行期間の旧鍵で署名を確かめて通した
    LegacyKeyAccepted,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::SignatureMismatch => "signature_mismatch",
            Reason::Expired => "expired",
            Reason::Revoked => "revoked",
            Reason::SharedSecretMismatch => "shared_secret_mismatch",
            Reason::Other => "other",
            Reason::LegacyKeyAccepted => "legacy_key_accepted",
        }
    }
}

/// 試験で出力を読むための控え。`capture` を呼んだときだけ貯める (本番は呼ばない)
static CAPTURED: Mutex<Option<Vec<String>>> = Mutex::new(None);

/// 試験用: 以降の出力を貯め始める (貯めたものは捨てる)
pub fn capture() {
    *CAPTURED.lock().unwrap_or_else(|e| e.into_inner()) = Some(Vec::new());
}

/// 試験用: 貯めた行を取り出して空にする
pub fn take_captured() -> Vec<String> {
    CAPTURED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .map(std::mem::take)
        .unwrap_or_default()
}

/// 1 行を作る。トークンの種別と期限は、分かるときだけ入れる
pub fn line(
    request: &str,
    reason: Reason,
    token_kind: Option<&str>,
    token_exp: Option<i64>,
) -> String {
    let mut entry = Map::new();
    entry.insert("ts".into(), json!(iso8601(jwt::now())));
    entry.insert("request".into(), json!(request));
    entry.insert("reason".into(), json!(reason.as_str()));
    if let Some(kind) = token_kind {
        entry.insert("token_kind".into(), json!(kind));
    }
    if let Some(exp) = token_exp {
        entry.insert("token_exp".into(), json!(iso8601(exp)));
    }
    Value::Object(entry).to_string()
}

pub fn emit(request: &str, reason: Reason, token_kind: Option<&str>, token_exp: Option<i64>) {
    let line = line(request, reason, token_kind, token_exp);
    eprintln!("{line}");
    if let Some(captured) = CAPTURED.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        captured.push(line);
    }
}
