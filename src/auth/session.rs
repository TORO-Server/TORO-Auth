//! セッションの取り出しと Cookie
//!
//! セッション Cookie は auth.torosaba.net だけのもの (`__Host-` で Domain を付けられなくしてある)。
//! 他のサブドメインのサーバーには渡らず、他のサブドメインから差し替えることもできない。
//!
//! どこから取り出すかは、用途で使い分ける:
//! - `from_bearer`: Bearer を付けて auth を呼ぶクライアント (api / mcp は `internal` で確かめる)
//! - `from_cookie`: ブラウザでの読み取りと、同意の画面
//! - `from_cookie_for_write`: ブラウザでの変更 (Origin を確かめる。CSRF 対策)
//! - `from_cookie_on_own_page`: auth 自身の画面からだけの変更 (90 日トークン)
//! - `from_request`: 自分の情報の確認のように、どちらも受け付けるもの
//!
//! トークンの種類の確認は `decode_access_token` の 1 か所で行う。

use axum::http::header;
use serde_json::{Map, Value};

use crate::App;
use crate::http::Ctx;
use crate::jwt::{self, Claims, Kind};
use crate::util::encode_uri_component;

/// OAuth で発行するアクセストークンの type。
/// ブラウザのセッションと 90 日トークンには type が無い
pub const ACCESS_TOKEN_TYPE: &str = "mcp_access_token";
/// API 用の短い期限のトークンの purpose (ブラウザのセッションから `/session-token` で出す)
pub const API_SESSION_PURPOSE: &str = "api_session";
/// 90 日トークンの purpose。いまの世代のものだけが通る (`tokens`)
pub const CONNECTOR_PURPOSE: &str = "ai_connector";
/// 利用者のアイコンとして信じる置き場所
const AVATAR_ORIGIN: &str = "https://cdn.discordapp.com/";
const DEFAULT_AVATAR: &str = concat!("/_assets/favicon.svg?v=", env!("CARGO_PKG_VERSION"));

pub const SESSION_COOKIE: &str = "__Host-toro_session";
const SESSION_MAX_AGE: i64 = 30 * 86400;
const COOKIE_ATTRIBUTES: &str = "Path=/; HttpOnly; Secure; SameSite=Lax";

pub struct Session {
    pub claims: Map<String, Value>,
}

impl Session {
    pub fn id(&self) -> &str {
        self.str_claim("id")
    }

    pub fn username(&self) -> &str {
        self.str_claim("username")
    }

    pub fn display_name(&self) -> &str {
        match self.str_claim("global_name") {
            "" => self.username(),
            name => name,
        }
    }

    pub fn can_edit(&self) -> bool {
        self.claims
            .get("can_edit")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    /// Wiki を変更してよいか。OAuth のトークンは、許可された scope (write か mcp) の中だけ
    pub fn can_write(&self) -> bool {
        let scope_allows = match self.claims.get("scope").and_then(Value::as_str) {
            Some(scope) => scope_allows_write(scope),
            None => true,
        };
        self.can_edit() && scope_allows
    }

    /// ログインしたときのロールの ID
    pub fn role_ids(&self) -> Vec<&str> {
        self.claims
            .get("roles")
            .and_then(Value::as_array)
            .map(|roles| roles.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    pub fn avatar(&self) -> Option<&str> {
        self.claims.get("avatar").and_then(Value::as_str)
    }

    /// Discord のアイコンの URL。無ければ TORO のアイコン
    pub fn avatar_url(&self) -> &str {
        self.claims
            .get("avatar_url")
            .and_then(Value::as_str)
            .filter(|url| url.starts_with(AVATAR_ORIGIN))
            .unwrap_or(DEFAULT_AVATAR)
    }

    fn str_claim(&self, name: &str) -> &str {
        self.claims.get(name).and_then(Value::as_str).unwrap_or("")
    }
}

/// scope が Wiki の変更を許しているか
pub fn scope_allows_write(scope: &str) -> bool {
    scope.split_whitespace().any(|s| s == "write" || s == "mcp")
}

/// scope が mcp の管理用のツールまで許しているか (実際に使えるのは Admin 以上のロールの人だけ)
pub fn scope_allows_admin_tools(scope: &str) -> bool {
    scope.split_whitespace().any(|s| s == "mcp")
}

/// 利用者の権限を表すトークンだけを通す。
/// 署名の鍵は種類ごとに違う。どの鍵で通ったかで種類が決まり、その種類に合う中身 (type / purpose) だけを受ける。
/// 認可コードやリフレッシュトークン、同意、ログインの state は、ここでは通らない (それぞれ別の鍵)。
pub fn decode_access_token(app: &App, token: &str) -> Option<Claims> {
    let keys = &app.cfg.jwt_keys;
    if let Some(claims) = jwt::verify(token, keys.get(Kind::Session)) {
        // ブラウザのセッション (type も purpose も無い) と、API 用の短いトークン (purpose = api_session)
        let purpose = claims.get("purpose").and_then(Value::as_str);
        let plain =
            !claims.contains_key("type") && matches!(purpose, None | Some(API_SESSION_PURPOSE));
        return (plain && session_is_current(app, &claims)).then_some(claims);
    }
    if let Some(claims) = jwt::verify(token, keys.get(Kind::Connector)) {
        let is_connector = !claims.contains_key("type")
            && claims.get("purpose").and_then(Value::as_str) == Some(CONNECTOR_PURPOSE);
        return (is_connector && is_current_connector_token(app, &claims)).then_some(claims);
    }
    if let Some(claims) = jwt::verify(token, keys.get(Kind::Access)) {
        let is_access = claims.get("type").and_then(Value::as_str) == Some(ACCESS_TOKEN_TYPE)
            && !claims.contains_key("purpose");
        return (is_access && grant_is_active(app, &claims)).then_some(claims);
    }
    None
}

/// ブラウザのセッションと API 用のトークンは、発行したときの世代 (`sgen`) がいまの世代のときだけ通す。
/// `/logout` が世代を進めるので、ログアウトしたセッションは (Cookie を残していても) 通らない。世代の無いものは通さない
fn session_is_current(app: &App, claims: &Claims) -> bool {
    let id = claims.get("id").and_then(Value::as_str);
    let generation = claims.get("sgen").and_then(Value::as_u64);
    match (id, generation) {
        (Some(id), Some(generation)) => app.sessions.current(id) == generation,
        _ => false,
    }
}

/// OAuth のアクセストークンは、連携 (`gid`) がまだ有効なときだけ通す。通ったら、最後に使った時刻を更新する (使っている間は続く)。
/// 使わないまま `OAUTH_IDLE_DAYS` を過ぎた連携は、ここで断る。`gid` の無いトークンも通さない
fn grant_is_active(app: &App, claims: &Claims) -> bool {
    let Some(gid) = claims.get("gid").and_then(Value::as_str) else {
        return false;
    };
    let Some(user) = claims.get("id").and_then(Value::as_str) else {
        return false;
    };
    app.grants
        .touch(gid, user, app.cfg.oauth_idle_seconds, jwt::now())
}

/// 再作成で置き換えられたトークンと、世代を持たない昔のトークンは通さない
fn is_current_connector_token(app: &App, claims: &Claims) -> bool {
    let id = claims.get("id").and_then(Value::as_str);
    let generation = claims.get("generation").and_then(Value::as_str);
    match (id, generation) {
        (Some(id), Some(generation)) => app.tokens.is_current(id, generation),
        _ => false,
    }
}

/// 通るトークンの持ち主。api / mcp からの確認 (`internal`) もここを通る
pub fn from_token(app: &App, token: &str) -> Option<Session> {
    let claims = decode_access_token(app, token)?;
    claims.get("id").and_then(Value::as_str)?;
    Some(Session { claims })
}

pub fn bearer_token(ctx: &Ctx) -> Option<&str> {
    ctx.header(header::AUTHORIZATION)
        .strip_prefix("Bearer ")
        .map(str::trim)
}

pub fn from_bearer(app: &App, ctx: &Ctx) -> Option<Session> {
    bearer_token(ctx).and_then(|token| from_token(app, token))
}

/// ブラウザのセッション。API 用のトークンを Cookie に入れても通さない
pub fn from_cookie(app: &App, ctx: &Ctx) -> Option<Session> {
    let token = cookie(ctx.header(header::COOKIE), SESSION_COOKIE)?;
    let session = from_token(app, &token)?;
    let is_browser_session =
        !session.claims.contains_key("type") && !session.claims.contains_key("purpose");
    is_browser_session.then_some(session)
}

/// ブラウザからの変更。Cookie は他のサブドメインからのリクエストにも付くので、送り元を確かめる
pub fn from_cookie_for_write(app: &App, ctx: &Ctx) -> Option<Session> {
    if !ctx.origin_trusted {
        return None;
    }
    from_cookie(app, ctx)
}

/// auth 自身の画面からの変更。長く使えるトークンは、Wiki の画面からも作らせない
pub fn from_cookie_on_own_page(app: &App, ctx: &Ctx) -> Option<Session> {
    if ctx.header(header::ORIGIN) != app.cfg.issuer {
        return None;
    }
    from_cookie(app, ctx)
}

/// 読み取り: Authorization: Bearer、次に Cookie
pub fn from_request(app: &App, ctx: &Ctx) -> Option<Session> {
    from_bearer(app, ctx).or_else(|| from_cookie(app, ctx))
}

pub fn cookie(header_value: &str, name: &str) -> Option<String> {
    header_value.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name)
            .then(|| percent_decode(value))
            .filter(|v| !v.is_empty())
    })
}

fn percent_decode(value: &str) -> String {
    let mut bytes = Vec::with_capacity(value.len());
    let mut chars = value.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(h1), Some(h2)) = (h1, h2) {
                let hex_val = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                };
                if let (Some(d1), Some(d2)) = (hex_val(h1), hex_val(h2)) {
                    bytes.push((d1 << 4) | d2);
                    continue;
                }
                bytes.push(b'%');
                bytes.push(h1);
                bytes.push(h2);
            } else {
                bytes.push(b'%');
                if let Some(h1) = h1 {
                    bytes.push(h1);
                }
            }
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 30 日のセッション Cookie
pub fn session_cookies(token: &str) -> Vec<String> {
    let token = encode_uri_component(token);
    vec![format!(
        "{SESSION_COOKIE}={token}; {COOKIE_ATTRIBUTES}; Max-Age={SESSION_MAX_AGE}"
    )]
}

pub fn logout_cookies() -> Vec<String> {
    vec![format!("{SESSION_COOKIE}=; {COOKIE_ATTRIBUTES}; Max-Age=0")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_cookie_by_exact_name() {
        let header = "a=1; toro_session=abc.def-_; other=x%3Dy; with_amp=foo%26bar";
        assert_eq!(cookie(header, "toro_session").as_deref(), Some("abc.def-_"));
        assert_eq!(cookie(header, "other").as_deref(), Some("x=y"));
        assert_eq!(cookie(header, "with_amp").as_deref(), Some("foo&bar"));
        assert_eq!(cookie(header, "session"), None);
        assert_eq!(cookie("toro_session=", "toro_session"), None);
    }

    #[test]
    fn write_needs_edit_permission_and_scope() {
        let session = |claims: Value| Session {
            claims: claims.as_object().unwrap().clone(),
        };
        use serde_json::json;
        assert!(session(json!({ "can_edit": true })).can_write());
        assert!(session(json!({ "can_edit": true, "scope": "read write" })).can_write());
        assert!(session(json!({ "can_edit": true, "scope": "mcp" })).can_write());
        assert!(!session(json!({ "can_edit": true, "scope": "read" })).can_write());
        assert!(!session(json!({ "can_edit": false, "scope": "write" })).can_write());
    }
}
