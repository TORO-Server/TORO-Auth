//! セッションの取り出しと Cookie

use axum::http::header;
use serde_json::{Map, Value};

use crate::App;
use crate::config::Config;
use crate::http::Ctx;
use crate::jwt::{self, Claims};
use crate::util::encode_uri_component;

/// OAuth で発行するアクセストークンの type。
/// ブラウザのセッションと 90 日トークンには type が無い
pub const ACCESS_TOKEN_TYPE: &str = "mcp_access_token";

const COOKIE_NAMES: [&str; 2] = ["toro_session", "wiki_session"];

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

    pub fn role_count(&self) -> usize {
        self.claims
            .get("roles")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    }

    pub fn avatar(&self) -> Option<&str> {
        self.claims.get("avatar").and_then(Value::as_str)
    }

    fn str_claim(&self, name: &str) -> &str {
        self.claims.get(name).and_then(Value::as_str).unwrap_or("")
    }
}

/// 利用者の権限を表すトークンだけを通す。
/// 同じ鍵で署名した認可コードやリフレッシュトークンを、アクセストークンとして使わせない
pub fn decode_access_token(app: &App, token: &str) -> Option<Claims> {
    let claims = jwt::verify(token, &app.cfg.jwt_secret)?;
    match claims.get("type") {
        None => Some(claims),
        Some(kind) if kind == ACCESS_TOKEN_TYPE => Some(claims),
        Some(_) => None,
    }
}

fn session_from_token(app: &App, token: &str) -> Option<Session> {
    let claims = decode_access_token(app, token)?;
    claims.get("id").and_then(Value::as_str)?;
    Some(Session { claims })
}

pub fn bearer_token(ctx: &Ctx) -> Option<&str> {
    ctx.header(header::AUTHORIZATION)
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// Authorization: Bearer、次に Cookie の順に調べる
pub fn from_request(app: &App, ctx: &Ctx) -> Option<Session> {
    if let Some(session) = bearer_token(ctx).and_then(|t| session_from_token(app, t)) {
        return Some(session);
    }
    let cookies = ctx.header(header::COOKIE);
    let token = COOKIE_NAMES.iter().find_map(|name| cookie(cookies, name))?;
    session_from_token(app, &token)
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
    url::form_urlencoded::parse(value.replace('+', "%2B").as_bytes())
        .next()
        .map(|(k, v)| {
            if v.is_empty() {
                k.into_owned()
            } else {
                format!("{k}={v}")
            }
        })
        .unwrap_or_default()
}

fn domain_part(cfg: &Config) -> String {
    match cfg.cookie_domain.as_str() {
        "" => String::new(),
        domain => format!("; Domain={domain}"),
    }
}

/// 30 日のセッション Cookie
pub fn session_cookies(cfg: &Config, token: &str) -> Vec<String> {
    let token = encode_uri_component(token);
    COOKIE_NAMES
        .iter()
        .map(|name| {
            format!(
                "{name}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000{}",
                domain_part(cfg)
            )
        })
        .collect()
}

pub fn logout_cookies(cfg: &Config) -> Vec<String> {
    COOKIE_NAMES
        .iter()
        .map(|name| {
            format!(
                "{name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0{}",
                domain_part(cfg)
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_cookie_by_exact_name() {
        let header = "a=1; toro_session=abc.def-_; other=x%3Dy";
        assert_eq!(cookie(header, "toro_session").as_deref(), Some("abc.def-_"));
        assert_eq!(cookie(header, "other").as_deref(), Some("x=y"));
        assert_eq!(cookie(header, "session"), None);
        assert_eq!(cookie("toro_session=", "toro_session"), None);
    }
}
