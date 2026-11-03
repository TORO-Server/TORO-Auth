//! Discord へのログインとコールバック

use axum::http::header;
use axum::response::Response;
use serde_json::{Value, json};
use url::Url;

use super::{discord, session};
use crate::App;
use crate::http::{self, Ctx};
use crate::jwt;
use crate::template::render;
use crate::util::{encode_uri_component, is_loopback_host, is_toro_host, random_hex};

const DEFAULT_RETURN: &str = "https://wiki.torosaba.net/";
const DISCORD_AUTHORIZE: &str = "https://discord.com/oauth2/authorize";
const SCOPES: &str = "identify guilds guilds.members.read";
const STATE_TYPE: &str = "login_state";
const STATE_LIFETIME: i64 = 600;
const SESSION_LIFETIME: i64 = 30 * 86400;
/// ログインを始めたブラウザと、戻ってきたブラウザが同じかを確かめる Cookie
const NONCE_COOKIE: &str = "toro_login_nonce";

/// ログイン後に戻してよい先だけを通す
pub fn safe_return_url(target: &str) -> Option<String> {
    let url = Url::parse(target).ok()?;
    let host = url.host_str()?;
    let allowed = match url.scheme() {
        "https" => is_toro_host(host) || is_loopback_host(host),
        "http" => is_loopback_host(host),
        _ => false,
    };
    allowed.then(|| url.to_string())
}

fn nonce_cookie(value: &str, max_age: i64) -> String {
    format!(
        "{NONCE_COOKIE}={value}; Path=/api/auth/callback; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}"
    )
}

pub fn start(app: &App, ctx: &Ctx) -> Response {
    let cfg = &app.cfg;
    let target = ctx
        .q("redirect")
        .and_then(safe_return_url)
        .unwrap_or_else(|| DEFAULT_RETURN.to_string());
    let nonce = random_hex(16);
    let state = jwt::sign(
        &json!({ "type": STATE_TYPE, "redirect": target, "nonce": nonce, "exp": jwt::now() + STATE_LIFETIME }),
        &cfg.jwt_secret,
    );
    let location = format!(
        "{DISCORD_AUTHORIZE}?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}",
        encode_uri_component(&cfg.discord_client_id),
        encode_uri_component(&cfg.discord_redirect_uri),
        encode_uri_component(SCOPES),
        encode_uri_component(&state),
    );
    let mut res = http::redirect(&location);
    http::append_cookies(&mut res, &[nonce_cookie(&nonce, STATE_LIFETIME)]);
    res
}

/// state を確かめて、戻り先を返す
fn verify_state(app: &App, ctx: &Ctx) -> Option<String> {
    let claims = jwt::verify(ctx.q("state")?, &app.cfg.jwt_secret)?;
    if claims.get("type").and_then(Value::as_str) != Some(STATE_TYPE) {
        return None;
    }
    let nonce = session::cookie(ctx.header(header::COOKIE), NONCE_COOKIE)?;
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce.as_str()) {
        return None;
    }
    claims
        .get("redirect")
        .and_then(Value::as_str)
        .and_then(safe_return_url)
}

pub async fn callback(app: &App, ctx: &Ctx) -> Result<Response, String> {
    let Some(return_to) = verify_state(app, ctx) else {
        return Ok(http::error(
            ctx,
            "Login session expired or invalid. Please try logging in again.",
            400,
        ));
    };
    let Some(code) = ctx.q("code") else {
        return Ok(http::error(
            ctx,
            "Missing authorization code from Discord",
            400,
        ));
    };

    let access_token = match discord::exchange_code(app, code).await? {
        Ok(token) => token,
        Err(detail) => {
            return Ok(http::error(
                ctx,
                &format!("Failed to exchange Discord code: {detail}"),
                400,
            ));
        }
    };
    let Some(user) = discord::fetch_user(app, &access_token).await else {
        return Ok(http::error(
            ctx,
            "Failed to fetch Discord user profile",
            400,
        ));
    };

    let membership = discord::membership(app, &user.id, &access_token).await;
    if !membership.is_member {
        let page = render(
            include_str!("../../assets/auth/not_member.html"),
            &[("RETURN_URL", &return_to)],
        );
        return Ok(http::html(page, 403));
    }
    let can_edit = match &app.cfg.discord_required_role_id {
        Some(role) => membership.roles.contains(role),
        None => true,
    };

    let now = jwt::now();
    let token = jwt::sign(
        &json!({
            "id": user.id,
            "username": user.username,
            "global_name": user.global_name,
            "avatar": user.avatar,
            "avatar_url": user.avatar_url(),
            "can_edit": can_edit,
            "roles": membership.roles,
            "iat": now,
            "exp": now + SESSION_LIFETIME,
        }),
        &app.cfg.jwt_secret,
    );

    let mut res = http::redirect(&return_to);
    let mut cookies = session::session_cookies(&app.cfg, &token);
    cookies.push(nonce_cookie("", 0));
    http::append_cookies(&mut res, &cookies);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_url_must_be_ours_and_web() {
        assert!(safe_return_url("https://wiki.torosaba.net/a?b=1").is_some());
        assert!(safe_return_url("http://localhost:4200/").is_some());
        assert_eq!(safe_return_url("https://evil.example/"), None);
        assert_eq!(safe_return_url("http://wiki.torosaba.net/"), None);
        assert_eq!(
            safe_return_url("javascript://torosaba.net/%0aalert(1)"),
            None
        );
        assert_eq!(safe_return_url("https://torosaba.net.evil.example/"), None);
    }
}
