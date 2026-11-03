//! OpenID Connect UserInfo (GET /oauth/userinfo)

use axum::response::Response;
use serde_json::{Value, json};

use crate::App;
use crate::auth::session;
use crate::http::{self, Ctx};

pub fn handle(app: &App, ctx: &Ctx) -> Response {
    let headers = http::cors_headers(ctx);
    let Some(token) = session::bearer_token(ctx) else {
        let body = json!({ "error": "unauthorized", "error_description": "Bearer token required" });
        return http::respond(401, headers, http::JSON_UTF8, body.to_string());
    };
    let claims = session::decode_access_token(app, token);
    let Some((claims, sub)) = claims.and_then(|c| {
        c.get("sub")
            .and_then(Value::as_str)
            .map(str::to_string)
            .map(|s| (c, s))
    }) else {
        let body =
            json!({ "error": "invalid_token", "error_description": "Invalid or expired token" });
        return http::respond(401, headers, http::JSON_UTF8, body.to_string());
    };

    let username = claims
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or("Discord User");
    let picture = match claims.get("avatar").and_then(Value::as_str) {
        Some(avatar) => format!("https://cdn.discordapp.com/avatars/{sub}/{avatar}.png"),
        None => "https://cdn.discordapp.com/embed/avatars/0.png".to_string(),
    };
    let data = json!({
        "sub": sub,
        "name": username,
        "preferred_username": username,
        "picture": picture,
        "email": format!("{sub}@discord.torosaba.net"),
        "email_verified": true,
    });
    http::pretty_json(headers, &data, 200)
}
