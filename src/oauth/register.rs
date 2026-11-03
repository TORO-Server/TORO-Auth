//! RFC 7591: 動的クライアント登録。登録内容は保存しない (認可時に送り先を画面に出して利用者に確かめてもらう)

use axum::response::Response;
use serde_json::{Value, json};

use crate::http::{self, Ctx};
use crate::util::random_hex;

pub fn handle(ctx: &Ctx) -> Response {
    // 空のボディでも受け付ける
    let body: Value = serde_json::from_slice(&ctx.body).unwrap_or(Value::Null);
    let client_name = match body.get("client_name") {
        Some(name) if !name.is_null() => name.clone(),
        _ => json!("AI Client"),
    };
    let redirect_uris = match body.get("redirect_uris") {
        Some(uris) if uris.is_array() => uris.clone(),
        _ => json!([]),
    };
    let data = json!({
        "client_id": format!("toro-ai-{}", random_hex(4)),
        "client_secret": format!("sec_{}", random_hex(16)),
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    http::json(ctx, &data, 201)
}
