//! api / mcp からのトークンの確認。内側のポート (`INTERNAL_PORT`) だけで受ける
//!
//! 署名の鍵 (`JWT_SECRET`) と 90 日トークンの世代の記録は auth だけが持つ。
//! api と mcp は、利用者の Bearer トークンをここへ渡して、いま通るものか、持ち主はだれかを尋ねる (RFC 7662 に倣った形)。
//! このポートは Cloudflare のトンネルにも、ホストにも公開しない。Docker の内側のネットワークだけで届く。
//! 渡されたトークンの中身を返すだけなので、トークンを持たない者には何も渡らない。

use std::sync::Arc;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::Method;
use axum::http::header::{self, HeaderValue};
use axum::response::Response;
use serde_json::{Value, json};

use crate::App;
use crate::auth::discord::{self, LiveRoles};
use crate::auth::session;
use crate::http;

/// トークン 1 本とその枠だけが入る大きさ
const MAX_BODY_BYTES: usize = 16 * 1024;

pub fn router(app: Arc<App>) -> Router {
    Router::new().fallback(dispatch).with_state(app)
}

async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let mut res = match (parts.method.clone(), parts.uri.path()) {
        (Method::GET, "/healthz") => reply(200, &json!({ "ok": true })),
        (Method::POST, "/introspect") => match to_bytes(body, MAX_BODY_BYTES).await {
            Ok(body) => introspect(&app, &body).await,
            Err(_) => reply(413, &json!({ "error": "Payload Too Large" })),
        },
        (_, "/introspect" | "/healthz") => reply(405, &json!({ "error": "Method Not Allowed" })),
        _ => reply(404, &json!({ "error": "Not Found" })),
    };
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn reply(status: u16, body: &Value) -> Response {
    http::respond(
        status,
        Default::default(),
        http::JSON_UTF8,
        body.to_string(),
    )
}

/// `{"token": "..."}` を受け、通るなら `{"active": true, "claims": {...}}`、通らないなら `{"active": false}`
///
/// `claims.roles` は、トークンに入っている値ではなく、**いまの Discord のロール**に差し替える (Bot トークンがあるとき)。
/// ロールは、トークンを発行した時点のものが入っていて、30〜90 日古くなる。OAuth のアクセストークンにはロールが入らない。
/// Admin かどうかなど、権限の判断に使う側 (mcp / guard) が、古いロールや空のロールで判断しないようにするため、ここで確かめる。
/// 確かめられないとき (Discord の障害) は、ロール無しとして返す (権限を、安全な側に倒す)。
/// `roles_source` が、どちらかを示す: `live` / `unavailable` / `token` (Bot トークンが無く、トークンの値のまま)
async fn introspect(app: &App, body: &[u8]) -> Response {
    let Some(token) = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|body| body.get("token")?.as_str().map(str::to_string))
    else {
        return reply(400, &json!({ "error": "Field \"token\" is required" }));
    };
    let Some(session) = session::from_token(app, &token) else {
        return reply(200, &json!({ "active": false }));
    };
    let user_id = session.id().to_string();
    let mut claims = session.claims;
    let source = match discord::live_roles(app, &user_id).await {
        LiveRoles::Live(roles) => {
            claims.insert("roles".into(), json!(roles));
            "live"
        }
        LiveRoles::Unavailable => {
            claims.insert("roles".into(), json!([]));
            "unavailable"
        }
        LiveRoles::NotConfigured => "token",
    };
    claims.insert("roles_source".into(), json!(source));
    reply(200, &json!({ "active": true, "claims": claims }))
}
