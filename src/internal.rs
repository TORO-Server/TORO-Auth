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
            Ok(body) => introspect(&app, &body),
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
fn introspect(app: &App, body: &[u8]) -> Response {
    let Some(token) = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|body| body.get("token")?.as_str().map(str::to_string))
    else {
        return reply(400, &json!({ "error": "Field \"token\" is required" }));
    };
    match session::from_token(app, &token) {
        Some(session) => reply(200, &json!({ "active": true, "claims": session.claims })),
        None => reply(200, &json!({ "active": false })),
    }
}
