//! api.torosaba.net の入り口。Wiki の原稿は `wiki::api`、仕様書は `openapi` にある

use axum::response::Response;
use serde_json::json;

use crate::App;
use crate::auth::session;
use crate::http::{self, Ctx};

/// 各サービスの URL を返す。プログラムはハードコードせず、これを読む
pub fn index(app: &App, ctx: &Ctx) -> Response {
    let api = &app.cfg.api_url;
    http::pretty_json(
        http::cors_headers(ctx),
        &json!({
            "service": "TORO Server API",
            "services": app.cfg.services(),
            "documentation": app.cfg.roles_page(),
            "openapi": format!("{api}/openapi.json"),
        }),
        200,
    )
}

/// トークンの持ち主
pub fn me(app: &App, ctx: &Ctx) -> Response {
    let body = match session::from_bearer(app, ctx) {
        Some(session) => json!({
            "authenticated": true,
            "user": {
                "id": session.id(),
                "username": session.username(),
                "can_edit": session.can_edit(),
            },
        }),
        None => json!({ "authenticated": false, "user": null }),
    };
    http::json(ctx, &body, 200)
}
