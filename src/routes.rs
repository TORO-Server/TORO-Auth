//! URL から各機能への振り分け。auth は 1 つの役割だけを受け持つので、ホストでは分けない

use std::sync::Arc;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::Method;
use axum::http::header::{self, HeaderValue};
use axum::response::Response;
use serde_json::json;

use crate::config::Config;
use crate::http::{self, Ctx};
use crate::{App, auth, home, oauth, static_files};

const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

pub fn router(app: Arc<App>) -> Router {
    Router::new().fallback(dispatch).with_state(app)
}

async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    // 同時に処理する数を限り、ボディの分も含めてメモリの使用量に上限を設ける
    let Ok(_permit) = app.requests.try_acquire() else {
        return http::busy();
    };

    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            let ctx = Ctx::new(&parts, Default::default(), &app.cfg);
            return http::json(&ctx, &json!({ "error": "Payload Too Large" }), 413);
        }
    };
    let ctx = Ctx::new(&parts, body, &app.cfg);

    let mut res = match route(&app, &ctx).await {
        Ok(res) => res,
        Err(message) => {
            eprintln!("{} {}: {message}", ctx.method, ctx.path);
            http::json(
                &ctx,
                &json!({ "error": "Internal Server Error", "message": message }),
                500,
            )
        }
    };
    let headers = res.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // 利用者ごとに違う応答を Cloudflare にためさせない。ためてよいものは、自分で Cache-Control を付ける
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    res
}

async fn route(app: &App, ctx: &Ctx) -> Result<Response, String> {
    if ctx.method == Method::OPTIONS {
        return Ok(http::no_content(http::cors_headers(ctx)));
    }

    let path = ctx.path.as_str();

    if path == "/healthz" {
        return Ok(http::json(ctx, &json!({ "ok": true }), 200));
    }
    if let Some(res) = static_files::serve(path) {
        return Ok(res);
    }

    route_auth(app, ctx).await
}

fn not_found(ctx: &Ctx) -> Response {
    http::json(ctx, &json!({ "error": "Not Found", "path": ctx.path }), 404)
}

/// auth: だれなのかを確かめる
async fn route_auth(app: &App, ctx: &Ctx) -> Result<Response, String> {
    let cfg = &app.cfg;
    let path = ctx.path.as_str();
    if let Some(moved) = moved_from_auth(cfg, path) {
        return Ok(http::moved(ctx, &moved));
    }
    match path {
        "/" | "/index.html" => Ok(home::handle(app, ctx).await),

        "/api/auth/login" => Ok(auth::login::start(app, ctx)),
        "/api/auth/callback" => auth::login::callback(app, ctx).await,
        "/api/auth/me" => Ok(auth::account::me(app, ctx)),
        "/api/auth/logout" => Ok(auth::account::logout(ctx)),
        "/api/auth/token" => Ok(auth::account::issue_token(app, ctx)),
        "/api/auth/session-token" => Ok(auth::account::issue_session_token(app, ctx)),

        "/.well-known/oauth-authorization-server" | "/.well-known/openid-configuration" => {
            Ok(oauth::metadata::authorization_server(app, ctx))
        }
        "/oauth/register" => Ok(oauth::register::handle(ctx)),
        "/oauth/authorize" => Ok(oauth::authorize::handle(app, ctx)),
        "/oauth/token" => Ok(oauth::token::handle(app, ctx)),
        "/oauth/userinfo" | "/userinfo" => Ok(oauth::userinfo::handle(app, ctx)),

        _ => Ok(not_found(ctx)),
    }
}

/// 以前 auth にあった URL の移り先
fn moved_from_auth(cfg: &Config, path: &str) -> Option<String> {
    let (api, mcp) = (&cfg.api_url, &cfg.mcp_url);
    match path {
        "/api/mcp" => Some(format!("{mcp}/")),
        "/mcp" | "/sse" => Some(format!("{mcp}{path}")),
        "/api/docs/raw" => Some(format!("{api}/docs/raw")),
        "/api/docs/save" => Some(format!("{api}/docs/save")),
        "/api/openapi.json" | "/openapi.json" => Some(format!("{api}/openapi.json")),
        _ if path.starts_with("/.well-known/oauth-protected-resource") => {
            Some(format!("{mcp}{path}"))
        }
        _ => None,
    }
}
