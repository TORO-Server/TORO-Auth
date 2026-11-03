//! URL から各機能への振り分け

use std::sync::Arc;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::Method;
use axum::http::header::{self, HeaderValue};
use axum::response::Response;
use serde_json::json;

use crate::http::{self, Ctx};
use crate::{App, auth, home, mcp, oauth, openapi, static_files, wiki};

const MCP_HOST: &str = "mcp.torosaba.net";
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

    // 稼働確認と、案内画面の画像
    if path == "/healthz" {
        return Ok(http::json(ctx, &json!({ "ok": true }), 200));
    }
    if let Some(res) = static_files::serve(path) {
        return Ok(res);
    }

    // OAuth 2.0 / MCP の発見 (どのホストでも最優先)
    match path {
        "/.well-known/oauth-protected-resource" => {
            return Ok(oauth::metadata::protected_resource(app, ctx));
        }
        "/.well-known/oauth-authorization-server" | "/.well-known/openid-configuration" => {
            return Ok(oauth::metadata::authorization_server(app, ctx));
        }
        "/oauth/register" => return Ok(oauth::register::handle(ctx)),
        "/oauth/authorize" => return Ok(oauth::authorize::handle(app, ctx)),
        "/oauth/token" => return Ok(oauth::token::handle(app, ctx)),
        "/oauth/userinfo" | "/userinfo" => return Ok(oauth::userinfo::handle(app, ctx)),
        _ => {}
    }

    // mcp.torosaba.net は、残りをすべて MCP として扱う
    let is_mcp_path = path == "/api/mcp"
        || path.starts_with("/api/mcp/")
        || path == "/mcp"
        || path.starts_with("/mcp/")
        || path == "/sse";
    if ctx.host == MCP_HOST || is_mcp_path {
        return Ok(mcp::transport::handle(app, ctx).await);
    }

    match path {
        "/" | "/index.html" => Ok(home::handle(app, ctx)),

        "/api/auth/login" => Ok(auth::login::start(app, ctx)),
        "/api/auth/callback" => auth::login::callback(app, ctx).await,
        "/api/auth/me" => Ok(auth::account::me(app, ctx)),
        "/api/auth/logout" => Ok(auth::account::logout(ctx)),
        "/api/auth/token" => Ok(auth::account::issue_token(app, ctx)),

        "/api/docs/raw" => Ok(wiki::api::raw(app, ctx).await),
        "/api/docs/save" => Ok(wiki::api::save(app, ctx).await),

        "/api/openapi.json" | "/openapi.json" => Ok(openapi::handle(app, ctx)),

        _ => Ok(http::json(
            ctx,
            &json!({ "error": "Not Found", "path": path }),
            404,
        )),
    }
}
