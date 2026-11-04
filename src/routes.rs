//! URL から各機能への振り分け。auth は 1 つの役割だけを受け持つので、ホストでは分けない

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::Method;
use axum::http::header::{self, HeaderValue};
use axum::response::Response;
use serde_json::json;

use crate::http::{self, Ctx};
use crate::{App, auth, home, oauth, static_files};

const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

pub fn router(app: Arc<App>) -> Router {
    Router::new().fallback(dispatch).with_state(app)
}

async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    let mut res = answer(&app, request).await;
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

async fn answer(app: &App, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    // 稼働確認は、同時処理の枠を使わない (混んでいるだけで、止まっていると見なされないように)
    if parts.uri.path() == "/healthz" {
        let ctx = Ctx::new(&parts, Default::default(), &app.cfg);
        return http::json(&ctx, &json!({ "ok": true }), 200);
    }
    // 同時に処理する数を限り、ボディの分も含めてメモリの使用量に上限を設ける
    let Ok(_permit) = app.requests.try_acquire() else {
        return http::busy();
    };

    let wait = Duration::from_secs(app.cfg.body_read_timeout_secs);
    let body = match tokio::time::timeout(wait, to_bytes(body, MAX_BODY_BYTES)).await {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            let ctx = Ctx::new(&parts, Default::default(), &app.cfg);
            return http::json(&ctx, &json!({ "error": "Payload Too Large" }), 413);
        }
        Err(_) => {
            let ctx = Ctx::new(&parts, Default::default(), &app.cfg);
            return http::json(&ctx, &json!({ "error": "Request Timeout" }), 408);
        }
    };
    let ctx = Ctx::new(&parts, body, &app.cfg);

    match route(app, &ctx).await {
        Ok(res) => res,
        // 中身はログにだけ残す (内側の事情を外に見せない)
        Err(message) => {
            eprintln!("{} {}: {message}", ctx.method, ctx.path);
            http::json(&ctx, &json!({ "error": "Internal Server Error" }), 500)
        }
    }
}

async fn route(app: &App, ctx: &Ctx) -> Result<Response, String> {
    if ctx.method == Method::OPTIONS {
        return Ok(http::no_content(http::cors_headers(ctx)));
    }

    let path = ctx.path.as_str();

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
    match ctx.path.as_str() {
        "/" => Ok(home::handle(app, ctx).await),

        "/login" => Ok(auth::login::start(app, ctx)),
        "/callback" => auth::login::callback(app, ctx).await,
        "/session" => Ok(auth::account::me(app, ctx)),
        "/logout" => Ok(auth::account::logout(ctx)),
        "/token" => Ok(auth::account::issue_token(app, ctx)),
        "/session-token" => Ok(auth::account::issue_session_token(app, ctx)),

        "/.well-known/oauth-authorization-server" | "/.well-known/openid-configuration" => {
            Ok(oauth::metadata::authorization_server(app, ctx))
        }
        "/oauth/register" => Ok(oauth::register::handle(ctx)),
        "/oauth/authorize" => Ok(oauth::authorize::handle(app, ctx)),
        "/oauth/token" => Ok(oauth::token::handle(app, ctx)),
        "/oauth/userinfo" => Ok(oauth::userinfo::handle(app, ctx)),

        _ => Ok(not_found(ctx)),
    }
}
