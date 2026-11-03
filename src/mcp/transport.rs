//! MCP の受け口: 案内画面、SSE、発見用の JSON、JSON-RPC 2.0

use std::convert::Infallible;

use axum::http::Method;
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::{StreamExt, stream};
use serde_json::{Value, json};

use super::{guide, tools};
use crate::App;
use crate::auth::session;
use crate::http::{self, Ctx};

const SERVER_NAME: &str = "toro-server-ai-gateway";
const SERVER_VERSION: &str = "1.2.0";
const DEFAULT_PROTOCOL_VERSION: &str = "2025-03-26";

fn headers(ctx: &Ctx) -> HeaderMap {
    let mut headers = http::cors_headers(ctx);
    headers.insert(
        HeaderName::from_static("access-control-expose-headers"),
        HeaderValue::from_static("WWW-Authenticate"),
    );
    headers
}

pub async fn handle(app: &App, ctx: &Ctx) -> Response {
    if ctx.method == Method::GET || ctx.method == Method::HEAD {
        return handle_get(app, ctx);
    }
    handle_rpc(app, ctx).await
}

fn handle_get(app: &App, ctx: &Ctx) -> Response {
    let session = session::from_bearer(app, ctx);
    let accept = ctx.header(header::ACCEPT);
    let path = ctx.path.as_str();
    let is_dedicated_path = path == "/mcp"
        || path.starts_with("/mcp/")
        || path == "/api/mcp"
        || path.starts_with("/api/mcp/");
    let wants_json = accept.contains("application/json") || ctx.q("format") == Some("json");

    if !is_dedicated_path && !wants_json && accept.contains("text/html") {
        return http::respond(
            200,
            http::public_headers(),
            http::HTML_UTF8,
            guide::render_page(),
        );
    }

    if accept.contains("text/event-stream") {
        return sse(app);
    }

    let tool_names: Vec<Value> = tools::definitions()
        .as_array()
        .map(|list| list.iter().map(|tool| tool["name"].clone()).collect())
        .unwrap_or_default();
    let user = session.as_ref().map_or(
        Value::Null,
        |s| json!({ "username": s.username(), "id": s.id(), "can_edit": s.can_edit() }),
    );
    let mcp_url = &app.cfg.mcp_url;
    http::pretty_json(
        headers(ctx),
        &json!({
            "status": "ok",
            "service": "TORO Server AI Gateway (MCP)",
            "version": SERVER_VERSION,
            "authenticated": session.is_some(),
            "user": user,
            "tools": tool_names,
            "instructions": format!(
                "Connect via Claude / ChatGPT / Gemini by setting URL \"{mcp_url}/\". Browser setup guide available at the same URL."
            ),
        }),
        200,
    )
}

/// 接続先を伝えたあとは、客が切るまで開けたままにする。開けておける数には上限がある
fn sse(app: &App) -> Response {
    let Ok(permit) = app.sse_streams.clone().try_acquire_owned() else {
        return http::busy();
    };
    let endpoint = Event::default()
        .event("endpoint")
        .data(format!("{}/mcp", app.cfg.mcp_url));
    let events = stream::once(async move { Ok::<_, Infallible>(endpoint) })
        .chain(stream::pending())
        .map(move |event| {
            let _held_until_disconnect = &permit;
            event
        });
    let mut res = Sse::new(events)
        .keep_alive(KeepAlive::default())
        .into_response();
    res.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    res
}

async fn handle_rpc(app: &App, ctx: &Ctx) -> Response {
    let Ok(body) = serde_json::from_slice::<Value>(&ctx.body) else {
        let parse_error = json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } });
        return http::respond(
            400,
            http::public_headers(),
            "application/json",
            parse_error.to_string(),
        );
    };

    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let params = body.get("params").cloned().unwrap_or_else(|| json!({}));
    let reply = |result: Value| {
        let body = json!({ "jsonrpc": "2.0", "id": id, "result": result });
        http::respond(200, headers(ctx), http::JSON_UTF8, body.to_string())
    };

    match method {
        "initialize" => {
            let version = params["protocolVersion"]
                .as_str()
                .unwrap_or(DEFAULT_PROTOCOL_VERSION);
            reply(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
                "instructions": "TORO Server AI Gateway provides tools to interact with TORO Server Wiki and server status.",
            }))
        }
        "notifications/initialized" => http::no_content(headers(ctx)),
        "tools/list" => reply(json!({ "tools": tools::definitions() })),
        "resources/list" => reply(json!({ "resources": [] })),
        "prompts/list" => reply(json!({ "prompts": [] })),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or("");
            let empty = json!({});
            let args = params
                .get("arguments")
                .filter(|a| a.is_object())
                .unwrap_or(&empty);
            // MCP のクライアントは Bearer を使う。Cookie を見ないので、ブラウザからの CSRF は成り立たない
            let session = session::from_bearer(app, ctx);
            reply(tools::call(app, name, args, session.as_ref()).await)
        }
        "ping" => reply(json!({})),
        _ if id.is_null() => http::no_content(headers(ctx)),
        _ => {
            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("Method not found: {method}") },
            });
            http::respond(404, headers(ctx), http::JSON_UTF8, body.to_string())
        }
    }
}
