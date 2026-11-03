//! ブラウザの Wiki エディタと OpenAPI から使う REST API

use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::Response;
use serde_json::{Value, json};

use super::github::{self, Commit};
use super::path;
use crate::App;
use crate::auth::session;
use crate::http::{self, Ctx};

/// GET /api/docs/raw
pub async fn raw(app: &App, ctx: &Ctx) -> Response {
    let Some(requested) = ctx.q("path").filter(|p| !p.is_empty()) else {
        return http::error(ctx, "Missing required query parameter \"path\"", 400);
    };
    let Some(clean_path) = path::normalize(requested) else {
        return http::error(ctx, "Invalid path", 400);
    };

    match github::get_file(app, &clean_path).await {
        Ok(None) => http::error(ctx, &format!("File not found: {requested}"), 404),
        Err(message) => http::error(ctx, &message, 500),
        Ok(Some(file)) if ctx.q("format") == Some("raw") => {
            let mut headers = HeaderMap::new();
            if let Ok(etag) = HeaderValue::from_str(&format!("\"{}\"", file.sha)) {
                headers.insert(header::ETAG, etag);
            }
            http::respond(200, headers, "text/markdown; charset=utf-8", file.content)
        }
        Ok(Some(file)) => http::json(
            ctx,
            &json!({ "path": file.path, "sha": file.sha, "content": file.content, "size": file.size }),
            200,
        ),
    }
}

/// POST /api/docs/save
pub async fn save(app: &App, ctx: &Ctx) -> Response {
    let Some(user) = session::from_request(app, ctx) else {
        return http::error(
            ctx,
            "Authentication required (please login with Discord)",
            401,
        );
    };
    if !user.can_edit() {
        return http::error(
            ctx,
            "You do not have permission to edit wiki documents",
            403,
        );
    }
    let Ok(body) = serde_json::from_slice::<Value>(&ctx.body) else {
        return http::error(ctx, "Invalid JSON body", 400);
    };

    let Some(requested) = body["path"].as_str().filter(|p| !p.is_empty()) else {
        return http::error(ctx, "Field \"path\" is required", 400);
    };
    let Some(content) = body["content"].as_str() else {
        return http::error(ctx, "Field \"content\" is required", 400);
    };
    if requested.starts_with('/') || path::normalize(requested).is_none() {
        return http::error(ctx, "Invalid path", 400);
    }

    let commit = Commit {
        path: requested,
        content,
        sha: body["sha"].as_str(),
        message: body["message"].as_str(),
        user: &user,
    };
    match github::commit_file(app, &commit).await {
        Ok((commit_sha, content_sha)) => http::json(
            ctx,
            &json!({
                "ok": true,
                "path": requested,
                "commitSha": commit_sha,
                "contentSha": content_sha,
                "message": "Wiki document updated successfully",
            }),
            200,
        ),
        // 画面は文言の 409 / does not match を見て、競合の案内を出す
        Err(message) => http::error(ctx, &format!("Failed to commit to GitHub: {message}"), 500),
    }
}
