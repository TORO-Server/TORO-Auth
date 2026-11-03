//! バイナリに埋め込んだ静的ファイル (MCP 案内画面のスクリーンショット)

use axum::http::header::{self, HeaderValue};
use axum::response::Response;

use crate::http;

pub fn serve(path: &str) -> Option<Response> {
    let bytes: &'static [u8] = match path {
        "/_assets/claude_settings.webp" => include_bytes!("../assets/mcp/claude_settings.webp"),
        "/_assets/chatgpt_settings.webp" => include_bytes!("../assets/mcp/chatgpt_settings.webp"),
        "/_assets/gemini_settings.webp" => include_bytes!("../assets/mcp/gemini_settings.webp"),
        _ => return None,
    };
    let mut headers = http::public_headers();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    Some(http::respond(200, headers, "image/webp", bytes))
}
