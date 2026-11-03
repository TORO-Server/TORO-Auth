//! バイナリに埋め込んだ静的ファイル (画面のスタイル、フォント、スクリーンショット)

use axum::http::header::{self, HeaderValue};
use axum::response::Response;

use crate::http;

const STYLE_CACHE: &str = "public, max-age=3600";
const IMAGE_CACHE: &str = "public, max-age=86400";
const FONT_CACHE: &str = "public, max-age=2592000";

pub fn serve(path: &str) -> Option<Response> {
    let (bytes, content_type, cache): (&'static [u8], &'static str, &'static str) = match path {
        "/_assets/auth.css" => (
            include_bytes!("../assets/auth/theme.css"),
            "text/css; charset=utf-8",
            STYLE_CACHE,
        ),
        "/_assets/mcp.css" => (
            include_bytes!("../assets/mcp/theme.css"),
            "text/css; charset=utf-8",
            STYLE_CACHE,
        ),
        "/_assets/favicon.svg" => (
            include_bytes!("../assets/auth/favicon.svg"),
            "image/svg+xml",
            IMAGE_CACHE,
        ),
        "/_assets/pixel.woff2" => (
            include_bytes!("../assets/fonts/pixel.woff2"),
            "font/woff2",
            FONT_CACHE,
        ),
        "/_assets/OFL.txt" => (
            include_bytes!("../assets/fonts/OFL.txt"),
            "text/plain; charset=utf-8",
            IMAGE_CACHE,
        ),
        "/_assets/claude_settings.webp" => (
            include_bytes!("../assets/mcp/claude_settings.webp"),
            "image/webp",
            IMAGE_CACHE,
        ),
        "/_assets/chatgpt_settings.webp" => (
            include_bytes!("../assets/mcp/chatgpt_settings.webp"),
            "image/webp",
            IMAGE_CACHE,
        ),
        "/_assets/gemini_settings.webp" => (
            include_bytes!("../assets/mcp/gemini_settings.webp"),
            "image/webp",
            IMAGE_CACHE,
        ),
        _ => return None,
    };
    let mut headers = http::public_headers();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    Some(http::respond(200, headers, content_type, bytes))
}
