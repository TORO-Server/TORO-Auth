//! バイナリに埋め込んだ静的ファイル (画面のスタイル、フォント、TORO のアイコン)

use axum::http::header::{self, HeaderName, HeaderValue};
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
        "/_assets/favicon.svg" => (
            include_bytes!("../assets/icons/favicon.svg"),
            "image/svg+xml",
            IMAGE_CACHE,
        ),
        // AI クライアントや検索エンジンは、決まった場所のアイコンを取りに来る
        "/favicon.ico" | "/favicon.png" | "/_assets/favicon-32.png" => (
            include_bytes!("../assets/icons/favicon-32.png"),
            "image/png",
            IMAGE_CACHE,
        ),
        "/apple-touch-icon.png" => (
            include_bytes!("../assets/icons/apple-touch-icon.png"),
            "image/png",
            IMAGE_CACHE,
        ),
        "/icon-64.png" => (
            include_bytes!("../assets/icons/icon-64.png"),
            "image/png",
            IMAGE_CACHE,
        ),
        "/icon-192.png" => (
            include_bytes!("../assets/icons/icon-192.png"),
            "image/png",
            IMAGE_CACHE,
        ),
        "/icon-512.png" => (
            include_bytes!("../assets/icons/icon-512.png"),
            "image/png",
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
        _ => return None,
    };
    let mut headers = http::public_headers();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    // AI クライアントの画面が、別のオリジンからアイコンを読めるように
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );
    Some(http::respond(200, headers, content_type, bytes))
}
