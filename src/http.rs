//! リクエストの読み取りと、共通の応答 (JSON、HTML、エラー、CORS)

use axum::body::{Body, Bytes};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};
use url::{Url, form_urlencoded};

use crate::template;
use crate::util::{is_loopback_host, is_toro_host};

/// 各機能に渡すリクエスト
pub struct Ctx {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: HeaderMap,
    /// ポートを除いた小文字のホスト名
    pub host: String,
    pub body: Bytes,
}

impl Ctx {
    pub fn new(parts: &Parts, body: Bytes) -> Self {
        let query = parts.uri.query().unwrap_or("");
        let host = parts
            .headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        Self {
            method: parts.method.clone(),
            path: parts.uri.path().to_string(),
            query: form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect(),
            headers: parts.headers.clone(),
            host: host.split(':').next().unwrap_or("").to_ascii_lowercase(),
            body,
        }
    }

    /// クエリの値 (同じ名前が複数あれば先頭)
    pub fn q(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// ヘッダーの値 (無ければ空文字)
    pub fn header(&self, name: HeaderName) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    pub fn accepts_html(&self) -> bool {
        self.header(header::ACCEPT).contains("text/html")
    }

    /// 指定の名前を除いたクエリ文字列
    pub fn query_without(&self, drop: &[&str]) -> String {
        let mut out = form_urlencoded::Serializer::new(String::new());
        for (k, v) in self
            .query
            .iter()
            .filter(|(k, _)| !drop.contains(&k.as_str()))
        {
            out.append_pair(k, v);
        }
        out.finish()
    }
}

pub fn is_allowed_origin(origin: &str) -> bool {
    Url::parse(origin)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| is_toro_host(h) || h == "localhost" || h == "127.0.0.1")
        })
        .unwrap_or(false)
}

pub fn cors_headers(ctx: &Ctx) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let origin = ctx.header(header::ORIGIN);
    match HeaderValue::from_str(origin) {
        Ok(value) if is_allowed_origin(origin) => {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        _ => {
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            );
        }
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization, X-Requested-With"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
    headers
}

/// どの Origin からでも読める応答のヘッダー
pub fn public_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers
}

pub fn respond(
    status: u16,
    mut headers: HeaderMap,
    content_type: &'static str,
    body: impl Into<Body>,
) -> Response {
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    let mut res = Response::new(body.into());
    *res.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    *res.headers_mut() = headers;
    res
}

pub const JSON_UTF8: &str = "application/json; charset=utf-8";
pub const HTML_UTF8: &str = "text/html; charset=utf-8";

pub fn json(ctx: &Ctx, data: &Value, status: u16) -> Response {
    respond(status, cors_headers(ctx), JSON_UTF8, data.to_string())
}

/// 整形した JSON (発見用のメタデータなど)
pub fn pretty_json(mut headers: HeaderMap, data: &Value, status: u16) -> Response {
    let body = serde_json::to_string_pretty(data).expect("JSON value serializes");
    headers.remove(header::CONTENT_TYPE);
    respond(status, headers, JSON_UTF8, body)
}

pub fn html(body: String, status: u16) -> Response {
    respond(status, HeaderMap::new(), HTML_UTF8, body)
}

/// ブラウザには HTML の、それ以外には JSON のエラーを返す
pub fn error(ctx: &Ctx, message: &str, status: u16) -> Response {
    if ctx.accepts_html() {
        let page = template::render(
            include_str!("../assets/common/error.html"),
            &[("STATUS", &status.to_string()), ("MESSAGE", message)],
        );
        return respond(status, cors_headers(ctx), HTML_UTF8, page);
    }
    json(ctx, &json!({ "error": message }), status)
}

pub fn no_content(headers: HeaderMap) -> Response {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::NO_CONTENT;
    *res.headers_mut() = headers;
    res
}

/// 302。`location` は URL として正しいものだけを渡す
pub fn redirect(location: &str) -> Response {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::FOUND;
    match HeaderValue::from_str(location) {
        Ok(value) => {
            res.headers_mut().insert(header::LOCATION, value);
        }
        Err(_) => *res.status_mut() = StatusCode::BAD_REQUEST,
    }
    res
}

pub fn append_cookies(res: &mut Response, cookies: &[String]) {
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(cookie) {
            res.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

/// OpenAPI の servers に書く、このリクエストの公開 URL。知らないホスト名は信じない
pub fn public_origin(ctx: &Ctx, fallback: &str) -> String {
    if is_toro_host(&ctx.host) {
        format!("https://{}", ctx.host)
    } else if is_loopback_host(&ctx.host) {
        let host = ctx.header(header::HOST);
        format!("http://{host}")
    } else {
        fallback.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_allow_list() {
        assert!(is_allowed_origin("https://wiki.torosaba.net"));
        assert!(is_allowed_origin("http://localhost:4200"));
        assert!(!is_allowed_origin("https://torosaba.net.evil.example"));
        assert!(!is_allowed_origin(""));
    }
}
