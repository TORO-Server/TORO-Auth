//! ログイン後の操作: 自分の情報、ログアウト、AI コネクタ用の API トークン

use axum::http::Method;
use axum::response::Response;
use serde_json::{Value, json};

use super::session;
use crate::App;
use crate::http::{self, Ctx};
use crate::jwt;

const CONNECTOR_TOKEN_LIFETIME: i64 = 90 * 86400;
const SESSION_TOKEN_LIFETIME: i64 = 600;

pub fn me(app: &App, ctx: &Ctx) -> Response {
    let body = match session::from_request(app, ctx) {
        Some(session) => json!({ "authenticated": true, "user": session.claims }),
        None => json!({ "authenticated": false, "user": null }),
    };
    http::json(ctx, &body, 200)
}

pub fn logout(ctx: &Ctx) -> Response {
    let mut res = if ctx.accepts_html() {
        http::html(
            include_str!("../../assets/auth/logout.html").to_string(),
            200,
        )
    } else {
        http::json(
            ctx,
            &json!({ "ok": true, "message": "Logged out successfully" }),
            200,
        )
    };
    http::append_cookies(&mut res, &session::logout_cookies());
    res
}

/// API を呼ぶための短い期限のトークン。セッションの Cookie は auth にしか届かないので、Wiki の画面はこれに換えて使う
pub fn issue_session_token(app: &App, ctx: &Ctx) -> Response {
    if ctx.method != Method::POST {
        return http::error(ctx, "Method Not Allowed", 405);
    }
    let Some(session) = session::from_cookie_for_write(app, ctx) else {
        return http::error(ctx, "Authentication required", 401);
    };
    let now = jwt::now();
    let mut claims = session.claims;
    claims.insert("purpose".into(), json!("api_session"));
    claims.insert("iat".into(), json!(now));
    claims.insert("exp".into(), json!(now + SESSION_TOKEN_LIFETIME));
    http::json(
        ctx,
        &json!({
            "token": jwt::sign(&Value::Object(claims), &app.cfg.jwt_secret),
            "expires_in": SESSION_TOKEN_LIFETIME,
        }),
        200,
    )
}

/// 90 日トークンの発行と再作成。本人のブラウザの、auth の画面からだけ (トークンでトークンを出すと、漏れたものが永久に更新できてしまう)。
/// トークンを返すのはこの応答の一度だけで、前のトークンは使えなくなる
pub fn issue_token(app: &App, ctx: &Ctx) -> Response {
    if ctx.method != Method::POST {
        return http::error(ctx, "Method Not Allowed", 405);
    }
    let Some(session) = session::from_cookie_on_own_page(app, ctx) else {
        return http::error(ctx, "Authentication required to generate API token", 401);
    };

    let now = jwt::now();
    let exp = now + CONNECTOR_TOKEN_LIFETIME;
    let generation = match app.tokens.rotate(session.id(), exp) {
        Ok(generation) => generation,
        Err(e) => {
            eprintln!("token store: {e}");
            return http::error(ctx, "Could not save the token record", 500);
        }
    };
    let mut claims = session.claims;
    claims.insert("purpose".into(), json!(session::CONNECTOR_PURPOSE));
    claims.insert("generation".into(), json!(generation));
    claims.insert("iat".into(), json!(now));
    claims.insert("exp".into(), json!(exp));
    let token = jwt::sign(&Value::Object(claims), &app.cfg.jwt_secret);

    http::json(
        ctx,
        &json!({ "ok": true, "token": token, "expires_at": iso8601(exp) }),
        200,
    )
}

/// UNIX 時刻を `2026-01-02T03:04:05.000Z` にする
pub fn iso8601(unix: i64) -> String {
    let days = unix.div_euclid(86400);
    let secs = unix.rem_euclid(86400);
    // 暦の計算 (Howard Hinnant の civil_from_days)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::iso8601;

    #[test]
    fn formats_dates_like_to_iso_string() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_709_164_800), "2024-02-29T00:00:00.000Z");
        assert_eq!(iso8601(1_793_750_399), "2026-11-03T23:59:59.000Z");
    }
}
