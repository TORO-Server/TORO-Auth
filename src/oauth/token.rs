//! トークンエンドポイント (POST /oauth/token)

use axum::http::header::{self, HeaderValue};
use axum::response::Response;
use serde_json::{Value, json};
use url::form_urlencoded;

use super::{CODE_TYPE, DEFAULT_SCOPE, REFRESH_TOKEN_TYPE};
use crate::App;
use crate::auth::session::ACCESS_TOKEN_TYPE;
use crate::http::{self, Ctx};
use crate::jwt::{self, Claims};
use crate::util::sha256_base64url;

const ACCESS_TOKEN_LIFETIME: i64 = 30 * 86400;
const REFRESH_TOKEN_LIFETIME: i64 = 180 * 86400;

fn respond(ctx: &Ctx, data: &Value, status: u16) -> Response {
    let mut res = http::json(ctx, data, status);
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn oauth_error(ctx: &Ctx, error: &str, description: &str) -> Response {
    respond(
        ctx,
        &json!({ "error": error, "error_description": description }),
        400,
    )
}

/// フォームと JSON のどちらのボディも受け付ける
fn parse_params(ctx: &Ctx) -> Result<Vec<(String, String)>, ()> {
    if ctx
        .header(header::CONTENT_TYPE)
        .contains("application/json")
    {
        let body: Value = serde_json::from_slice(&ctx.body).map_err(|_| ())?;
        let object = body.as_object().ok_or(())?;
        return Ok(object
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_str().map_or_else(|| v.to_string(), str::to_string),
                )
            })
            .collect());
    }
    Ok(form_urlencoded::parse(&ctx.body).into_owned().collect())
}

fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn claim<'a>(claims: &'a Claims, name: &str) -> Option<&'a str> {
    claims.get(name).and_then(Value::as_str)
}

pub fn handle(app: &App, ctx: &Ctx) -> Response {
    let Ok(params) = parse_params(ctx) else {
        return oauth_error(ctx, "invalid_request", "Invalid JSON body");
    };
    match param(&params, "grant_type") {
        Some("refresh_token") => refresh(app, ctx, &params),
        Some("authorization_code") => exchange_code(app, ctx, &params),
        _ => oauth_error(
            ctx,
            "unsupported_grant_type",
            "Only authorization_code and refresh_token are supported",
        ),
    }
}

fn refresh(app: &App, ctx: &Ctx, params: &[(String, String)]) -> Response {
    let Some(refresh_token) = param(params, "refresh_token") else {
        return oauth_error(ctx, "invalid_request", "Missing refresh_token");
    };
    let Some(mut claims) = jwt::verify(refresh_token, &app.cfg.jwt_secret)
        .filter(|claims| claim(claims, "type") == Some(REFRESH_TOKEN_TYPE))
    else {
        return oauth_error(ctx, "invalid_grant", "Invalid refresh_token");
    };

    let scope = claim(&claims, "scope").unwrap_or(DEFAULT_SCOPE).to_string();
    let now = jwt::now();
    claims.insert("type".into(), json!(ACCESS_TOKEN_TYPE));
    claims.insert("iat".into(), json!(now));
    claims.insert("exp".into(), json!(now + ACCESS_TOKEN_LIFETIME));
    let access_token = jwt::sign(&Value::Object(claims), &app.cfg.jwt_secret);

    respond(
        ctx,
        &json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_LIFETIME,
            "refresh_token": refresh_token,
            "scope": scope,
        }),
        200,
    )
}

/// PKCE。S256 だけ。challenge と verifier は、そろっているか、どちらも無いか (省略は認可の段階で限ってある)
fn pkce_ok(code: &Claims, verifier: Option<&str>) -> bool {
    match (claim(code, "code_challenge"), verifier) {
        (Some(challenge), Some(verifier)) => {
            claim(code, "code_challenge_method") == Some("S256")
                && sha256_base64url(verifier.as_bytes()) == challenge
        }
        (None, None) => true,
        _ => false,
    }
}

/// 認可コードは一度だけ。初めてなら true
fn consume_code(app: &App, jti: &str, exp: i64) -> bool {
    let mut used = app.used_codes.lock().expect("used_codes lock");
    let now = jwt::now();
    used.retain(|_, until| *until >= now);
    used.insert(jti.to_string(), exp).is_none()
}

fn exchange_code(app: &App, ctx: &Ctx, params: &[(String, String)]) -> Response {
    let Some(code) = param(params, "code") else {
        return oauth_error(ctx, "invalid_request", "Missing code");
    };
    let invalid_code = || oauth_error(ctx, "invalid_grant", "Code is invalid or expired");
    let Some(payload) =
        jwt::verify(code, &app.cfg.jwt_secret).filter(|c| claim(c, "type") == Some(CODE_TYPE))
    else {
        return invalid_code();
    };
    let (Some(jti), Some(exp)) = (
        claim(&payload, "jti"),
        payload.get("exp").and_then(Value::as_i64),
    ) else {
        return invalid_code();
    };

    if let Some(uri) = param(params, "redirect_uri")
        && claim(&payload, "redirect_uri") != Some(uri)
    {
        return oauth_error(ctx, "invalid_grant", "redirect_uri mismatch");
    }
    if let Some(client_id) = param(params, "client_id")
        && claim(&payload, "client_id") != Some(client_id)
    {
        return oauth_error(ctx, "invalid_grant", "client_id mismatch");
    }
    if !pkce_ok(&payload, param(params, "code_verifier")) {
        return oauth_error(ctx, "invalid_grant", "PKCE verification failed");
    }
    if !consume_code(app, jti, exp) {
        return invalid_code();
    }

    let sub = claim(&payload, "sub").unwrap_or("");
    let username = claim(&payload, "username").unwrap_or("");
    let avatar = claim(&payload, "avatar");
    let avatar_url = match avatar {
        Some(avatar) => format!("https://cdn.discordapp.com/avatars/{sub}/{avatar}.png"),
        None => "https://cdn.discordapp.com/embed/avatars/0.png".to_string(),
    };
    let can_edit = payload
        .get("can_edit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let scope = claim(&payload, "scope").unwrap_or(DEFAULT_SCOPE);
    let now = jwt::now();

    let access_token = jwt::sign(
        &json!({
            "sub": sub,
            "id": sub,
            "username": username,
            "name": username,
            "global_name": username,
            "avatar": avatar,
            "avatar_url": avatar_url,
            "can_edit": can_edit,
            "roles": [],
            "scope": scope,
            "type": ACCESS_TOKEN_TYPE,
            "iss": app.cfg.issuer,
            "aud": claim(&payload, "client_id"),
            "iat": now,
            "exp": now + ACCESS_TOKEN_LIFETIME,
        }),
        &app.cfg.jwt_secret,
    );
    // Google Account Linking の必須要件なので、refresh_token を必ず返す
    let refresh_token = jwt::sign(
        &json!({
            "sub": sub,
            "id": sub,
            "username": username,
            "can_edit": can_edit,
            "scope": scope,
            "type": REFRESH_TOKEN_TYPE,
            "iat": now,
            "exp": now + REFRESH_TOKEN_LIFETIME,
        }),
        &app.cfg.jwt_secret,
    );

    respond(
        ctx,
        &json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_LIFETIME,
            "refresh_token": refresh_token,
            "scope": scope,
        }),
        200,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(value: Value) -> Claims {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn pkce_rules() {
        // RFC 7636 付録 B の例
        let s256 = claims(json!({
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }));
        assert!(pkce_ok(
            &s256,
            Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        ));
        assert!(!pkce_ok(&s256, Some("wrong")));
        assert!(!pkce_ok(&s256, None));

        // plain は受け付けない
        let plain = claims(json!({ "code_challenge": "abc", "code_challenge_method": "plain" }));
        assert!(!pkce_ok(&plain, Some("abc")));

        // challenge の無いコードに verifier を送ってきたら、すり替えの疑い
        assert!(!pkce_ok(&claims(json!({})), Some("x")));
        assert!(pkce_ok(&claims(json!({})), None));
    }
}
