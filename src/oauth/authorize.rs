//! 認可エンドポイント (GET /oauth/authorize)
//!
//! コードを出すのは、ログイン済みの本人が同意画面の「承認」を押したときだけ。
//! 承認のリンクには、そのセッションとこの要求の内容に結び付けた署名付きの consent を入れる
//! (`approved=1` のような値を付けただけの URL を踏ませても、コードは出ない)。

use axum::http::header::{self, HeaderValue};
use axum::response::Response;
use serde_json::{Map, Value, json};
use url::Url;

use super::{CODE_TYPE, DEFAULT_SCOPE, pages};
use crate::App;
use crate::auth::session::{self, Session};
use crate::http::{self, Ctx};
use crate::jwt;
use crate::util::{encode_uri_component, is_loopback_host, random_hex, sha256_base64url};

const CONSENT_TYPE: &str = "oauth_consent";
const CONSENT_LIFETIME: i64 = 600;
const CODE_LIFETIME: i64 = 300;
/// 同意の流れの中で付ける値。ログイン後に戻る URL などからは取り除く
const FLOW_PARAMS: [&str; 5] = ["consent", "approved", "auto", "denied", "deny"];

/// クライアントへの戻り先として受け付ける URI か。
/// ウェブは https (手元は http も)、デスクトップアプリの独自スキームも通す
pub fn is_valid_redirect_uri(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if url.fragment().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(is_loopback_host),
        "javascript" | "data" | "vbscript" | "file" | "about" | "blob" | "ftp" | "ws" | "wss" => {
            false
        }
        _ => true,
    }
}

/// 利用者に見せる戻り先
fn redirect_target_label(uri: &str) -> String {
    match Url::parse(uri) {
        Ok(url) => match url.host_str() {
            Some(host) => format!("{}://{host}", url.scheme()),
            None => format!("{}:", url.scheme()),
        },
        Err(_) => uri.to_string(),
    }
}

fn client_display_name(client_id: &str, redirect_uri: &str) -> String {
    if client_id.contains("gemini") || redirect_uri.contains("google") {
        "Google Gemini".into()
    } else if client_id.contains("claude") || redirect_uri.contains("claude") {
        "Claude".into()
    } else if client_id.contains("chatgpt")
        || redirect_uri.contains("openai")
        || redirect_uri.contains("chatgpt")
    {
        "ChatGPT".into()
    } else {
        client_id.to_string()
    }
}

/// クエリの同じ名前の値を置き換える
fn set_param(url: &mut Url, name: &str, value: &str) {
    let rest: Vec<(String, String)> = url
        .query_pairs()
        .into_owned()
        .filter(|(k, _)| k != name)
        .collect();
    let mut pairs = url.query_pairs_mut();
    pairs.clear();
    for (k, v) in &rest {
        pairs.append_pair(k, v);
    }
    pairs.append_pair(name, value);
}

/// 同意した内容の指紋。承認のリンクと実際の要求が同じかを比べる
fn request_fingerprint(ctx: &Ctx) -> String {
    let fields = [
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
    ];
    let joined = fields.map(|name| ctx.q(name).unwrap_or("")).join("\0");
    sha256_base64url(joined.as_bytes())
}

fn consent_is_valid(app: &App, ctx: &Ctx, session: &Session) -> bool {
    let Some(claims) = ctx
        .q("consent")
        .and_then(|token| jwt::verify(token, &app.cfg.jwt_secret))
    else {
        return false;
    };
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    text("type") == Some(CONSENT_TYPE)
        && text("sub") == Some(session.id())
        && text("request") == Some(request_fingerprint(ctx).as_str())
}

fn issue_code(
    app: &App,
    ctx: &Ctx,
    session: &Session,
    client_id: &str,
    redirect_uri: &str,
) -> Response {
    let mut claims = Map::new();
    claims.insert("sub".into(), json!(session.id()));
    claims.insert("username".into(), json!(session.username()));
    claims.insert("avatar".into(), json!(session.avatar()));
    claims.insert("can_edit".into(), json!(session.can_edit()));
    claims.insert("client_id".into(), json!(client_id));
    claims.insert("redirect_uri".into(), json!(redirect_uri));
    for name in ["code_challenge", "code_challenge_method"] {
        if let Some(value) = ctx.q(name) {
            claims.insert(name.into(), json!(value));
        }
    }
    claims.insert(
        "scope".into(),
        json!(ctx.q("scope").unwrap_or(DEFAULT_SCOPE)),
    );
    claims.insert("type".into(), json!(CODE_TYPE));
    claims.insert("jti".into(), json!(random_hex(16)));
    claims.insert("exp".into(), json!(jwt::now() + CODE_LIFETIME));

    let code = jwt::sign(&Value::Object(claims), &app.cfg.jwt_secret);
    let Ok(mut target) = Url::parse(redirect_uri) else {
        return http::html(pages::invalid_request("Invalid redirect_uri"), 400);
    };
    set_param(&mut target, "code", &code);
    if let Some(state) = ctx.q("state").filter(|s| !s.is_empty()) {
        set_param(&mut target, "state", state);
    }
    let mut res = http::redirect(target.as_str());
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn denied_page(ctx: &Ctx, client_name: &str, redirect_uri: &str) -> Response {
    let client_return = Url::parse(redirect_uri).ok().map(|mut url| {
        set_param(&mut url, "error", "access_denied");
        set_param(
            &mut url,
            "error_description",
            "User denied the authorization request",
        );
        if let Some(state) = ctx.q("state").filter(|s| !s.is_empty()) {
            set_param(&mut url, "state", state);
        }
        url.to_string()
    });
    let retry_url = format!("/oauth/authorize?{}", ctx.query_without(&FLOW_PARAMS));
    http::html(
        pages::denied(client_name, client_return.as_deref(), &retry_url),
        403,
    )
}

pub fn handle(app: &App, ctx: &Ctx) -> Response {
    let client_id = ctx.q("client_id").unwrap_or("AI Client");
    let Some(redirect_uri) = ctx.q("redirect_uri") else {
        return http::html(
            pages::invalid_request("Missing required query parameter: \"redirect_uri\""),
            400,
        );
    };
    if !is_valid_redirect_uri(redirect_uri) {
        return http::html(
            pages::invalid_request("Query parameter \"redirect_uri\" is not allowed"),
            400,
        );
    }
    let client_name = client_display_name(client_id, redirect_uri);

    if ctx.q("denied") == Some("1") || ctx.q("deny") == Some("1") {
        return denied_page(ctx, &client_name, redirect_uri);
    }

    let session = session::from_request(app, ctx);
    if let Some(session) = &session
        && consent_is_valid(app, ctx, session)
    {
        return issue_code(app, ctx, session, client_id, redirect_uri);
    }

    // 同意画面。ログインしていなければ Discord へ行き、この画面に戻ってから承認してもらう
    let base = ctx.query_without(&FLOW_PARAMS);
    let issuer = &app.cfg.issuer;
    let authorize_url = format!("{issuer}/oauth/authorize?{base}");
    let login_url = format!(
        "{issuer}/api/auth/login?redirect={}",
        encode_uri_component(&authorize_url)
    );
    let deny_url = format!("/oauth/authorize?{base}&denied=1");
    let approve_url = session.as_ref().map(|session| {
        let consent = jwt::sign(
            &json!({
                "type": CONSENT_TYPE,
                "sub": session.id(),
                "request": request_fingerprint(ctx),
                "exp": jwt::now() + CONSENT_LIFETIME,
            }),
            &app.cfg.jwt_secret,
        );
        format!(
            "/oauth/authorize?{base}&consent={}",
            encode_uri_component(&consent)
        )
    });

    let page = pages::consent(&pages::Consent {
        client_name: &client_name,
        redirect_target: &redirect_target_label(redirect_uri),
        session: session.as_ref(),
        login_url: &login_url,
        approve_url: approve_url.as_deref(),
        deny_url: &deny_url,
    });
    let mut res = http::html(page, 200);
    res.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_rules() {
        assert!(is_valid_redirect_uri(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(is_valid_redirect_uri("http://localhost:6274/callback"));
        assert!(is_valid_redirect_uri("http://127.0.0.1:33418/"));
        assert!(is_valid_redirect_uri(
            "cursor://anysphere.cursor-retrieval/oauth/callback"
        ));
        assert!(!is_valid_redirect_uri("http://evil.example/cb"));
        assert!(!is_valid_redirect_uri("javascript:alert(1)"));
        assert!(!is_valid_redirect_uri("data:text/html,x"));
        assert!(!is_valid_redirect_uri("https://a.example/cb#frag"));
        assert!(!is_valid_redirect_uri("not a url"));
    }

    #[test]
    fn display_name_detection() {
        assert_eq!(
            client_display_name("toro-ai-1", "https://claude.ai/cb"),
            "Claude"
        );
        assert_eq!(
            client_display_name("toro-ai-1", "https://chatgpt.com/cb"),
            "ChatGPT"
        );
        assert_eq!(
            client_display_name("x", "https://oauth.google.com/cb"),
            "Google Gemini"
        );
        assert_eq!(
            client_display_name("toro-ai-1", "https://a.example/"),
            "toro-ai-1"
        );
    }

    #[test]
    fn set_param_replaces_existing_value() {
        let mut url = Url::parse("https://a.example/cb?code=old&x=1").unwrap();
        set_param(&mut url, "code", "new");
        assert_eq!(url.as_str(), "https://a.example/cb?x=1&code=new");
    }
}
