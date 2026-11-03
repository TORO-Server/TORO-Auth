//! 脆弱性の確認で見つかった攻撃が、成り立たないことの試験

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};
use toro_auth::jwt;
use toro_auth::util::{encode_uri_component, sha256_base64url};

const SUBDOMAIN: &str = "https://assets.torosaba.net";
const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier";

fn authorize_path(redirect_uri: &str, client_id: &str) -> String {
    format!(
        "/oauth/authorize?client_id={}&code_challenge={}&code_challenge_method=S256&redirect_uri={}",
        encode_uri_component(client_id),
        sha256_base64url(VERIFIER.as_bytes()),
        encode_uri_component(redirect_uri)
    )
}

fn token_for(claims: Value) -> String {
    jwt::sign(&claims, JWT_SECRET)
}

async fn post_token(
    server: &TestServer,
    origin: Option<&str>,
    cookie: Option<&str>,
    bearer: Option<&str>,
) -> u16 {
    let mut request = server.client.post(server.url("/api/auth/token"));
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    request.send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn only_exact_origins_get_credentialed_cors() {
    let server = start().await;
    let cors = |origin: &'static str| {
        let request = server
            .client
            .get(server.url("/api/auth/me"))
            .header(header::ORIGIN, origin);
        async move { request.send().await.unwrap() }
    };

    let res = cors(WIKI_ORIGIN).await;
    assert_eq!(
        res.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        WIKI_ORIGIN
    );
    assert_eq!(res.headers()[header::VARY], "Origin");

    for other in [
        SUBDOMAIN,
        "https://torosaba.net",
        "http://wiki.torosaba.net",
        "http://localhost:4200",
        "https://wiki.torosaba.net.evil.example",
    ] {
        let res = cors(other).await;
        assert_eq!(
            res.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "*",
            "{other}"
        );
        assert!(
            res.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }
}

#[tokio::test]
async fn api_tokens_come_only_from_a_browser_session_on_a_trusted_origin() {
    let server = start().await;
    let cookie = server.login("member").await;

    assert_eq!(
        post_token(&server, Some(SUBDOMAIN), Some(&cookie), None).await,
        401
    );
    assert_eq!(post_token(&server, None, Some(&cookie), None).await, 401);
    assert_eq!(
        post_token(&server, Some(WIKI_ORIGIN), Some(&cookie), None).await,
        200
    );
    // トップページのボタン (同じ Origin)
    assert_eq!(
        post_token(&server, Some(&server.base), Some(&cookie), None).await,
        200
    );

    // 漏れたトークンでは更新できない
    let bearer =
        token_for(json!({ "id": "1", "username": "u", "can_edit": true, "exp": jwt::now() + 60 }));
    assert_eq!(
        post_token(&server, Some(WIKI_ORIGIN), None, Some(&bearer)).await,
        401
    );
}

#[tokio::test]
async fn cookies_cannot_carry_api_tokens() {
    let server = start().await;
    for claims in [
        json!({ "id": "1", "username": "u", "can_edit": true, "purpose": "ai_connector" }),
        json!({ "id": "1", "username": "u", "can_edit": true, "type": "mcp_access_token" }),
    ] {
        let cookie = format!("__Host-toro_session={}", token_for(claims));
        let me: Value = server
            .get_with_cookie("/api/auth/me", &cookie)
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(me["authenticated"], false);
    }
}

#[tokio::test]
async fn cookies_on_the_parent_domain_are_not_accepted() {
    let server = start().await;
    let session = server.login("member").await;
    let value = session.strip_prefix("__Host-toro_session=").unwrap();

    for name in ["toro_session", "wiki_session"] {
        let me: Value = server
            .get_with_cookie("/api/auth/me", &format!("{name}={value}"))
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(me["authenticated"], false, "{name}");
    }
}

#[tokio::test]
async fn session_cookie_is_host_only_and_clears_the_old_ones() {
    let server = start().await;
    let start = server.get("/api/auth/login").await;
    let state = query_param(&location(&start), "state").unwrap();
    let nonce_set_cookie = set_cookies(&start);
    assert!(nonce_set_cookie[0].starts_with("__Host-toro_login_nonce="));
    assert!(nonce_set_cookie[0].contains("Path=/;"));
    assert!(!nonce_set_cookie[0].contains("Domain"));

    let nonce = cookie_pair(&nonce_set_cookie, "__Host-toro_login_nonce").unwrap();
    let res = server
        .get_with_cookie(
            &format!(
                "/api/auth/callback?code=member&state={}",
                encode_uri_component(&state)
            ),
            &nonce,
        )
        .await;
    let cookies = set_cookies(&res);
    let session = cookies
        .iter()
        .find(|c| c.starts_with("__Host-toro_session="))
        .unwrap();
    assert!(session.ends_with("; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000"));
    assert!(!session.contains("Domain"));
    for old in ["toro_session=;", "wiki_session=;"] {
        let removal = cookies.iter().find(|c| c.starts_with(old)).unwrap();
        assert!(removal.contains("Max-Age=0") && removal.contains("Domain=.torosaba.net"));
    }
}

#[tokio::test]
async fn wiki_save_rejects_cross_origin_cookie_requests() {
    let server = start().await;
    let cookie = server.login("member").await;
    let body = r#"{"path":"defaced","content":"x"}"#;

    // text/plain は、ブラウザが事前確認なしで送れる
    let send = |origin: Option<&'static str>| {
        let mut request = server
            .client
            .post(server.url("/api/docs/save"))
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(body);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        async move { request.send().await.unwrap().status().as_u16() }
    };

    assert_eq!(send(Some(SUBDOMAIN)).await, 401);
    assert_eq!(send(None).await, 401);
    assert!(server.github.commits.lock().unwrap().is_empty());

    assert_eq!(send(Some(WIKI_ORIGIN)).await, 200);
    assert_eq!(server.github.commits.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn mcp_ignores_cookies() {
    let server = start().await;
    let cookie = server.login("member").await;

    let res = server
        .client
        .post(server.url("/mcp"))
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, WIKI_ORIGIN)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "wiki_save_page", "arguments": { "path": "x", "content": "y" } },
        }))
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["result"]["isError"], true);
    assert!(server.github.commits.lock().unwrap().is_empty());

    let discovery: Value = server
        .get_with_cookie("/mcp", &cookie)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(discovery["authenticated"], false);
}

#[tokio::test]
async fn brand_names_cannot_be_spoofed_on_the_consent_page() {
    let server = start().await;
    for (redirect, client_id) in [
        ("https://evil.example/claude", "x"),
        ("https://evil.example/cb", "claude"),
        ("https://chatgpt.com.evil.example/", "chatgpt"),
        ("https://evil.example/google", "gemini"),
    ] {
        let page = server
            .get(&authorize_path(redirect, client_id))
            .await
            .text()
            .await
            .unwrap();
        assert!(
            page.contains("REQUESTING CLIENT: UNVERIFIED:"),
            "{redirect}"
        );
        assert!(
            page.contains("TOKENS WILL BE SENT TO: https://"),
            "{redirect}"
        );
    }
    let page = server
        .get(&authorize_path(
            "https://claude.ai/api/mcp/auth_callback",
            "toro-ai-1",
        ))
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("REQUESTING CLIENT: Claude"));
}

#[tokio::test]
async fn client_id_cannot_expand_template_blocks() {
    let server = start().await;
    let cookie = server.login("member").await;
    let path = authorize_path("https://a.example/cb", "{{USER_SECTION}}");
    let page = server
        .get_with_cookie(&path, &cookie)
        .await
        .text()
        .await
        .unwrap();
    assert_eq!(page.matches("APPROVE AI CLIENT INTEGRATION").count(), 1);
}

#[tokio::test]
async fn bearer_tokens_cannot_pass_the_consent_page() {
    let server = start().await;
    let bearer =
        token_for(json!({ "id": "1", "username": "u", "can_edit": true, "exp": jwt::now() + 60 }));
    let page = server
        .client
        .get(server.url(&authorize_path("https://a.example/cb", "x")))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("LOGIN VIA DISCORD"));
    assert!(!page.contains("consent="));
}

#[tokio::test]
async fn read_scope_cannot_write() {
    let server = start().await;
    let token = |scope: &str| {
        token_for(json!({
            "id": "1", "sub": "1", "username": "u", "can_edit": true, "scope": scope,
            "type": "mcp_access_token", "exp": jwt::now() + 60,
        }))
    };
    let args = json!({ "path": "x", "content": "y" });

    let (text, is_error) = server
        .tool("wiki_save_page", args.clone(), Some(&token("read")))
        .await;
    assert!(is_error, "{text}");

    let res = server
        .client
        .post(server.url("/api/docs/save"))
        .bearer_auth(token("read"))
        .json(&args)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    assert!(server.github.commits.lock().unwrap().is_empty());

    for scope in ["mcp", "read write"] {
        let (text, is_error) = server
            .tool("wiki_save_page", args.clone(), Some(&token(scope)))
            .await;
        assert!(!is_error, "{scope}: {text}");
    }
}

#[tokio::test]
async fn consent_page_shows_the_requested_scope() {
    let server = start().await;
    let path = format!("{}&scope=read", authorize_path("https://a.example/cb", "x"));
    let page = server.get(&path).await.text().await.unwrap();
    assert!(page.contains("REQUESTED SCOPE: read"));
}

#[tokio::test]
async fn pkce_is_mandatory_with_s256_except_for_google_linking() {
    let server = start().await;
    let target = encode_uri_component("https://a.example/cb");

    for query in [
        format!("redirect_uri={target}"),
        format!("redirect_uri={target}&code_challenge=abc"),
        format!("redirect_uri={target}&code_challenge=abc&code_challenge_method=plain"),
    ] {
        let res = server.get(&format!("/oauth/authorize?{query}")).await;
        assert_eq!(res.status(), 400, "{query}");
    }

    let google = encode_uri_component("https://oauth-redirect.googleusercontent.com/r/project");
    let res = server
        .get(&format!("/oauth/authorize?redirect_uri={google}"))
        .await;
    assert_eq!(res.status(), 200);
    assert!(
        res.text()
            .await
            .unwrap()
            .contains("REQUESTING CLIENT: Google Gemini")
    );

    let meta: Value = server
        .get("/.well-known/oauth-authorization-server")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
}

#[tokio::test]
async fn verifier_without_challenge_is_refused_and_response_carries_iss() {
    let server = start().await;
    let cookie = server.login("member").await;
    let google = "https://oauth-redirect.googleusercontent.com/r/project";

    let page = server
        .get_with_cookie(
            &format!(
                "/oauth/authorize?client_id=g&redirect_uri={}",
                encode_uri_component(google)
            ),
            &cookie,
        )
        .await
        .text()
        .await
        .unwrap();
    let start = page.find("/oauth/authorize?").unwrap();
    let approve = page[start..]
        .split('"')
        .next()
        .unwrap()
        .replace("&amp;", "&");
    let res = server.get_with_cookie(&approve, &cookie).await;
    assert_eq!(res.status(), 302);
    let target = location(&res);
    assert_eq!(query_param(&target, "iss").unwrap(), server.base);
    let code = query_param(&target, "code").unwrap();

    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("code_verifier", VERIFIER)
        .finish();
    let res = server
        .client
        .post(server.url("/oauth/token"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn personal_responses_are_not_cacheable() {
    let server = start().await;
    let cookie = server.login("member").await;
    for path in ["/", "/api/auth/me", "/mcp"] {
        let res = server.get_with_cookie(path, &cookie).await;
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store", "{path}");
    }
    // 拡張子で Cloudflare にためさせる手も効かない
    let res = server
        .client
        .get(server.url("/x.png"))
        .header(header::HOST, "mcp.torosaba.net")
        .header(header::ACCEPT, "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");

    let image = server.get("/_assets/claude_settings.webp").await;
    assert_eq!(
        image.headers()[header::CACHE_CONTROL],
        "public, max-age=86400"
    );
}

#[tokio::test]
async fn approve_page_cannot_be_framed() {
    let server = start().await;
    let path = authorize_path("https://a.example/cb", "x");
    let csp = |res: &reqwest::Response| {
        res.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_string()
    };

    let guest = server.get(&path).await;
    assert!(!csp(&guest).contains("frame-ancestors"));

    let cookie = server.login("member").await;
    let logged_in = server.get_with_cookie(&path, &cookie).await;
    assert!(csp(&logged_in).contains("frame-ancestors 'none'"));
    assert!(csp(&logged_in).contains("default-src 'none'"));

    assert!(csp(&server.get("/").await).contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn large_bodies_are_refused() {
    let server = start().await;
    let res = server
        .client
        .post(server.url("/mcp"))
        .body(vec![b'x'; 2 * 1024 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 413);
}

#[tokio::test]
async fn sse_streams_are_limited_and_released() {
    let server = start().await;
    let open = || {
        server
            .client
            .get(server.url("/sse"))
            .header(header::ACCEPT, "text/event-stream")
            .send()
    };

    let mut streams = Vec::new();
    for _ in 0..toro_auth::MAX_SSE_STREAMS {
        let mut res = open().await.unwrap();
        assert_eq!(res.status(), 200);
        // 最初のイベントまで受けて、確かに始まったことを確かめる
        res.chunk().await.unwrap().unwrap();
        streams.push(res);
    }
    assert_eq!(open().await.unwrap().status(), 503);

    drop(streams);
    // 切断が伝わるのを待つ
    let mut status = 0;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        status = open().await.unwrap().status().as_u16();
        if status == 200 {
            break;
        }
    }
    assert_eq!(status, 200);
}
