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
    let mut request = server.client.post(server.url("/token"));
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
            .get(server.url("/session"))
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
async fn api_tokens_come_only_from_a_browser_session_on_our_own_page() {
    let server = start().await;
    let cookie = server.login("member").await;

    assert_eq!(
        post_token(&server, Some(SUBDOMAIN), Some(&cookie), None).await,
        401
    );
    assert_eq!(post_token(&server, None, Some(&cookie), None).await, 401);
    // Wiki の画面が作れるのは、短いトークン (/session-token) だけ
    assert_eq!(
        post_token(&server, Some(WIKI_ORIGIN), Some(&cookie), None).await,
        401
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
        post_token(&server, Some(&server.base), None, Some(&bearer)).await,
        401
    );
}

#[tokio::test]
async fn cookies_cannot_carry_api_tokens() {
    let server = start().await;
    for claims in [
        json!({ "id": "1", "username": "u", "can_edit": true, "purpose": "ai_connector", "exp": jwt::now() + 60 }),
        json!({ "id": "1", "username": "u", "can_edit": true, "type": "mcp_access_token", "exp": jwt::now() + 60 }),
    ] {
        let cookie = format!("__Host-toro_session={}", token_for(claims));
        let me: Value = server
            .get_with_cookie("/session", &cookie)
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
            .get_with_cookie("/session", &format!("{name}={value}"))
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(me["authenticated"], false, "{name}");
    }
}

#[tokio::test]
async fn session_cookie_is_host_only() {
    let server = start().await;
    let start = server.get("/login").await;
    let state = query_param(&location(&start), "state").unwrap();
    let nonce_set_cookie = set_cookies(&start);
    assert!(nonce_set_cookie[0].starts_with("__Host-toro_login_nonce="));
    assert!(nonce_set_cookie[0].contains("Path=/;"));
    assert!(!nonce_set_cookie[0].contains("Domain"));

    let nonce = cookie_pair(&nonce_set_cookie, "__Host-toro_login_nonce").unwrap();
    let res = server
        .get_with_cookie(
            &format!(
                "/callback?code=member&state={}",
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
    assert!(cookies.iter().all(|c| !c.contains("Domain")));
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
        assert!(page.contains("要求元: 未確認:"), "{redirect}");
        assert!(page.contains("トークンの送り先: https://"), "{redirect}");
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
    assert!(page.contains("要求元: Claude"));
}

#[tokio::test]
async fn other_google_hosts_are_not_gemini_and_need_pkce() {
    let server = start().await;
    for redirect in [
        "https://sites.google.com/view/x",
        "https://docs.google.com/x",
        "https://gemini.google.com/cb",
    ] {
        // PKCE なしは断る
        let res = server
            .get(&format!(
                "/oauth/authorize?redirect_uri={}",
                encode_uri_component(redirect)
            ))
            .await;
        assert_eq!(res.status(), 400, "{redirect}");
    }
    // 名前を出すのは、決まったホストだけ
    let page = server
        .get(&authorize_path("https://sites.google.com/view/x", "gemini"))
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("要求元: 未確認:"));
    let page = server
        .get(&authorize_path("https://gemini.google.com/cb", "x"))
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("要求元: Google Gemini"));
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
    assert_eq!(page.matches("連携を承認する").count(), 1);
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
    assert!(page.contains("Discord でログイン"));
    assert!(!page.contains("consent="));
}

#[tokio::test]
async fn introspection_passes_the_scope_through_and_refuses_the_rest() {
    let server = start().await;
    let token = |scope: &str| {
        token_for(json!({
            "id": "1", "sub": "1", "username": "u", "can_edit": true, "scope": scope,
            "exp": jwt::now() + 60,
        }))
    };
    // scope は、api / mcp が書き込みを許すかどうかを決める材料としてそのまま渡る
    let claims = server.introspect(&token("read")).await.unwrap();
    assert_eq!(claims["scope"], "read");
    assert_eq!(claims["can_edit"], true);

    // 認可コード、リフレッシュトークン、期限切れ、別の鍵で署名したものは通らない
    for rejected in [
        token_for(json!({ "id": "1", "type": "oauth_code", "exp": jwt::now() + 60 })),
        token_for(json!({ "id": "1", "type": "mcp_refresh_token", "exp": jwt::now() + 60 })),
        token_for(json!({ "id": "1", "username": "u", "exp": jwt::now() - 1 })),
        jwt::sign(&json!({ "id": "1", "username": "u" }), "another-secret"),
        "garbage".to_string(),
    ] {
        assert!(server.introspect(&rejected).await.is_none(), "{rejected}");
    }
}
#[tokio::test]
async fn consent_page_shows_the_requested_scope() {
    let server = start().await;
    let path = format!("{}&scope=read", authorize_path("https://a.example/cb", "x"));
    let page = server.get(&path).await.text().await.unwrap();
    assert!(page.contains("求める権限: read"));
    assert!(page.contains("Wiki の編集は求めていません"));
    assert!(!page.contains("Wiki の編集と保存"));
    assert!(!page.contains("{{"));

    let path = format!("{}&scope=mcp", authorize_path("https://a.example/cb", "x"));
    let page = server.get(&path).await.text().await.unwrap();
    assert!(page.contains("Wiki の編集と保存"));
}

#[tokio::test]
async fn consent_page_says_what_admins_also_grant() {
    let server = start().await;
    const ADMIN_LINE: &str = "Admin 以上のロールの人だけ: 荒らし対策の操作";
    let page_for = |scope: Option<&str>| {
        let mut path = authorize_path("https://a.example/cb", "x");
        if let Some(scope) = scope {
            path.push_str(&format!("&scope={}", encode_uri_component(scope)));
        }
        let request = server.client.get(server.url(&path));
        async move { request.send().await.unwrap().text().await.unwrap() }
    };

    // mcp を求めるときは書く。scope を省くと既定の read write mcp になるので、同じ
    for scope in [Some("mcp"), Some("read write mcp"), None] {
        let page = page_for(scope).await;
        assert!(page.contains(ADMIN_LINE), "{scope:?}");
        assert!(page.contains("Discord ボットの操作"), "{scope:?}");
        assert!(!page.contains("{{"), "{scope:?}");
    }
    for scope in ["read", "read write", "mcpx", ""] {
        let page = page_for(Some(scope)).await;
        assert!(!page.contains(ADMIN_LINE), "{scope:?}");
        assert!(!page.contains("{{"), "{scope:?}");
    }
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
    assert!(res.text().await.unwrap().contains("要求元: Google Gemini"));

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
    for path in ["/", "/session"] {
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

    let image = server.get("/icon-512.png").await;
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
    assert!(csp(&logged_in).contains("font-src 'self'"));

    assert!(csp(&server.get("/").await).contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn every_page_has_a_content_security_policy() {
    let server = start().await;
    let csp = |res: &reqwest::Response| {
        res.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_string()
    };

    // トークンを出すトップページは、自分のスクリプトだけを動かす
    let cookie = server.login("member").await;
    let home = server.get_with_cookie("/", &cookie).await;
    let policy = csp(&home);
    assert!(policy.contains("default-src 'none'"));
    assert!(policy.contains("script-src 'self'"));
    assert!(policy.contains("connect-src 'self'"));
    assert!(policy.contains("frame-ancestors 'none'"));
    assert!(!policy.contains("'unsafe-inline'"));
    assert!(!home.text().await.unwrap().contains(" style="));

    // スクリプトを持たない画面
    let guest = server
        .get(&authorize_path("https://a.example/cb", "x"))
        .await;
    let denied = server
        .get(&format!(
            "{}&denied=1",
            authorize_path("https://a.example/cb", "x")
        ))
        .await;
    let invalid = server.get("/oauth/authorize").await;
    let logout = server
        .client
        .get(server.url("/logout"))
        .header(header::ACCEPT, "text/html")
        .send()
        .await
        .unwrap();
    let error = server
        .client
        .get(server.url("/callback"))
        .header(header::ACCEPT, "text/html")
        .send()
        .await
        .unwrap();
    for res in [&guest, &denied, &invalid, &logout, &error] {
        let policy = csp(res);
        assert!(policy.contains("default-src 'none'"), "{}", res.url());
        assert!(!policy.contains("script-src"), "{}", res.url());
    }
}

#[tokio::test]
async fn internal_errors_do_not_reach_the_client() {
    // Discord につながらないときの理由は、ログにだけ残す
    let server = start_with(|cfg| cfg.discord_api = "http://127.0.0.1:9".into()).await;
    let start = server.get("/login").await;
    let state = encode_uri_component(&query_param(&location(&start), "state").unwrap());
    let nonce = cookie_pair(&set_cookies(&start), "__Host-toro_login_nonce").unwrap();
    let res = server
        .get_with_cookie(&format!("/callback?code=member&state={state}"), &nonce)
        .await;
    assert_eq!(res.status(), 500);
    assert_eq!(
        res.json::<Value>().await.unwrap(),
        json!({ "error": "Internal Server Error" })
    );
}

#[tokio::test]
async fn health_checks_answer_even_when_every_slot_is_taken() {
    use tokio::io::AsyncWriteExt;
    let server = start().await;
    let address = server.base.strip_prefix("http://").unwrap();
    // ボディを送らないまま待つ接続で、同時処理の枠 (256) をすべて埋める
    let mut streams = Vec::new();
    for _ in 0..256 {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"POST /oauth/token HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n")
            .await
            .unwrap();
        streams.push(stream);
    }
    let busy = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let res = server.get("/nope").await;
            if res.status() == 503 {
                return res;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(busy.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(busy.headers()[header::CACHE_CONTROL], "no-store");

    let health = server.get("/healthz").await;
    assert_eq!(health.status(), 200);
    assert_eq!(health.headers()[header::CACHE_CONTROL], "no-store");
    drop(streams);
}

#[tokio::test]
async fn slow_bodies_are_cut_off_and_the_slot_comes_back() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = start_with(|cfg| cfg.body_read_timeout_secs = 1).await;
    let address = server.base.strip_prefix("http://").unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    // 宣言した長さのボディを送らないまま待つ
    stream
        .write_all(b"POST /oauth/token HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n")
        .await
        .unwrap();
    let mut head = [0u8; 12];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut head),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&head, b"HTTP/1.1 408");
    assert_eq!(server.get("/healthz").await.status(), 200);
}

#[tokio::test]
async fn large_bodies_are_refused() {
    let server = start().await;
    let res = server
        .client
        .post(server.url("/oauth/token"))
        .body(vec![b'x'; 2 * 1024 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 413);
}
