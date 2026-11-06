//! AI クライアント向けの OAuth 2.0 の流れ

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};
use toro_auth::jwt;
use toro_auth::util::{encode_uri_component, sha256_base64url};

const CLIENT_REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier";

fn authorize_path(redirect_uri: &str, extra: &str) -> String {
    let challenge = sha256_base64url(VERIFIER.as_bytes());
    format!(
        "/oauth/authorize?client_id=toro-ai-1&response_type=code&scope=mcp&state=st%20ate&code_challenge={challenge}&code_challenge_method=S256&redirect_uri={}{extra}",
        encode_uri_component(redirect_uri)
    )
}

/// 同意画面の HTML から、承認のリンクを取り出す
fn approve_link(page: &str) -> String {
    let start = page
        .find("/oauth/authorize?")
        .unwrap_or_else(|| panic!("no authorize link: {page}"));
    let approve = page[start..].split('"').next().unwrap();
    assert!(approve.contains("consent="), "{approve}");
    approve.replace("&amp;", "&")
}

/// ログインして同意し、認可コードを受け取る
async fn get_code(server: &TestServer, cookie: &str) -> String {
    let page = server
        .get_with_cookie(&authorize_path(CLIENT_REDIRECT, ""), cookie)
        .await
        .text()
        .await
        .unwrap();
    let res = server.get_with_cookie(&approve_link(&page), cookie).await;
    assert_eq!(res.status(), 302);
    let target = location(&res);
    assert!(target.starts_with(CLIENT_REDIRECT), "{target}");
    assert_eq!(query_param(&target, "state").unwrap(), "st ate");
    query_param(&target, "code").unwrap()
}

async fn token_request(server: &TestServer, params: &[(&str, &str)]) -> reqwest::Response {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    server
        .client
        .post(server.url("/oauth/token"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap()
}

async fn exchange(server: &TestServer, code: &str) -> reqwest::Response {
    token_request(
        server,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", "toro-ai-1"),
            ("code_verifier", VERIFIER),
        ],
    )
    .await
}

#[tokio::test]
async fn metadata_is_served() {
    let server = start().await;
    let meta: Value = server
        .get("/.well-known/oauth-authorization-server")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(meta["issuer"], server.base);
    assert_eq!(
        meta["token_endpoint"],
        format!("{}/oauth/token", server.base)
    );
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));

    let openid: Value = server
        .get("/.well-known/openid-configuration")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(openid, meta);
}

#[tokio::test]
async fn dynamic_client_registration() {
    let server = start().await;
    let res = server
        .client
        .post(server.url("/oauth/register"))
        .json(&json!({ "client_name": "Claude", "redirect_uris": [CLIENT_REDIRECT] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let body: Value = res.json().await.unwrap();
    assert!(body["client_id"].as_str().unwrap().starts_with("toro-ai-"));
    assert_eq!(body["client_name"], "Claude");
    assert_eq!(body["redirect_uris"], json!([CLIENT_REDIRECT]));

    // 空のボディでも登録できる
    let res = server
        .client
        .post(server.url("/oauth/register"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.json::<Value>().await.unwrap()["client_name"],
        "AI Client"
    );
}

#[tokio::test]
async fn full_flow_from_guest_to_refresh() {
    let server = start().await;

    // 未ログイン: ログインのリンクが出て、戻り先が見える
    let page = server
        .get(&authorize_path(CLIENT_REDIRECT, ""))
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("Discord でログイン"));
    assert!(page.contains("トークンの送り先: https://claude.ai"));
    assert!(!page.contains("consent="));
    assert!(!page.contains("{{"));

    // ログインすると同意画面へ戻る
    let authorize_url = server.url(&authorize_path(CLIENT_REDIRECT, ""));
    let (cookie, back) = server.login_to("member", &authorize_url).await;
    assert_eq!(
        url::Url::parse(&back).unwrap(),
        url::Url::parse(&authorize_url).unwrap()
    );

    // ログイン直後にコードを出さず、承認を待つ
    let res = server
        .get_with_cookie(&authorize_path(CLIENT_REDIRECT, ""), &cookie)
        .await;
    assert_eq!(res.status(), 200);
    assert!(res.text().await.unwrap().contains("連携を承認する"));

    let code = get_code(&server, &cookie).await;
    let res = exchange(&server, &code).await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let tokens: Value = res.json().await.unwrap();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 30 * 86400);
    assert_eq!(tokens["scope"], "mcp");
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();

    let claims = jwt::verify(access, JWT_SECRET).unwrap();
    assert_eq!(claims["type"], "mcp_access_token");
    assert_eq!(claims["aud"], "toro-ai-1");
    assert_eq!(claims["id"], "1001");

    // アクセストークンで使える
    let info: Value = server
        .client
        .get(server.url("/oauth/userinfo"))
        .bearer_auth(access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["sub"], "1001");
    assert_eq!(info["email"], "1001@discord.torosaba.net");
    let claims = server.introspect(access).await.unwrap();
    assert_eq!(claims["username"], "member_user");

    // リフレッシュ
    let res = token_request(
        &server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", "toro-ai-1"),
        ],
    )
    .await;
    assert_eq!(res.status(), 200);
    let renewed: Value = res.json().await.unwrap();
    // リフレッシュのたびに、新しいリフレッシュトークンが返る (使っている間は続くように)。新しいほうでも、もう一度リフレッシュできる
    let renewed_refresh = renewed["refresh_token"].as_str().unwrap();
    assert_eq!(
        token_request(
            &server,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", renewed_refresh),
                ("client_id", "toro-ai-1")
            ]
        )
        .await
        .status(),
        200
    );
    let claims = server
        .introspect(renewed["access_token"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(claims["username"], "member_user");
}

#[tokio::test]
async fn token_endpoint_accepts_json_bodies() {
    let server = start().await;
    let cookie = server.login("member").await;
    let code = get_code(&server, &cookie).await;
    let res = server
        .client
        .post(server.url("/oauth/token"))
        .json(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": VERIFIER,
            "redirect_uri": CLIENT_REDIRECT,
            "client_id": "toro-ai-1",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn links_without_a_signed_consent_never_issue_a_code() {
    let server = start().await;
    let cookie = server.login("member").await;
    for extra in [
        "&approved=1",
        "&auto=1",
        "&consent=forged",
        "&consent=a.b.c",
    ] {
        let res = server
            .get_with_cookie(&authorize_path("https://evil.example/cb", extra), &cookie)
            .await;
        assert_eq!(res.status(), 200, "{extra}");
        assert!(res.headers().get(header::LOCATION).is_none(), "{extra}");
    }
}

#[tokio::test]
async fn consent_is_bound_to_the_request_and_the_user() {
    let server = start().await;
    let cookie = server.login("member").await;
    let page = server
        .get_with_cookie(&authorize_path(CLIENT_REDIRECT, ""), &cookie)
        .await
        .text()
        .await
        .unwrap();
    let approve = approve_link(&page);

    // 戻り先を差し替えたら無効
    let original_query = url::Url::parse(&format!("http://x{approve}")).unwrap();
    let mut tampered_query = original_query.clone();
    tampered_query
        .query_pairs_mut()
        .clear()
        .extend_pairs(original_query.query_pairs().map(|(k, v)| {
            if k == "redirect_uri" {
                (k, "https://evil.example/cb".into())
            } else {
                (k, v)
            }
        }));
    let tampered = format!("/oauth/authorize?{}", tampered_query.query().unwrap());
    assert_eq!(
        tampered_query
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .unwrap()
            .1,
        "https://evil.example/cb"
    );
    let res = server.get_with_cookie(&tampered, &cookie).await;
    assert_eq!(res.status(), 200);
    assert!(res.headers().get(header::LOCATION).is_none());

    // 他の人のセッションでは無効
    let other = server.login("other").await;
    let res = server.get_with_cookie(&approve, &other).await;
    assert_eq!(res.status(), 200);
    assert!(res.headers().get(header::LOCATION).is_none());

    // ログインしていなければ無効
    let res = server.get(&approve).await;
    assert_eq!(res.status(), 200);
    assert!(res.headers().get(header::LOCATION).is_none());

    // 本人なら有効
    assert_eq!(
        server.get_with_cookie(&approve, &cookie).await.status(),
        302
    );

    // 一度使った consent は再利用できない (ワンタイム性)
    assert_eq!(
        server.get_with_cookie(&approve, &cookie).await.status(),
        200
    );
}

#[tokio::test]
async fn browser_prefetches_do_not_approve() {
    let server = start().await;
    let cookie = server.login("member").await;
    let page = server
        .get_with_cookie(&authorize_path(CLIENT_REDIRECT, ""), &cookie)
        .await
        .text()
        .await
        .unwrap();
    let approve = approve_link(&page);

    for (name, value) in [
        ("sec-purpose", "prefetch"),
        ("sec-purpose", "prefetch;prerender"),
        ("purpose", "prefetch"),
    ] {
        let res = server
            .client
            .get(server.url(&approve))
            .header(header::COOKIE, &cookie)
            .header(name, value)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{name}: {value}");
        assert!(res.headers().get(header::LOCATION).is_none());
    }

    // 先読みでは consent を使い切らないので、本人が押せば通る
    assert_eq!(
        server.get_with_cookie(&approve, &cookie).await.status(),
        302
    );
}

#[tokio::test]
async fn codes_can_be_used_once() {
    let server = start().await;
    let cookie = server.login("member").await;
    let code = get_code(&server, &cookie).await;
    assert_eq!(exchange(&server, &code).await.status(), 200);

    let res = exchange(&server, &code).await;
    assert_eq!(res.status(), 400);
    assert_eq!(res.json::<Value>().await.unwrap()["error"], "invalid_grant");
}

#[tokio::test]
async fn pkce_is_enforced() {
    let server = start().await;
    let cookie = server.login("member").await;
    let code = get_code(&server, &cookie).await;

    let without = token_request(
        &server,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", "toro-ai-1"),
        ],
    )
    .await;
    assert_eq!(without.status(), 400);
    assert_eq!(
        without.json::<Value>().await.unwrap()["error_description"],
        "PKCE verification failed"
    );

    let wrong = token_request(
        &server,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", "toro-ai-1"),
            ("code_verifier", "x"),
        ],
    )
    .await;
    assert_eq!(wrong.status(), 400);

    // 失敗してもコードは残る
    assert_eq!(exchange(&server, &code).await.status(), 200);
}

#[tokio::test]
async fn code_must_match_redirect_uri_and_client() {
    let server = start().await;
    let cookie = server.login("member").await;
    let code = get_code(&server, &cookie).await;

    let res = token_request(
        &server,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://evil.example/"),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(
        res.json::<Value>().await.unwrap()["error_description"],
        "redirect_uri mismatch"
    );

    // redirect_uri 省略時も拒絶されること (RFC 6749)
    let res = token_request(
        &server,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(
        res.json::<Value>().await.unwrap()["error_description"],
        "redirect_uri mismatch"
    );

    let res = token_request(
        &server,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", "other"),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(
        res.json::<Value>().await.unwrap()["error_description"],
        "client_id mismatch"
    );
}

#[tokio::test]
async fn only_access_tokens_work_as_bearer() {
    let server = start().await;
    let cookie = server.login("member").await;
    let code = get_code(&server, &cookie).await;
    let tokens: Value = exchange(&server, &code).await.json().await.unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();

    for token in [refresh, code.as_str()] {
        let me: Value = server
            .client
            .get(server.url("/session"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(me["authenticated"], false);
        let res = server
            .client
            .get(server.url("/oauth/userinfo"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401);
    }

    // アクセストークンはリフレッシュトークンの代わりにならない
    let access = tokens["access_token"].as_str().unwrap();
    let res = token_request(
        &server,
        &[("grant_type", "refresh_token"), ("refresh_token", access)],
    )
    .await;
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn token_endpoint_errors() {
    let server = start().await;
    let res = token_request(&server, &[("grant_type", "password")]).await;
    assert_eq!(
        res.json::<Value>().await.unwrap()["error"],
        "unsupported_grant_type"
    );
    let res = token_request(&server, &[("grant_type", "authorization_code")]).await;
    assert_eq!(
        res.json::<Value>().await.unwrap()["error"],
        "invalid_request"
    );
    let res = token_request(
        &server,
        &[("grant_type", "authorization_code"), ("code", "nope")],
    )
    .await;
    assert_eq!(res.json::<Value>().await.unwrap()["error"], "invalid_grant");
}

#[tokio::test]
async fn userinfo_requires_a_bearer_token() {
    let server = start().await;
    assert_eq!(server.get("/oauth/userinfo").await.status(), 401);
    // セッションのトークンには sub が無い
    let cookie = server.login("member").await;
    let token = cookie.strip_prefix("__Host-toro_session=").unwrap();
    let res = server
        .client
        .get(server.url("/oauth/userinfo"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn denial_page_offers_the_way_back_with_an_error() {
    let server = start().await;
    let res = server
        .get(&authorize_path(CLIENT_REDIRECT, "&denied=1"))
        .await;
    assert_eq!(res.status(), 403);
    let page = res.text().await.unwrap();
    assert!(page.contains("連携を拒否しました"));
    assert!(page.contains("https://claude.ai/api/mcp/auth_callback?error=access_denied"));
    assert!(!page.contains("{{"));
}

#[tokio::test]
async fn bad_redirect_uris_are_refused() {
    let server = start().await;
    let res = server.get("/oauth/authorize?client_id=x").await;
    assert_eq!(res.status(), 400);
    for bad in [
        "javascript:alert(1)",
        "data:text/html,x",
        "http://evil.example/cb",
        "not a url",
    ] {
        let res = server.get(&authorize_path(bad, "")).await;
        assert_eq!(res.status(), 400, "{bad}");
        assert!(!res.text().await.unwrap().contains("{{"));
    }
}

#[tokio::test]
async fn client_id_is_escaped() {
    let server = start().await;
    let path = format!(
        "/oauth/authorize?code_challenge=abc&code_challenge_method=S256&redirect_uri={}&client_id={}",
        encode_uri_component("https://a.example/cb"),
        encode_uri_component("<script>alert(1)</script>")
    );
    let page = server.get(&path).await.text().await.unwrap();
    assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!page.contains("<script>alert"));
}

#[tokio::test]
async fn expired_consent_is_refused() {
    let server = start().await;
    let cookie = server.login("member").await;
    let expired = jwt::sign(
        &json!({ "type": "oauth_consent", "sub": "1001", "request": "x", "exp": jwt::now() - 1 }),
        JWT_SECRET,
    );
    let extra = format!("&consent={}", encode_uri_component(&expired));
    let res = server
        .get_with_cookie(&authorize_path(CLIENT_REDIRECT, &extra), &cookie)
        .await;
    assert_eq!(res.status(), 200);
    assert!(res.headers().get(header::LOCATION).is_none());
}

// ---- 使っている間は続き、使わないと無効になる ----

use std::time::Duration;

async fn issue_tokens(server: &TestServer) -> (String, String) {
    let cookie = server.login("member").await;
    let code = get_code(server, &cookie).await;
    let tokens: Value = exchange(server, &code).await.json().await.unwrap();
    (
        tokens["access_token"].as_str().unwrap().to_string(),
        tokens["refresh_token"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn oauth_access_tokens_get_roles_too() {
    // OAuth のアクセストークンは roles が空で発行される。確認の窓口が、いまのロールを足す
    let server = start_with(|cfg| cfg.discord_bot_token = Some("bot-token".into())).await;
    let (access, _) = issue_tokens(&server).await;
    let claims = server.introspect(&access).await.unwrap();
    assert_eq!(claims["roles"], json!(["role-a", "role-b"]));
    assert_eq!(claims["roles_source"], "live");
}

#[tokio::test]
async fn oauth_tokens_lose_edit_rights_with_the_role() {
    // ロールを持っていたころに発行された OAuth のトークンでも、確認の窓口の答えはいまのロールで決まる
    let server = start_with(|cfg| {
        cfg.discord_bot_token = Some("bot-token".into());
        cfg.discord_required_role_id = Some("role-z".into());
    })
    .await;
    let (access, refresh) = issue_tokens(&server).await;
    for token in [access, renew_access_token(&server, &refresh).await] {
        let mut issued_earlier = jwt::verify(&token, JWT_SECRET).unwrap();
        issued_earlier.insert("can_edit".into(), json!(true));
        let token = jwt::sign(&Value::Object(issued_earlier), JWT_SECRET);
        let claims = server.introspect(&token).await.unwrap();
        assert_eq!(claims["roles_source"], "live");
        assert_eq!(claims["can_edit"], false);
    }
}

async fn renew_access_token(server: &TestServer, refresh: &str) -> String {
    let renewed: Value = refresh_with(server, refresh).await.json().await.unwrap();
    renewed["access_token"].as_str().unwrap().to_string()
}

async fn refresh_with(server: &TestServer, refresh: &str) -> reqwest::Response {
    token_request(
        server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", "toro-ai-1"),
        ],
    )
    .await
}

#[tokio::test]
async fn refreshed_tokens_keep_the_scope_and_the_client() {
    let server = start().await;
    let (_, refresh) = issue_tokens(&server).await;

    let res = token_request(
        &server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", "other-client"),
        ],
    )
    .await;
    assert_eq!(res.status(), 400);
    assert_eq!(
        res.json::<Value>().await.unwrap()["error_description"],
        "client_id mismatch"
    );

    // client_id を付けない更新は、トークンがクライアントに結び付いている限り拒否する
    let res = token_request(
        &server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ],
    )
    .await;
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "client_id mismatch");

    let res = token_request(
        &server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", "toro-ai-1"),
        ],
    )
    .await;
    assert_eq!(res.status(), 200);
    let renewed: Value = res.json().await.unwrap();
    let access = jwt::verify(renewed["access_token"].as_str().unwrap(), JWT_SECRET).unwrap();
    assert_eq!(access["scope"], "mcp");
    assert_eq!(access["aud"], "toro-ai-1");
    assert_eq!(access["type"], "mcp_access_token");
    assert_eq!(renewed["scope"], "mcp");
}

#[tokio::test]
async fn oversized_and_unreadable_requests_are_refused_before_the_consent_page() {
    let server = start().await;
    let target = encode_uri_component(CLIENT_REDIRECT);
    let challenge = sha256_base64url(VERIFIER.as_bytes());
    let base = format!(
        "/oauth/authorize?code_challenge={challenge}&code_challenge_method=S256&redirect_uri={target}"
    );
    for query in [
        format!("{base}&client_id={}", "x".repeat(257)),
        format!("{base}&scope={}", "x".repeat(257)),
        format!("{base}&scope={}", encode_uri_component("読む")),
        format!(
            "/oauth/authorize?code_challenge={}&code_challenge_method=S256&redirect_uri={target}",
            "x".repeat(129)
        ),
        format!(
            "/oauth/authorize?code_challenge={challenge}&code_challenge_method=S256&redirect_uri={}",
            encode_uri_component(&format!("{CLIENT_REDIRECT}?a={}", "x".repeat(2048)))
        ),
    ] {
        let res = server.get(&query).await;
        assert_eq!(res.status(), 400, "{query}");
    }
}

#[tokio::test]
async fn login_continues_while_used_and_ends_after_idling() {
    // 使わないまま 2 秒を過ぎたら無効。1.1 秒おきに使えば、合計が 2 秒を超えても続く
    let server = start_with(|cfg| cfg.oauth_idle_seconds = 2).await;
    let (access, refresh) = issue_tokens(&server).await;
    for round in 1..=3 {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(server.introspect(&access).await.is_some(), "round {round}");
    }
    // 使わずに置く
    tokio::time::sleep(Duration::from_millis(3200)).await;
    assert!(server.introspect(&access).await.is_none());
    // リフレッシュトークンも通らない (もう一度ログインして連携する)
    let res = refresh_with(&server, &refresh).await;
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("not used")
    );
    // 無効になった連携は、あとから使っても戻らない
    assert!(server.introspect(&access).await.is_none());
}

#[tokio::test]
async fn refreshing_keeps_the_grant_alive_without_other_use() {
    let server = start_with(|cfg| cfg.oauth_idle_seconds = 2).await;
    let (access, mut refresh) = issue_tokens(&server).await;
    let gid = jwt::verify(&access, JWT_SECRET).unwrap()["gid"].clone();
    assert!(gid.as_str().is_some_and(|g| g.len() == 32), "{gid}");
    let mut last_access = access;
    // アクセストークンは使わず、リフレッシュだけを続ける (合計 3.3 秒 > 2 秒)
    for round in 1..=3 {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let res = refresh_with(&server, &refresh).await;
        assert_eq!(res.status(), 200, "round {round}");
        let renewed: Value = res.json().await.unwrap();
        refresh = renewed["refresh_token"].as_str().unwrap().to_string();
        last_access = renewed["access_token"].as_str().unwrap().to_string();
        assert_eq!(jwt::verify(&last_access, JWT_SECRET).unwrap()["gid"], gid);
        assert_eq!(jwt::verify(&refresh, JWT_SECRET).unwrap()["gid"], gid);
    }
    assert!(server.introspect(&last_access).await.is_some());
}

#[tokio::test]
async fn tokens_without_a_grant_are_refused() {
    let server = start().await;
    let now = jwt::now();
    // gid を持たない昔のトークン
    let legacy_access = jwt::sign(
        &json!({
            "sub": "1001", "id": "1001", "username": "member_user", "can_edit": true, "roles": [],
            "scope": "mcp", "type": "mcp_access_token", "iat": now, "exp": now + 3600,
        }),
        JWT_SECRET,
    );
    let legacy_refresh = jwt::sign(
        &json!({
            "sub": "1001", "id": "1001", "username": "member_user", "can_edit": true,
            "scope": "mcp", "type": "mcp_refresh_token", "iat": now, "exp": now + 3600,
        }),
        JWT_SECRET,
    );
    assert!(server.introspect(&legacy_access).await.is_none());
    // リフレッシュも通らない (もう一度ログインして連携する)
    let res = refresh_with(&server, &legacy_refresh).await;
    assert_eq!(res.status(), 400);
    assert_eq!(res.json::<Value>().await.unwrap()["error"], "invalid_grant");
}

#[tokio::test]
async fn omitted_scope_defaults_to_read_only() {
    let server = start().await;
    let cookie = server.login("member").await;
    let challenge = sha256_base64url(VERIFIER.as_bytes());
    let path = format!(
        "/oauth/authorize?client_id=toro-ai-1&response_type=code&state=st%20ate&code_challenge={challenge}&code_challenge_method=S256&redirect_uri={}",
        encode_uri_component(CLIENT_REDIRECT)
    );

    // 同意画面でも、求める権限は読み取りだけと出る
    let page = server
        .get_with_cookie(&path, &cookie)
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("求める権限: read"), "{page}");
    assert!(!page.contains("Wiki の編集と保存"), "{page}");

    let res = server.get_with_cookie(&approve_link(&page), &cookie).await;
    assert_eq!(res.status(), 302);
    let code = query_param(&location(&res), "code").unwrap();

    let res = exchange(&server, &code).await;
    assert_eq!(res.status(), 200);
    let tokens: Value = res.json().await.unwrap();
    assert_eq!(tokens["scope"], "read");

    // リフレッシュで権限が広がることもない
    let res = token_request(
        &server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("client_id", "toro-ai-1"),
        ],
    )
    .await;
    assert_eq!(res.status(), 200);
    let renewed: Value = res.json().await.unwrap();
    assert_eq!(renewed["scope"], "read");
}

#[tokio::test]
async fn a_lost_grant_record_invalidates_the_tokens() {
    // 連携の記録が無い (失った・偽の) gid のトークンは、署名が正しくても通さない
    let server = start().await;
    let now = jwt::now();
    let token = jwt::sign(
        &json!({
            "sub": "1001", "id": "1001", "username": "member_user", "can_edit": true, "roles": [],
            "scope": "mcp", "type": "mcp_access_token", "gid": "00000000000000000000000000000000",
            "iat": now, "exp": now + 3600,
        }),
        JWT_SECRET,
    );
    assert!(server.introspect(&token).await.is_none());
}
