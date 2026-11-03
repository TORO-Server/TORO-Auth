//! Discord ログイン、セッション、API トークン、CORS、トップページ

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};
use toro_auth::jwt;
use toro_auth::util::encode_uri_component;

#[tokio::test]
async fn login_sets_session_and_returns_to_the_requested_page() {
    let server = start().await;
    let (cookie, target) = server
        .login_to("member", "https://wiki.torosaba.net/foo?x=1")
        .await;
    assert_eq!(target, "https://wiki.torosaba.net/foo?x=1");

    let me: Value = server
        .get_with_cookie("/api/auth/me", &cookie)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me["authenticated"], true);
    assert_eq!(me["user"]["id"], "1001");
    assert_eq!(me["user"]["username"], "member_user");
    assert_eq!(me["user"]["can_edit"], true);
    assert_eq!(me["user"]["roles"], json!(["role-a", "role-b"]));
    assert_eq!(
        me["user"]["avatar_url"],
        "https://cdn.discordapp.com/avatars/1001/abc.png"
    );
}

#[tokio::test]
async fn foreign_return_urls_fall_back_to_the_wiki() {
    let server = start().await;
    for bad in [
        "https://evil.example/",
        "javascript://torosaba.net/%0aalert(1)",
        "http://wiki.torosaba.net/",
    ] {
        let (_, target) = server.login_to("member", bad).await;
        assert_eq!(target, "https://wiki.torosaba.net/", "{bad}");
    }
}

#[tokio::test]
async fn callback_requires_the_browser_that_started_the_login() {
    let server = start().await;
    let start = server.get("/api/auth/login").await;
    let state = encode_uri_component(&query_param(&location(&start), "state").unwrap());
    let path = format!("/api/auth/callback?code=member&state={state}");

    // Cookie なし (他人に踏ませたリンク)
    let res = server.get(&path).await;
    assert_eq!(res.status(), 400);
    assert!(
        set_cookies(&res)
            .iter()
            .all(|c| !c.starts_with("__Host-toro_session"))
    );

    // 別のログインの Cookie
    let res = server
        .get_with_cookie(&path, "__Host-toro_login_nonce=other")
        .await;
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn callback_rejects_forged_state() {
    let server = start().await;
    let forged = jwt::sign(
        &json!({ "type": "login_state", "redirect": "https://wiki.torosaba.net/", "nonce": "n", "exp": jwt::now() + 60 }),
        "wrong-key",
    );
    let res = server
        .get_with_cookie(
            &format!(
                "/api/auth/callback?code=member&state={}",
                encode_uri_component(&forged)
            ),
            "__Host-toro_login_nonce=n",
        )
        .await;
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn non_members_are_refused() {
    let server = start().await;
    let start = server.get("/api/auth/login").await;
    let state = encode_uri_component(&query_param(&location(&start), "state").unwrap());
    let nonce = cookie_pair(&set_cookies(&start), "__Host-toro_login_nonce").unwrap();

    let res = server
        .get_with_cookie(
            &format!("/api/auth/callback?code=outsider&state={state}"),
            &nonce,
        )
        .await;
    assert_eq!(res.status(), 403);
    assert!(
        set_cookies(&res)
            .iter()
            .all(|c| !c.starts_with("__Host-toro_session"))
    );
    assert!(res.text().await.unwrap().contains("ギルド未所属"));
}

#[tokio::test]
async fn discord_exchange_failure_is_reported() {
    let server = start().await;
    let start = server.get("/api/auth/login").await;
    let state = encode_uri_component(&query_param(&location(&start), "state").unwrap());
    let nonce = cookie_pair(&set_cookies(&start), "__Host-toro_login_nonce").unwrap();

    let res = server
        .get_with_cookie(
            &format!("/api/auth/callback?code=bad&state={state}"),
            &nonce,
        )
        .await;
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .starts_with("Failed to exchange Discord code")
    );
}

#[tokio::test]
async fn required_role_controls_can_edit() {
    let server = start_with(|cfg| cfg.discord_required_role_id = Some("role-z".into())).await;
    let cookie = server.login("member").await;
    let me: Value = server
        .get_with_cookie("/api/auth/me", &cookie)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me["user"]["can_edit"], false);

    let server = start_with(|cfg| cfg.discord_required_role_id = Some("role-b".into())).await;
    let cookie = server.login("member").await;
    let me: Value = server
        .get_with_cookie("/api/auth/me", &cookie)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me["user"]["can_edit"], true);
}

#[tokio::test]
async fn me_without_session() {
    let server = start().await;
    let res = server.get("/api/auth/me").await;
    assert_eq!(
        res.text().await.unwrap(),
        r#"{"authenticated":false,"user":null}"#
    );
}

#[tokio::test]
async fn logout_clears_cookies_in_both_formats() {
    let server = start().await;

    let res = server
        .client
        .post(server.url("/api/auth/logout"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await;
    let res = res.unwrap();
    assert!(
        set_cookies(&res)
            .iter()
            .any(|c| c.starts_with("__Host-toro_session=;") && c.contains("Max-Age=0"))
    );
    assert_eq!(res.json::<Value>().await.unwrap()["ok"], true);

    let res = server
        .client
        .get(server.url("/api/auth/logout"))
        .header(header::ACCEPT, "text/html")
        .send()
        .await;
    let res = res.unwrap();
    assert!(
        set_cookies(&res)
            .iter()
            .any(|c| c.starts_with("wiki_session=;"))
    );
    assert!(res.text().await.unwrap().contains("ログアウトしました"));
}

#[tokio::test]
async fn api_token_requires_post_and_session() {
    let server = start().await;
    assert_eq!(
        server
            .client
            .post(server.url("/api/auth/token"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    let cookie = server.login("member").await;
    // GET では発行しない (他のサイトからリンクで踏ませない)
    assert_eq!(
        server
            .get_with_cookie("/api/auth/token", &cookie)
            .await
            .status(),
        405
    );

    let res = server
        .client
        .post(server.url("/api/auth/token"))
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, WIKI_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert!(body["expires_at"].as_str().unwrap().ends_with(".000Z"));
    // トークンを返すのは 1 か所だけ。接続先の案内などは Wiki の記事にある
    assert_eq!(body.as_object().unwrap().len(), 3);

    let token = body["token"].as_str().unwrap();
    let claims = jwt::verify(token, JWT_SECRET).unwrap();
    assert_eq!(claims["purpose"], "ai_connector");
    assert!(claims["exp"].as_i64().unwrap() > jwt::now() + 89 * 86400);

    // Bearer として使える
    let res = server
        .client
        .get(server.url("/api/auth/me"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.json::<Value>().await.unwrap()["user"]["id"], "1001");
}

async fn issue_token(server: &TestServer, cookie: &str) -> String {
    let res = server
        .client
        .post(server.url("/api/auth/token"))
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, WIKI_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let body: Value = res.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

async fn is_accepted(server: &TestServer, token: &str) -> bool {
    let me: Value = server
        .api_client
        .get(server.url("/me"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    me["authenticated"] == true
}

#[tokio::test]
async fn recreating_a_token_revokes_only_the_previous_one() {
    let server = start().await;
    let member = server.login("member").await;
    let other = server.login("other").await;

    let first = issue_token(&server, &member).await;
    let others = issue_token(&server, &other).await;
    assert!(is_accepted(&server, &first).await);

    let second = issue_token(&server, &member).await;
    assert_ne!(first, second);
    assert!(!is_accepted(&server, &first).await);
    assert!(is_accepted(&server, &second).await);
    // 他の人のトークン、ブラウザのセッション、短いトークンは巻き込まない
    assert!(is_accepted(&server, &others).await);
    assert!(
        server
            .get_with_cookie("/", &member)
            .await
            .text()
            .await
            .unwrap()
            .contains("ログイン中")
    );
    let short = server.session_token(&member).await;
    assert!(is_accepted(&server, &short).await);
}

#[tokio::test]
async fn connector_tokens_without_a_generation_are_rejected() {
    let server = start().await;
    let old = jwt::sign(
        &json!({
            "id": "1001", "username": "member_user", "can_edit": true,
            "purpose": "ai_connector", "exp": jwt::now() + 3600,
        }),
        JWT_SECRET,
    );
    assert!(!is_accepted(&server, &old).await);

    // 世代が記録と違うものも通らない
    let cookie = server.login("member").await;
    issue_token(&server, &cookie).await;
    let forged_generation = jwt::sign(
        &json!({
            "id": "1001", "username": "member_user", "can_edit": true, "generation": "guess",
            "purpose": "ai_connector", "exp": jwt::now() + 3600,
        }),
        JWT_SECRET,
    );
    assert!(!is_accepted(&server, &forged_generation).await);
}

#[tokio::test]
async fn token_is_never_shown_again_after_it_is_issued() {
    let server = start().await;
    let cookie = server.login("member").await;

    let before = server
        .get_with_cookie("/", &cookie)
        .await
        .text()
        .await
        .unwrap();
    assert!(before.contains("トークンを発行する"));
    assert!(before.contains("未発行"));

    let token = issue_token(&server, &cookie).await;
    for path in ["/", "/api/auth/me"] {
        let page = server
            .get_with_cookie(path, &cookie)
            .await
            .text()
            .await
            .unwrap();
        assert!(!page.contains(&token), "{path}");
    }

    let after = server
        .get_with_cookie("/", &cookie)
        .await
        .text()
        .await
        .unwrap();
    assert!(after.contains("トークンを再作成する"));
    assert!(after.contains("まで有効"));
    assert!(!after.contains("未発行"));
}

#[tokio::test]
async fn failing_to_save_the_record_issues_no_token() {
    let missing = std::env::temp_dir().join("toro-auth-test-does-not-exist");
    let server = start_with(|cfg| cfg.state_dir = missing.to_string_lossy().into_owned()).await;
    let cookie = server.login("member").await;
    let res = server
        .client
        .post(server.url("/api/auth/token"))
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, WIKI_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 500);
    let body: Value = res.json().await.unwrap();
    assert!(body.get("token").is_none());
}

#[tokio::test]
async fn cors_allows_credentials_only_for_our_origins() {
    let server = start().await;
    let origin = |o: &'static str| {
        let client = server.client.clone();
        let url = server.url("/api/auth/me");
        async move {
            client
                .get(url)
                .header(header::ORIGIN, o)
                .send()
                .await
                .unwrap()
        }
    };

    let res = origin("https://wiki.torosaba.net").await;
    assert_eq!(
        res.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://wiki.torosaba.net"
    );
    assert_eq!(
        res.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
        "true"
    );

    let res = origin("https://torosaba.net.evil.example").await;
    assert_eq!(res.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert!(
        res.headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none()
    );

    let res = server
        .client
        .request(reqwest::Method::OPTIONS, server.url("/api/docs/save"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);
    assert_eq!(res.headers()[header::ACCESS_CONTROL_MAX_AGE], "86400");
}

#[tokio::test]
async fn home_shows_guest_and_session_and_escapes_names() {
    let server = start().await;
    let guest = server.get("/").await.text().await.unwrap();
    assert!(guest.contains("未ログイン"));
    assert!(guest.contains("/api/auth/login"));
    assert!(!guest.contains("{{"));
    // ログインの情報のほかに、説明を置かない
    for extra in [
        "窓口",
        "場所",
        "OpenAPI",
        "mcp.torosaba.net",
        "api.torosaba.net",
    ] {
        assert!(!guest.contains(extra), "{extra}");
    }

    let member = server.login("member").await;
    let page = server
        .get_with_cookie("/", &member)
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("https://cdn.discordapp.com/avatars/1001/abc"));
    assert!(page.contains("referrerpolicy=\"no-referrer\""));
    for extra in [
        "窓口",
        "場所",
        "OpenAPI",
        "mcp.torosaba.net",
        "api.torosaba.net",
    ] {
        assert!(!page.contains(extra), "{extra}");
    }

    let cookie = server.login("xss").await;
    let page = server
        .get_with_cookie("/", &cookie)
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("ログイン中"));
    assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;"));
    assert!(!page.contains("<img src=x"));
    assert!(!page.contains("{{"));
}

#[tokio::test]
async fn unknown_paths_are_json_404() {
    let server = start().await;
    let res = server.get("/nope").await;
    assert_eq!(res.status(), 404);
    assert_eq!(
        res.json::<Value>().await.unwrap(),
        json!({ "error": "Not Found", "path": "/nope" })
    );
    assert_eq!(server.get("/healthz").await.status(), 200);
}
