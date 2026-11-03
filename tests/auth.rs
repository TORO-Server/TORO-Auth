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
    assert!(res.text().await.unwrap().contains("SESSION TERMINATED"));
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

    let token = body["token"].as_str().unwrap();
    assert_eq!(body["connectors"]["chatgpt"]["token"], token);
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
    assert!(guest.contains("AUTH SESSION: GUEST"));
    assert!(guest.contains("/api/auth/login"));
    assert!(!guest.contains("{{"));

    let cookie = server.login("xss").await;
    let page = server
        .get_with_cookie("/", &cookie)
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains("AUTH SESSION: ACTIVE"));
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

#[tokio::test]
async fn openapi_uses_the_request_host_for_known_hosts_only() {
    let server = start().await;
    let spec = |host: &'static str| {
        let client = server.client.clone();
        let url = server.url("/api/openapi.json");
        async move {
            client
                .get(url)
                .header(header::HOST, host)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    assert_eq!(
        spec("auth.torosaba.net").await["servers"][0]["url"],
        "https://auth.torosaba.net"
    );
    assert_eq!(spec("evil.example").await["servers"][0]["url"], server.base);
    assert_eq!(
        spec("auth.torosaba.net").await["paths"]["/api/docs/save"]["post"]["operationId"],
        "saveWikiDoc"
    );
}
