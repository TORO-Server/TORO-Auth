//! 署名の鍵の分離、ログアウトによるセッションの失効、確認の窓口の共有秘密

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};
use toro_auth::jwt::{self, Kind};

async fn logout(server: &TestServer, cookie: &str) -> reqwest::Response {
    server
        .client
        .post(server.url("/logout"))
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, server.base.as_str())
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .unwrap()
}

async fn session_is_valid(server: &TestServer, cookie: &str) -> bool {
    let me: Value = server
        .get_with_cookie("/session", cookie)
        .await
        .json()
        .await
        .unwrap();
    me["authenticated"] == true
}

#[tokio::test]
async fn logging_out_revokes_the_session_everywhere() {
    let server = start().await;
    // 同じアカウントの 2 つの端末
    let first = server.login("member").await;
    let second = server.login("member").await;
    let short = server.introspect(&server.session_token(&first).await).await;
    assert!(short.is_some());
    assert!(session_is_valid(&server, &first).await);
    assert!(session_is_valid(&server, &second).await);

    // Cookie を残した (盗まれた) つもりで、ログアウトの前のセッションを控えておく
    let before = first.clone();
    let short_before = server.session_token(&first).await;
    assert_eq!(logout(&server, &first).await.status(), 200);

    assert!(
        !session_is_valid(&server, &before).await,
        "旧セッションが通る"
    );
    assert!(
        !session_is_valid(&server, &second).await,
        "別の端末のセッションが通る"
    );
    assert!(
        server.introspect(&short_before).await.is_none(),
        "旧セッションの API 用トークンが通る"
    );

    // もう一度ログインすれば使える。別のアカウントには影響しない
    let again = server.login("member").await;
    assert!(session_is_valid(&server, &again).await);
}

#[tokio::test]
async fn logging_out_does_not_touch_other_accounts() {
    let server = start().await;
    let member = server.login("member").await;
    let other = server.login("other").await;
    logout(&server, &member).await;
    assert!(!session_is_valid(&server, &member).await);
    assert!(session_is_valid(&server, &other).await);
}

#[tokio::test]
async fn logging_out_without_a_session_changes_nothing() {
    let server = start().await;
    let member = server.login("member").await;
    let res = server
        .client
        .post(server.url("/logout"))
        .header(header::ORIGIN, server.base.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert!(session_is_valid(&server, &member).await);
}

#[tokio::test]
async fn logout_get_and_foreign_post_do_not_revoke() {
    let server = start().await;
    let member = server.login("member").await;

    // 最上位の GET 遷移 (ブラウザでの閲覧) は確認画面を返すだけで、失効させない
    let get_html = server
        .client
        .get(server.url("/logout"))
        .header(header::COOKIE, &member)
        .header(header::ACCEPT, "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(get_html.status(), 200);
    assert!(set_cookies(&get_html).is_empty());
    let html = get_html.text().await.unwrap();
    assert!(html.contains(r#"method="post" action="/logout""#));
    assert!(session_is_valid(&server, &member).await);

    // HTML を受けない GET は 405
    let get_json = server
        .client
        .get(server.url("/logout"))
        .header(header::COOKIE, &member)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(get_json.status(), 405);
    assert!(session_is_valid(&server, &member).await);

    // Origin の無い POST や、別オリジン (サブドメインを含む) からの POST は拒否し、失効させない
    for origin in [None, Some("https://wiki.torosaba.net"), Some("https://evil.example")] {
        let mut req = server
            .client
            .post(server.url("/logout"))
            .header(header::COOKIE, &member);
        if let Some(origin) = origin {
            req = req.header(header::ORIGIN, origin);
        }
        let res = req.send().await.unwrap();
        assert_eq!(res.status(), 403, "{origin:?}");
        assert!(session_is_valid(&server, &member).await);
    }
}

#[tokio::test]
async fn sessions_without_a_generation_are_refused() {
    let server = start().await;
    let no_generation = jwt::sign(
        &json!({ "id": "1001", "username": "u", "can_edit": true, "exp": jwt::now() + 60 }),
        &key(Kind::Session),
    );
    assert!(server.introspect(&no_generation).await.is_none());
    let future_generation = jwt::sign(
        &json!({ "id": "1001", "username": "u", "sgen": 5, "exp": jwt::now() + 60 }),
        &key(Kind::Session),
    );
    assert!(server.introspect(&future_generation).await.is_none());
}

#[tokio::test]
async fn logging_out_keeps_ninety_day_tokens_and_oauth_grants() {
    let server = start().await;
    let cookie = server.login("member").await;
    let res = server
        .client
        .post(server.url("/token"))
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, server.base.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let connector = body["token"].as_str().unwrap().to_string();
    assert!(server.introspect(&connector).await.is_some());
    logout(&server, &cookie).await;
    // 90 日トークンは、再作成で失効させる別の仕組み。ログアウトでは変わらない
    assert!(server.introspect(&connector).await.is_some());
}

/// 1 つの種類の鍵で署名したトークンは、別の種類としては通らない
#[tokio::test]
async fn a_token_signed_with_another_kinds_key_is_refused() {
    let server = start().await;
    let now = jwt::now();
    let session_shape = json!({ "id": "1001", "username": "u", "sgen": 0, "exp": now + 60 });
    let connector_shape = json!({
        "id": "1001", "username": "u", "purpose": "ai_connector", "generation": "x", "exp": now + 60,
    });
    let access_shape = json!({
        "id": "1001", "username": "u", "type": "mcp_access_token", "gid": "0".repeat(32), "exp": now + 60,
    });
    for (shape, correct) in [
        (&session_shape, Kind::Session),
        (&connector_shape, Kind::Connector),
        (&access_shape, Kind::Access),
    ] {
        for signer in Kind::ALL {
            if signer == correct {
                continue;
            }
            let token = jwt::sign(shape, &key(signer));
            assert!(
                server.introspect(&token).await.is_none(),
                "{signer:?} の鍵で署名した {correct:?} の形のトークンが通った"
            );
        }
    }
    // 正しい鍵の session だけが通る (他の 2 つは、記録 (世代・連携) が無いので通らない)
    assert!(
        server
            .introspect(&jwt::sign(&session_shape, &key(Kind::Session)))
            .await
            .is_some()
    );
}

/// セッションの鍵で、OAuth の種類 (アクセス、リフレッシュ、認可コード) の形のトークンを作っても通らない
#[tokio::test]
async fn the_session_key_cannot_mint_other_kinds() {
    let server = start().await;
    let now = jwt::now();
    for kind_name in [
        "mcp_access_token",
        "mcp_refresh_token",
        "oauth_code",
        "oauth_consent",
        "login_state",
    ] {
        let token = jwt::sign(
            &json!({ "id": "1001", "username": "u", "sgen": 0, "type": kind_name, "gid": "0".repeat(32), "exp": now + 60 }),
            &key(Kind::Session),
        );
        assert!(server.introspect(&token).await.is_none(), "{kind_name}");
    }
    let purpose = jwt::sign(
        &json!({ "id": "1001", "username": "u", "sgen": 0, "purpose": "ai_connector", "generation": "x", "exp": now + 60 }),
        &key(Kind::Session),
    );
    assert!(server.introspect(&purpose).await.is_none());
}

async fn introspect_status(server: &TestServer, token: &str, secret: Option<&str>) -> u16 {
    let mut request = server
        .client
        .post(format!("{}/introspect", server.internal))
        .json(&json!({ "token": token }));
    if let Some(secret) = secret {
        request = request.header("X-Toro-Token", secret);
    }
    request.send().await.unwrap().status().as_u16()
}

const SECRET: &str = "introspect-secret-introspect-secret";

#[tokio::test]
async fn introspection_needs_the_shared_secret_when_one_is_set() {
    let server = start_with(|cfg| cfg.introspect_secret = Some(SECRET.into())).await;
    let cookie = server.login("member").await;
    let token = server.session_token(&cookie).await;

    assert_eq!(introspect_status(&server, &token, None).await, 401);
    assert_eq!(introspect_status(&server, &token, Some("wrong")).await, 401);
    assert_eq!(introspect_status(&server, &token, Some("")).await, 401);
    assert_eq!(
        introspect_status(&server, &token, Some(&SECRET[..SECRET.len() - 1])).await,
        401
    );
    assert_eq!(introspect_status(&server, &token, Some(SECRET)).await, 200);

    // 秘密を示した呼び出しは、これまでどおり中身を返す
    let res = server
        .client
        .post(format!("{}/introspect", server.internal))
        .header("X-Toro-Token", SECRET)
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["active"], true);
    // 稼働確認は、秘密なしで答える (healthcheck を壊さない)
    let health = server
        .client
        .get(format!("{}/healthz", server.internal))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
}

#[tokio::test]
async fn introspection_is_open_inside_the_network_while_no_secret_is_set() {
    let server = start().await;
    let cookie = server.login("member").await;
    let token = server.session_token(&cookie).await;
    assert_eq!(introspect_status(&server, &token, None).await, 200);
}
