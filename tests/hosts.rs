//! auth の役割の範囲、以前の URL の転送、api / mcp からのトークンの確認、URL の正本

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};
use toro_auth::jwt;

#[tokio::test]
async fn auth_does_not_serve_api_or_mcp() {
    let server = start().await;

    for path in ["/docs/raw?path=a", "/docs/list", "/me", "/docs/save"] {
        assert_eq!(server.get(path).await.status(), 404, "{path}");
    }
    // どのホストで来ても、答えるのは auth の役割だけ
    for host in ["api.torosaba.net", "mcp.torosaba.net"] {
        let res = server
            .client
            .get(server.url("/me"))
            .header(header::HOST, host)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 404, "{host}");
    }
}

#[tokio::test]
async fn old_urls_on_auth_move_to_the_right_host() {
    let server = start().await;
    for (old, new) in [
        ("/api/mcp", "https://mcp.torosaba.net/"),
        ("/mcp", "https://mcp.torosaba.net/"),
        ("/sse", "https://mcp.torosaba.net/"),
        ("/api/openapi.json", "https://api.torosaba.net/openapi.json"),
        ("/openapi.json", "https://api.torosaba.net/openapi.json"),
        ("/api/docs/save", "https://api.torosaba.net/docs/save"),
        (
            "/api/docs/raw?path=a%20b",
            "https://api.torosaba.net/docs/raw?path=a%20b",
        ),
        (
            "/.well-known/oauth-protected-resource",
            "https://mcp.torosaba.net/.well-known/oauth-protected-resource",
        ),
    ] {
        let res = server.get(old).await;
        assert_eq!(res.status(), 308, "{old}");
        assert_eq!(location(&res), new, "{old}");
    }

    // POST も 308 で届き、Wiki の画面からの転送が読めるよう CORS も付く
    let res = server
        .client
        .post(server.url("/api/docs/save"))
        .header(header::ORIGIN, WIKI_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 308);
    assert_eq!(
        res.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        WIKI_ORIGIN
    );
}

#[tokio::test]
async fn session_tokens_are_short_and_checked_by_introspection() {
    let server = start().await;
    let cookie = server.login("member").await;

    // Cookie は auth のもの。確認の窓口にはトークンそのものを渡す
    assert!(server.introspect(&cookie).await.is_none());

    let res = server
        .client
        .post(server.url("/session-token"))
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, WIKI_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    let issued: Value = res.json().await.unwrap();
    assert_eq!(issued["expires_in"], 600);
    let token = issued["token"].as_str().unwrap();
    let claims = jwt::verify(token, JWT_SECRET).unwrap();
    assert!(claims["exp"].as_i64().unwrap() <= jwt::now() + 600);

    let claims = server.introspect(token).await.unwrap();
    assert_eq!(claims["id"], "1001");
    assert_eq!(claims["username"], "member_user");
    assert_eq!(claims["can_edit"], true);
}

#[tokio::test]
async fn session_tokens_need_the_cookie_a_trusted_origin_and_post() {
    let server = start().await;
    let cookie = server.login("member").await;
    let path = server.url("/session-token");

    for origin in [Some("https://assets.torosaba.net"), None] {
        let mut request = server.client.post(&path).header(header::COOKIE, &cookie);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        assert_eq!(request.send().await.unwrap().status(), 401, "{origin:?}");
    }

    // 短いトークンから、新しいトークンは作れない
    let token = server.session_token(&cookie).await;
    let res = server
        .client
        .post(&path)
        .bearer_auth(&token)
        .header(header::ORIGIN, WIKI_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    let res = server
        .client
        .get(&path)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 405);
}

#[tokio::test]
async fn introspection_only_answers_on_the_internal_port() {
    let server = start().await;
    let internal = |path: &str| format!("{}{path}", server.internal);

    // 公開のポートには、確認の窓口がない
    let res = server
        .client
        .post(server.url("/introspect"))
        .json(&json!({ "token": "x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // 内側のポートは、確認の窓口と稼働確認だけ
    let res = server
        .client
        .get(internal("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    for path in ["/", "/session", "/oauth/token"] {
        let res = server.client.get(internal(path)).send().await.unwrap();
        assert_eq!(res.status(), 404, "{path}");
    }
}

#[tokio::test]
async fn introspection_validates_its_input() {
    let server = start().await;
    let url = format!("{}/introspect", server.internal);

    let res = server.client.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 405);

    for body in ["{broken", "{}", r#"{"token":1}"#] {
        let res = server.client.post(&url).body(body).send().await.unwrap();
        assert_eq!(res.status(), 400, "{body}");
    }

    let res = server
        .client
        .post(&url)
        .body(vec![b'x'; 17 * 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 413);

    let res = server
        .client
        .post(&url)
        .json(&json!({ "token": "garbage" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        res.json::<Value>().await.unwrap(),
        json!({ "active": false })
    );
}

#[tokio::test]
async fn pages_take_their_urls_from_the_config() {
    let server = start_with(|cfg| {
        cfg.mcp_url = "https://mcp.example.test".into();
        cfg.api_url = "https://api.example.test".into();
        cfg.wiki_url = "https://wiki.example.test".into();
    })
    .await;

    let home = server.get("/").await.text().await.unwrap();
    assert!(
        !home.contains("torosaba.net/"),
        "hard-coded URL in the home page"
    );
    assert!(!home.contains("{{"));

    let invalid = server.get("/oauth/authorize").await.text().await.unwrap();
    assert!(invalid.contains("https://wiki.example.test/wiki/"));
    assert!(!invalid.contains("{{"));

    // 以前の URL の転送先も、設定から作る
    let res = server.get("/mcp").await;
    assert_eq!(location(&res), "https://mcp.example.test/");
    let res = server.get("/api/docs/raw").await;
    assert_eq!(location(&res), "https://api.example.test/docs/raw");
}

#[tokio::test]
async fn asset_urls_change_with_each_version() {
    let server = start().await;
    let version = env!("CARGO_PKG_VERSION");
    let home = server.get("/").await.text().await.unwrap();
    assert!(home.contains(&format!("/_assets/auth.css?v={version}")));
    assert!(home.contains(&format!("/_assets/favicon.svg?v={version}")));
    assert!(home.contains(&format!("/_assets/token.js?v={version}")));
}

#[tokio::test]
async fn token_script_is_served_without_types() {
    let server = start().await;
    let script = server.get("/_assets/token.js").await.text().await.unwrap();
    assert!(script.contains("/token"));
    assert!(!script.contains("TokenResponse"));
    assert!(!script.contains("HTMLButtonElement"));
}

#[tokio::test]
async fn static_files_are_served_with_the_right_types() {
    let server = start().await;
    for (path, content_type) in [
        ("/_assets/auth.css", "text/css; charset=utf-8"),
        ("/_assets/token.js", "text/javascript; charset=utf-8"),
        ("/_assets/pixel.woff2", "font/woff2"),
        ("/_assets/favicon.svg", "image/svg+xml"),
        ("/_assets/OFL.txt", "text/plain; charset=utf-8"),
        ("/icon-64.png", "image/png"),
    ] {
        let res = server.get(path).await;
        assert_eq!(res.status(), 200, "{path}");
        assert_eq!(res.headers()[header::CONTENT_TYPE], content_type, "{path}");
        assert!(
            res.headers()[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .starts_with("public")
        );
        assert!(!res.bytes().await.unwrap().is_empty());
    }
}
