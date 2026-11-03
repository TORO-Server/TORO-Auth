//! auth / api / mcp の役割の分離と、URL の正本

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};
use toro_auth::jwt;

#[tokio::test]
async fn api_root_lists_every_service_from_the_config() {
    let server = start().await;
    let body: Value = server.api_get("/").await.json().await.unwrap();
    assert_eq!(body["services"]["auth"], server.base);
    assert_eq!(body["services"]["api"], "https://api.torosaba.net");
    assert_eq!(body["services"]["mcp"], "https://mcp.torosaba.net");
    assert_eq!(body["openapi"], "https://api.torosaba.net/openapi.json");
    assert!(
        body["documentation"]
            .as_str()
            .unwrap()
            .starts_with("https://wiki.torosaba.net/wiki/")
    );
}

#[tokio::test]
async fn each_host_only_answers_for_its_own_role() {
    let server = start().await;

    // auth に API と MCP はない
    assert_eq!(server.get("/docs/raw?path=a").await.status(), 404);
    assert_eq!(server.get("/me").await.status(), 404);

    // api に認証と MCP はない
    for path in [
        "/api/auth/me",
        "/api/auth/login",
        "/oauth/token",
        "/mcp",
        "/sse",
    ] {
        assert_eq!(server.api_get(path).await.status(), 404, "{path}");
    }

    // mcp は画面を持たず、ブラウザはつなぎ方の記事へ送る
    let res = server
        .mcp_client
        .get(server.url("/"))
        .header(header::ACCEPT, "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 302);
    assert!(location(&res).starts_with("https://wiki.torosaba.net/wiki/AI"));
}

#[tokio::test]
async fn old_urls_on_auth_move_to_the_right_host() {
    let server = start().await;
    for (old, new) in [
        ("/api/mcp", "https://mcp.torosaba.net/"),
        ("/mcp", "https://mcp.torosaba.net/mcp"),
        ("/sse", "https://mcp.torosaba.net/sse"),
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
async fn authorization_endpoints_on_mcp_move_to_auth() {
    let server = start().await;
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/oauth/register",
        "/oauth/authorize?client_id=x",
        "/oauth/token",
    ] {
        let res = server.mcp_get(path).await;
        assert_eq!(res.status(), 308, "{path}");
        assert_eq!(location(&res), format!("{}{path}", server.base));
    }
}

#[tokio::test]
async fn api_ignores_cookies_and_uses_short_tokens_from_auth() {
    let server = start().await;
    let cookie = server.login("member").await;
    let body = json!({ "path": "a", "content": "x" });

    // Cookie では保存できない (届いたとしても見ない)
    let res = server
        .api_client
        .post(server.url("/docs/save"))
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, WIKI_ORIGIN)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert!(server.github.commits.lock().unwrap().is_empty());

    // Wiki の画面から短いトークンをもらって保存する
    let res = server
        .client
        .post(server.url("/api/auth/session-token"))
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

    let res = server
        .api_client
        .post(server.url("/docs/save"))
        .bearer_auth(token)
        .header(header::ORIGIN, WIKI_ORIGIN)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(server.github.commits.lock().unwrap().len(), 1);

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
    assert_eq!(me["user"]["username"], "member_user");
}

#[tokio::test]
async fn session_tokens_need_the_cookie_a_trusted_origin_and_post() {
    let server = start().await;
    let cookie = server.login("member").await;
    let path = server.url("/api/auth/session-token");

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
async fn openapi_describes_the_api_host_only() {
    let server = start().await;
    let spec: Value = server.api_get("/openapi.json").await.json().await.unwrap();
    assert_eq!(spec["servers"][0]["url"], "https://api.torosaba.net");
    assert_eq!(
        spec["paths"]["/docs/save"]["post"]["operationId"],
        "saveWikiDoc"
    );
    assert!(spec["paths"]["/docs/raw"]["get"].is_object());
    assert!(spec["paths"]["/me"]["get"].is_object());
    assert_eq!(spec["paths"].as_object().unwrap().len(), 3);
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

    let guide = server
        .client
        .get(server.url("/"))
        .header(header::HOST, "mcp.example.test")
        .header(header::ACCEPT, "text/html")
        .send()
        .await
        .unwrap();
    assert!(location(&guide).starts_with("https://wiki.example.test/wiki/"));
    assert!(location(&guide).ends_with('/'));

    let invalid = server.get("/oauth/authorize").await.text().await.unwrap();
    assert!(invalid.contains("https://wiki.example.test/wiki/"));
    assert!(!invalid.contains("{{"));

    let body: Value = server
        .client
        .post(server.url("/mcp"))
        .header(header::HOST, "mcp.example.test")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "server_get_info", "arguments": {} },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let text = body["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("https://api.example.test/"));
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
    assert!(script.contains("/api/auth/token"));
    assert!(!script.contains("TokenResponse"));
    assert!(!script.contains("HTMLButtonElement"));
}
