//! MCP サーバー: 受け口とツール

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};
use toro_auth::jwt;

const MCP_HOST: &str = "mcp.torosaba.net";

fn editor_token() -> String {
    jwt::sign(
        &json!({ "id": "1001", "username": "editor", "can_edit": true, "roles": [], "exp": jwt::now() + 60 }),
        JWT_SECRET,
    )
}

#[tokio::test]
async fn initialize_echoes_the_protocol_version() {
    let server = start().await;
    let res = server
        .rpc(
            "initialize",
            json!({ "protocolVersion": "2025-06-18" }),
            None,
        )
        .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["id"], 7);
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        body["result"]["serverInfo"]["name"],
        "toro-server-ai-gateway"
    );
    assert_eq!(
        body["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
}

#[tokio::test]
async fn lists_are_served() {
    let server = start().await;
    let body: Value = server
        .rpc("tools/list", json!({}), None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["result"]["tools"].as_array().unwrap().len(), 7);
    let body: Value = server
        .rpc("resources/list", json!({}), None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["result"]["resources"], json!([]));
    let body: Value = server
        .rpc("prompts/list", json!({}), None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["result"]["prompts"], json!([]));
    let body: Value = server
        .rpc("ping", json!({}), None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["result"], json!({}));
}

#[tokio::test]
async fn notifications_and_errors() {
    let server = start().await;
    assert_eq!(
        server
            .rpc("notifications/initialized", json!({}), None)
            .await
            .status(),
        202
    );

    let res = server.rpc("no/such", json!({}), None).await;
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["error"]["code"], -32601);

    // id の無い未知の通知は黙って受ける
    let res = server
        .client
        .post(server.url("/mcp"))
        .json(&json!({ "jsonrpc": "2.0", "method": "notifications/other" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);

    let res = server
        .client
        .post(server.url("/mcp"))
        .body("{broken")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(res.json::<Value>().await.unwrap()["error"]["code"], -32700);
}

#[tokio::test]
async fn mcp_host_shows_the_guide_to_browsers_and_json_to_clients() {
    let server = start().await;
    let request = |accept: &'static str| {
        server
            .client
            .get(server.url("/"))
            .header(header::HOST, MCP_HOST)
            .header(header::ACCEPT, accept)
    };

    let page = request("text/html")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("TORO サーバー 外部 AI 連携システム"));
    assert!(page.contains("ログイン状態の確認・ログイン"));
    assert!(page.contains("/_assets/claude_settings.webp"));
    assert!(!page.contains("{{"));

    let body: Value = request("application/json")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["authenticated"], false);
    assert_eq!(body["tools"].as_array().unwrap().len(), 7);

    // 専用のパスはブラウザでも JSON
    let res = server
        .client
        .get(server.url("/mcp"))
        .header(header::ACCEPT, "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(res.json::<Value>().await.unwrap()["status"], "ok");
}

#[tokio::test]
async fn mcp_host_still_serves_oauth_and_images() {
    let server = start().await;
    let on_mcp = |path: &str| {
        server
            .client
            .get(server.url(path))
            .header(header::HOST, MCP_HOST)
    };

    let meta: Value = on_mcp("/.well-known/oauth-protected-resource")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta["resource"], "https://mcp.torosaba.net");

    let res = on_mcp("/oauth/authorize?code_challenge=abc&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fa.example%2F")
        .send()
        .await
        .unwrap();
    assert!(res.text().await.unwrap().contains("連携の許可"));

    for image in ["claude_settings", "chatgpt_settings", "gemini_settings"] {
        let res = on_mcp(&format!("/_assets/{image}.webp"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.headers()[header::CONTENT_TYPE], "image/webp");
        assert!(res.bytes().await.unwrap().starts_with(b"RIFF"));
    }

    // 他の API は MCP に吸い込まれる (Worker と同じ)
    let body: Value = on_mcp("/api/auth/me")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn sse_sends_the_endpoint_and_stays_open() {
    let server = start().await;
    let mut res = server
        .client
        .get(server.url("/sse"))
        .header(header::ACCEPT, "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "text/event-stream");
    assert_eq!(res.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");

    let first = res.chunk().await.unwrap().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&first),
        "event: endpoint\ndata: https://mcp.torosaba.net/mcp\n\n"
    );

    // すぐには閉じない
    let next = tokio::time::timeout(std::time::Duration::from_millis(200), res.chunk()).await;
    assert!(next.is_err(), "stream closed early");
}

#[tokio::test]
async fn wiki_list_and_get_tools() {
    let server = start().await;
    server.put_file("docs/01_About/a.md", "sha1", "本文");

    let (text, is_error) = server.tool("wiki_list_pages", json!({}), None).await;
    assert!(!is_error);
    assert_eq!(
        text,
        "取得ドキュメント総数: 2\n\n- 01_About/a.md\n- 02_Guide/b.md"
    );

    let (text, _) = server
        .tool("wiki_list_pages", json!({ "category": "02_Guide" }), None)
        .await;
    assert_eq!(text, "取得ドキュメント総数: 1\n\n- 02_Guide/b.md");

    let (text, is_error) = server
        .tool("wiki_get_page", json!({ "path": "01_About/a" }), None)
        .await;
    assert!(!is_error);
    assert_eq!(text, "=== Path: docs/01_About/a.md (SHA: sha1) ===\n\n本文");

    let (_, is_error) = server
        .tool("wiki_get_page", json!({ "path": "missing" }), None)
        .await;
    assert!(is_error);
    let (_, is_error) = server.tool("wiki_get_page", json!({}), None).await;
    assert!(is_error);
}

#[tokio::test]
async fn wiki_tools_cannot_leave_docs() {
    let server = start().await;
    let token = editor_token();
    let (_, is_error) = server
        .tool("wiki_get_page", json!({ "path": "../../secret" }), None)
        .await;
    assert!(is_error);
    let (_, is_error) = server
        .tool(
            "wiki_save_page",
            json!({ "path": "../.github/x", "content": "x" }),
            Some(&token),
        )
        .await;
    assert!(is_error);
    assert!(server.github.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn wiki_save_tool_checks_permission_and_commits() {
    let server = start().await;
    let args = json!({ "path": "a", "content": "本文", "message": "更新" });

    let (text, is_error) = server.tool("wiki_save_page", args.clone(), None).await;
    assert!(is_error);
    assert!(text.starts_with("認証エラー"));

    let readonly = jwt::sign(
        &json!({ "id": "9", "username": "ro", "can_edit": false }),
        JWT_SECRET,
    );
    let (text, is_error) = server
        .tool("wiki_save_page", args.clone(), Some(&readonly))
        .await;
    assert!(is_error);
    assert!(text.starts_with("権限エラー"));

    let (text, is_error) = server
        .tool("wiki_save_page", args, Some(&editor_token()))
        .await;
    assert!(!is_error, "{text}");
    assert!(text.starts_with("コミット成功！\n- コミット SHA: commit-1"));
    let commits = server.github.commits.lock().unwrap();
    assert!(
        commits[0]["message"]
            .as_str()
            .unwrap()
            .starts_with("docs: 更新 (by editor via AI Gateway)\n\nCo-authored-by:")
    );
}

#[tokio::test]
async fn wiki_search_finds_text_in_documents() {
    let server = start().await;
    let search = |query: &'static str| server.tool("wiki_search", json!({ "query": query }), None);

    assert_eq!(
        search("traincarts").await.0,
        "検索結果 \"traincarts\":\n\n- 01_About/a.md"
    );
    assert_eq!(
        search("電車 TrainCarts").await.0,
        "検索結果 \"電車 TrainCarts\":\n\n- 01_About/a.md"
    );
    assert_eq!(
        search("02_guide").await.0,
        "検索結果 \"02_guide\":\n\n- 02_Guide/b.md"
    );
    assert!(search("無い語").await.0.contains("見つかりませんでした"));
    // GitHub の検索の修飾子は、ただの語として扱う
    assert!(
        search("traincarts repo:TORO-Server/Private")
            .await
            .0
            .contains("見つかりませんでした")
    );
    assert!(search("   ").await.0.contains("見つかりませんでした"));
}

#[tokio::test]
async fn wiki_search_reads_each_document_once() {
    let server = start().await;
    for _ in 0..3 {
        server
            .tool("wiki_search", json!({ "query": "電車" }), None)
            .await;
    }
    assert_eq!(server.github.blob_requests(), 2);
}

#[tokio::test]
async fn wiki_search_picks_up_changes_after_the_interval() {
    let server = start_with(|cfg| cfg.wiki_index_ttl_secs = 0).await;
    server
        .tool("wiki_search", json!({ "query": "x" }), None)
        .await;
    assert_eq!(server.github.blob_requests(), 2);

    {
        let mut docs = server.github.docs.lock().unwrap();
        docs.insert(
            "docs/01_About/a.md".to_string(),
            ("sha-a2".to_string(), "新しい本文".to_string()),
        );
        docs.remove("docs/02_Guide/b.md");
    }
    let (text, _) = server
        .tool("wiki_search", json!({ "query": "新しい" }), None)
        .await;
    assert_eq!(text, "検索結果 \"新しい\":\n\n- 01_About/a.md");
    // 変わった 1 件だけを読み直す
    assert_eq!(server.github.blob_requests(), 3);

    let (text, _) = server
        .tool("wiki_search", json!({ "query": "marumasign" }), None)
        .await;
    assert!(text.contains("見つかりませんでした"));
    let (text, _) = server
        .tool("wiki_search", json!({ "query": "電車" }), None)
        .await;
    assert!(text.contains("見つかりませんでした"));
}

#[tokio::test]
async fn invalid_tokens_get_401_so_clients_can_reauthorize() {
    let server = start().await;
    let expired = jwt::sign(
        &json!({ "id": "1", "username": "u", "exp": jwt::now() - 1 }),
        JWT_SECRET,
    );
    let other_key = jwt::sign(&json!({ "id": "1", "username": "u" }), "another-secret");

    for token in [expired.as_str(), other_key.as_str(), "garbage"] {
        let res = server.rpc("tools/list", json!({}), Some(token)).await;
        assert_eq!(res.status(), 401);
        let challenge = res.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert!(challenge.contains("error=\"invalid_token\""));
        assert!(challenge.contains(
            "resource_metadata=\"https://mcp.torosaba.net/.well-known/oauth-protected-resource\""
        ));

        let res = server
            .client
            .get(server.url("/mcp"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401);
    }

    // トークンなしと、有効なトークンは今までどおり
    assert_eq!(
        server.rpc("tools/list", json!({}), None).await.status(),
        200
    );
    let valid = editor_token();
    assert_eq!(
        server
            .rpc("tools/list", json!({}), Some(&valid))
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn resource_metadata_is_served_for_clients_using_a_path() {
    let server = start().await;
    let res = server
        .client
        .get(server.url("/.well-known/oauth-protected-resource/mcp"))
        .header(header::HOST, MCP_HOST)
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["resource"], "https://mcp.torosaba.net");
    assert!(body["authorization_servers"].is_array());
}

#[tokio::test]
async fn theme_files_are_served_with_the_right_types() {
    let server = start().await;
    for (path, content_type) in [
        ("/_assets/mcp.css", "text/css; charset=utf-8"),
        ("/_assets/auth.css", "text/css; charset=utf-8"),
        ("/_assets/pixel.woff2", "font/woff2"),
        ("/_assets/favicon.svg", "image/svg+xml"),
        ("/_assets/OFL.txt", "text/plain; charset=utf-8"),
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

#[tokio::test]
async fn delete_is_not_supported() {
    let server = start().await;
    let res = server
        .client
        .delete(server.url("/mcp"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 405);
}

#[tokio::test]
async fn server_status_reports_offline_when_unreachable() {
    let server = start().await;
    let (text, is_error) = server.tool("server_get_status", json!({}), None).await;
    assert!(!is_error);
    assert!(text.contains("[OFFLINE] オフライン"));
}

#[tokio::test]
async fn server_info_and_identity() {
    let server = start().await;
    let (text, _) = server.tool("server_get_info", json!({}), None).await;
    assert!(text.contains("https://wiki.torosaba.net/"));

    let (text, _) = server.tool("auth_get_identity", json!({}), None).await;
    assert!(text.starts_with("未認証状態です"));

    let (text, _) = server
        .tool("auth_get_identity", json!({}), Some(&editor_token()))
        .await;
    assert!(text.contains("- USER: editor"));
    assert!(text.contains("[YES] (TORO SERVER MEMBER)"));

    let (text, is_error) = server.tool("no_such_tool", json!({}), None).await;
    assert!(is_error);
    assert!(text.contains("no_such_tool"));
}
