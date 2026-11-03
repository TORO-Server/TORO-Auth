//! Wiki の REST API (api.torosaba.net/docs/*)

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};
use toro_auth::jwt;
use toro_auth::util::encode_uri_component;

const JP_PATH: &str = "07_System/日本語のページ.md";

fn encoded_jp_path() -> String {
    let encoded: Vec<String> = format!("docs/{JP_PATH}")
        .split('/')
        .map(encode_uri_component)
        .collect();
    encoded.join("/")
}

#[tokio::test]
async fn raw_returns_decoded_content() {
    let server = start().await;
    let long_body = "本文 ".repeat(100);
    server.put_file(&encoded_jp_path(), "abc", &long_body);

    let res = server
        .api_get(&format!("/docs/raw?path={}", encode_uri_component(JP_PATH)))
        .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["sha"], "abc");
    assert_eq!(body["content"], long_body.as_str());
    assert_eq!(body["size"], long_body.len());

    let res = server
        .api_get(&format!(
            "/docs/raw?format=raw&path={}",
            encode_uri_component(JP_PATH)
        ))
        .await;
    assert_eq!(res.headers()[header::ETAG], "\"abc\"");
    assert_eq!(
        res.headers()[header::CONTENT_TYPE],
        "text/markdown; charset=utf-8"
    );
    assert_eq!(res.text().await.unwrap(), long_body);
}

#[tokio::test]
async fn raw_errors() {
    let server = start().await;
    assert_eq!(server.api_get("/docs/raw").await.status(), 400);
    assert_eq!(server.api_get("/docs/raw?path=missing").await.status(), 404);
}

#[tokio::test]
async fn paths_outside_docs_never_reach_github() {
    let server = start().await;
    let cookie = server.login("member").await;
    for bad in ["../secret", "a/../../secret", "a\\b", "a//b"] {
        let encoded = encode_uri_component(bad);
        assert_eq!(
            server
                .api_get(&format!("/docs/raw?path={encoded}"))
                .await
                .status(),
            400,
            "{bad}"
        );

        let res = server
            .api_client
            .post(server.url("/docs/save"))
            .bearer_auth(server.session_token(&cookie).await)
            .json(&json!({ "path": bad, "content": "x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400, "{bad}");
    }
    assert!(server.github.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn save_requires_login_and_permission() {
    let server = start().await;
    let body = json!({ "path": "a", "content": "x" });

    let res = server
        .api_client
        .post(server.url("/docs/save"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);

    let readonly = jwt::sign(
        &json!({ "id": "9", "username": "ro", "can_edit": false, "exp": jwt::now() + 60 }),
        JWT_SECRET,
    );
    let res = server
        .api_client
        .post(server.url("/docs/save"))
        .bearer_auth(readonly)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
}

#[tokio::test]
async fn save_commits_as_the_discord_user() {
    let server = start().await;
    let cookie = server.login("member").await;
    server.put_file("docs/a.md", "old-sha", "old");

    let res = server
        .api_client
        .post(server.url("/docs/save"))
        .bearer_auth(server.session_token(&cookie).await)
        .json(
            &json!({ "path": "a", "content": "新しい本文", "sha": "old-sha", "message": "直した" }),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["commitSha"], "commit-1");

    let commits = server.github.commits.lock().unwrap();
    let commit = &commits[0];
    assert_eq!(commit["branch"], "main");
    assert_eq!(commit["sha"], "old-sha");
    assert_eq!(commit["author"]["name"], "member_user (via Discord)");
    assert_eq!(
        commit["committer"]["email"],
        "1001+discord@users.noreply.torosaba.net"
    );
    assert!(
        commit["message"]
            .as_str()
            .unwrap()
            .starts_with("直した\n\nCo-authored-by: member_user <1001+discord@")
    );
    assert_eq!(
        server.github.files.lock().unwrap()["docs/a.md"].1,
        "新しい本文"
    );
}

#[tokio::test]
async fn save_without_sha_uses_the_latest_and_new_files_have_none() {
    let server = start().await;
    let cookie = server.login("member").await;
    server.put_file("docs/a.md", "latest", "old");

    for (path, expected_sha) in [("a", json!("latest")), ("new-page", Value::Null)] {
        let res = server
            .api_client
            .post(server.url("/docs/save"))
            .bearer_auth(server.session_token(&cookie).await)
            .json(&json!({ "path": path, "content": "x" }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(
            server.github.commits.lock().unwrap().last().unwrap()["sha"],
            expected_sha
        );
    }
    let commits = server.github.commits.lock().unwrap();
    assert!(
        commits[0]["message"]
            .as_str()
            .unwrap()
            .starts_with("Wiki update: docs/a.md\n\nEdited via Browser/API")
    );
}

#[tokio::test]
async fn conflicts_keep_the_text_the_editor_looks_for() {
    let server = start().await;
    let cookie = server.login("member").await;
    server.put_file("docs/a.md", "current", "old");

    let res = server
        .api_client
        .post(server.url("/docs/save"))
        .bearer_auth(server.session_token(&cookie).await)
        .json(&json!({ "path": "a", "content": "x", "sha": "stale" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 500);
    let error = res.json::<Value>().await.unwrap()["error"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        error.starts_with("Failed to commit to GitHub: GitHub Commit error (409)"),
        "{error}"
    );
    assert!(error.contains("does not match"));
}
