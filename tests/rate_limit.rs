//! auth のレート制限の統合試験。
//!
//! 対象は /login、/oauth/register、/oauth/token。要求元の識別子は toro-edge が
//! 設定する `X-Toro-Client-Ip` ヘッダーから読むため、試験ではヘッダーで IP を変える。

mod common;

use axum::http::header;
use common::{TestServer, start};

const CLIENT_IP: &str = "x-toro-client-ip";
const LOGIN: &str = "/login?redirect=https://wiki.torosaba.net/";

async fn login(server: &TestServer, ip: &str) -> reqwest::Response {
    server
        .client
        .get(server.url(LOGIN))
        .header(CLIENT_IP, ip)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn twenty_first_request_from_one_ip_is_blocked() {
    let server = start().await;
    let ip = "203.0.113.7";
    for _ in 0..20 {
        let res = login(&server, ip).await;
        assert_eq!(res.status(), 302);
    }
    let blocked = login(&server, ip).await;
    assert_eq!(blocked.status(), 429);
    assert_eq!(blocked.headers()[header::RETRY_AFTER], "10");
    let body: serde_json::Value = blocked.json().await.unwrap();
    assert_eq!(body["error"], "Too Many Requests");
}

#[tokio::test]
async fn limit_is_per_client_ip() {
    let server = start().await;
    for _ in 0..20 {
        assert_eq!(login(&server, "203.0.113.7").await.status(), 302);
    }
    assert_eq!(login(&server, "203.0.113.7").await.status(), 429);
    // 別の IP は制限にかからない。
    assert_eq!(login(&server, "198.51.100.1").await.status(), 302);
}

#[tokio::test]
async fn other_paths_are_not_limited() {
    let server = start().await;
    for _ in 0..25 {
        let res = server
            .client
            .get(server.url("/.well-known/openid-configuration"))
            .header(CLIENT_IP, "203.0.113.7")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
    }
}
