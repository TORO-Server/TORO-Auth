//! 確認の窓口 (/introspect) が返すロール: トークンの値ではなく、いまの Discord のロール

mod common;

use common::*;
use serde_json::json;

/// 発行した時点のロールが入った、試験用のトークン
fn token_with_roles(id: &str, roles: serde_json::Value) -> String {
    toro_auth::jwt::sign(
        &json!({ "id": id, "username": "u", "can_edit": true, "roles": roles, "exp": toro_auth::jwt::now() + 600 }),
        JWT_SECRET,
    )
}

#[tokio::test]
async fn roles_are_replaced_by_the_live_ones() {
    let server = start_with(|cfg| cfg.discord_bot_token = Some("bot-token".into())).await;
    // トークンには古い (Admin だった) ロールが入っているが、いまは role-live だけ
    let claims = server
        .introspect(&token_with_roles("7007", json!(["admin-role", "role-a"])))
        .await
        .unwrap();
    assert_eq!(claims["roles"], json!(["role-live"]));
    assert_eq!(claims["roles_source"], "live");
    assert_eq!(claims["id"], "7007");
    assert_eq!(claims["can_edit"], true);
}

#[tokio::test]
async fn roles_are_empty_for_people_who_left_or_when_discord_fails() {
    let server = start_with(|cfg| cfg.discord_bot_token = Some("bot-token".into())).await;
    // ギルドを抜けた人 (404): 空のロールで、確かめた扱い
    let claims = server
        .introspect(&token_with_roles("8008", json!(["admin-role"])))
        .await
        .unwrap();
    assert_eq!(claims["roles"], json!([]));
    assert_eq!(claims["roles_source"], "live");
    // 確かめられない (500): 古いロールを信じず、空にする
    let claims = server
        .introspect(&token_with_roles("9009", json!(["admin-role"])))
        .await
        .unwrap();
    assert_eq!(claims["roles"], json!([]));
    assert_eq!(claims["roles_source"], "unavailable");
}

#[tokio::test]
async fn without_a_bot_token_the_token_roles_are_passed_through() {
    let server = start().await;
    let claims = server
        .introspect(&token_with_roles("1001", json!(["role-a"])))
        .await
        .unwrap();
    assert_eq!(claims["roles"], json!(["role-a"]));
    assert_eq!(claims["roles_source"], "token");
}
