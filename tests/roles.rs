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

/// 発行した時点の `can_edit` が入った、試験用のトークン
fn token_with_can_edit(id: &str, can_edit: bool) -> String {
    toro_auth::jwt::sign(
        &json!({ "id": id, "username": "u", "can_edit": can_edit, "roles": ["role-old"], "exp": toro_auth::jwt::now() + 600 }),
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

#[tokio::test]
async fn can_edit_follows_the_required_role_right_now() {
    let server = start_with(|cfg| {
        cfg.discord_bot_token = Some("bot-token".into());
        cfg.discord_required_role_id = Some("role-live".into());
    })
    .await;
    // トークンの値とは逆でも、いまのロールで決まる
    let claims = server
        .introspect(&token_with_can_edit("7007", false))
        .await
        .unwrap();
    assert_eq!(claims["can_edit"], true);
    // ロールを外された人は、トークンに true が入っていても編集できない
    let claims = server
        .introspect(&token_with_can_edit("1001", true))
        .await
        .unwrap();
    assert_eq!(claims["roles"], json!(["role-a", "role-b"]));
    assert_eq!(claims["can_edit"], false);
}

#[tokio::test]
async fn without_a_required_role_every_live_member_can_edit() {
    let server = start_with(|cfg| cfg.discord_bot_token = Some("bot-token".into())).await;
    // ロールが 1 つも無いメンバーでも、ギルドに居れば編集できる。トークンの false には引きずられない
    let claims = server
        .introspect(&token_with_can_edit("6006", false))
        .await
        .unwrap();
    assert_eq!(claims["roles"], json!([]));
    assert_eq!(claims["roles_source"], "live");
    assert_eq!(claims["can_edit"], true);
}

#[tokio::test]
async fn people_who_left_and_discord_failures_cannot_edit() {
    let server = start_with(|cfg| cfg.discord_bot_token = Some("bot-token".into())).await;
    let left = server
        .introspect(&token_with_can_edit("8008", true))
        .await
        .unwrap();
    assert_eq!(left["roles_source"], "live");
    assert_eq!(left["can_edit"], false);

    let unavailable = server
        .introspect(&token_with_can_edit("9009", true))
        .await
        .unwrap();
    assert_eq!(unavailable["roles_source"], "unavailable");
    assert_eq!(unavailable["can_edit"], false);
    // 覚えておいた結果でも、同じ
    let again = server
        .introspect(&token_with_can_edit("8008", true))
        .await
        .unwrap();
    assert_eq!(again["can_edit"], false);
}

#[tokio::test]
async fn without_a_bot_token_can_edit_stays_as_issued() {
    let server = start_with(|cfg| cfg.discord_required_role_id = Some("role-z".into())).await;
    for can_edit in [true, false] {
        let claims = server
            .introspect(&token_with_can_edit("1001", can_edit))
            .await
            .unwrap();
        assert_eq!(claims["roles_source"], "token");
        assert_eq!(claims["can_edit"], can_edit);
    }
}
