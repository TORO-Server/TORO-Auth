//! 第1段階 (対策3・対策2) の検証用サーバーでの確認。試験用の鍵と偽の Discord だけを使う。
//! 出力の行は `CHECK ...`。ログ行はそのまま `LOG {...}` として出す (秘密は入らないことも機械的に確かめる)。
//! 実行: cargo test --test stage1_reasons -- --nocapture --test-threads=1

mod common;

use axum::http::header;
use common::*;
use serde_json::{Value, json};
use toro_auth::auth::session;
use toro_auth::jwt::{self, Kind};
use toro_auth::reject_log;
use toro_auth::util::{encode_uri_component, sha256_base64url};

const CLIENT_REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier";
const SECRET: &str = "introspect-secret-introspect-secret";
/// 旧鍵 (3.0.1 の JWT_SECRET の役。試験用の値)
const OLD_KEY: &str = "old-jwt-secret-old-jwt-secret-old-jwt-secret";
/// 3.0.1 でもなく現行でもない鍵 (署名不一致の試験用)
const STRANGER_KEY: &str = "stranger-key-stranger-key-stranger-key";

/// 試験間でプロセス全体の reject_log::CAPTURED へのアクセスを直列化する
static CAPTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn authorize_path() -> String {
    let challenge = sha256_base64url(VERIFIER.as_bytes());
    format!(
        "/oauth/authorize?client_id=toro-ai-1&response_type=code&scope=mcp&state=st%20ate&code_challenge={challenge}&code_challenge_method=S256&redirect_uri={}",
        encode_uri_component(CLIENT_REDIRECT)
    )
}

async fn token_request(server: &TestServer, params: &[(&str, &str)]) -> reqwest::Response {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    server
        .client
        .post(server.url("/oauth/token"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap()
}

async fn issue(server: &TestServer) -> (String, String) {
    let cookie = server.login("member").await;
    let page = server
        .get_with_cookie(&authorize_path(), &cookie)
        .await
        .text()
        .await
        .unwrap();
    let start = page.find("/oauth/authorize?").unwrap();
    let approve = page[start..]
        .split('"')
        .next()
        .unwrap()
        .replace("&amp;", "&");
    let res = server.get_with_cookie(&approve, &cookie).await;
    let code = query_param(&location(&res), "code").unwrap();
    let t: Value = token_request(
        server,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", "toro-ai-1"),
            ("code_verifier", VERIFIER),
        ],
    )
    .await
    .json()
    .await
    .unwrap();
    (
        t["access_token"].as_str().unwrap().into(),
        t["refresh_token"].as_str().unwrap().into(),
    )
}

async fn refresh(server: &TestServer, token: &str) -> (u16, Value) {
    let res = token_request(
        server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", "toro-ai-1"),
        ],
    )
    .await;
    (res.status().as_u16(), res.json().await.unwrap())
}

async fn introspect_status(server: &TestServer, token: &str, secret: Option<&str>) -> (u16, bool) {
    let mut request = server
        .client
        .post(format!("{}/introspect", server.internal))
        .json(&json!({ "token": token }));
    if let Some(secret) = secret {
        request = request.header("X-Toro-Token", secret);
    }
    let res = request.send().await.unwrap();
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    (status, body["active"] == true)
}

/// 取り出したログ行を出し、各行が 1 行の JSON で、許された項目だけを持つことを確かめる
fn take_lines(label: &str) -> Vec<Value> {
    let lines = reject_log::take_captured();
    let mut parsed = Vec::new();
    for line in lines {
        println!("LOG {label}: {line}");
        assert!(!line.contains('\n'));
        let value: Value = serde_json::from_str(&line).expect("1 行の JSON");
        for key in value.as_object().unwrap().keys() {
            assert!(
                ["ts", "request", "reason", "token_kind", "token_exp"].contains(&key.as_str()),
                "許されない項目 {key}"
            );
        }
        parsed.push(value);
    }
    parsed
}

fn only(lines: Vec<Value>, reason: &str, kind: Option<&str>) -> Value {
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = lines.into_iter().next().unwrap();
    assert_eq!(line["reason"], reason, "{line}");
    assert_eq!(line["token_kind"].as_str(), kind, "{line}");
    line
}

/// 本文を書き換えて、同じ鍵で署名し直す
fn resign(
    token: &str,
    key: &str,
    edit: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> String {
    let mut claims = jwt::check(token, &self::key_for(token)).unwrap_or_default();
    edit(&mut claims);
    jwt::sign(&Value::Object(claims), key)
}

/// 本物の経路で発行したトークンの本文を読むために、種類に合う試験用の鍵を選ぶ
fn key_for(token: &str) -> String {
    let (kind, _) = jwt::peek(token);
    match kind {
        Some("refresh") => key(Kind::Refresh),
        Some("access") => key(Kind::Access),
        Some("connector") => key(Kind::Connector),
        _ => key(Kind::Session),
    }
}

#[tokio::test]
async fn reasons_for_each_rejection() {
    let _capture_guard = CAPTURE_LOCK.lock().await;
    reject_log::capture();
    let server = start_with(|cfg| cfg.introspect_secret = Some(SECRET.into())).await;
    let (access, refresh_token) = issue(&server).await;
    let _ = take_lines("setup");

    // 1. 正常: 401 も理由ログも出ない
    assert_eq!(
        introspect_status(&server, &access, Some(SECRET)).await,
        (200, true)
    );
    assert!(take_lines("normal").is_empty());
    println!("CHECK normal_has_no_reason_log=ok");

    // 2. 共有秘密の不一致 (なし / 違う値): 401 と shared_secret_mismatch
    for given in [None, Some("wrong")] {
        assert_eq!(
            introspect_status(&server, &access, given).await,
            (401, false)
        );
        let line = only(take_lines("shared_secret"), "shared_secret_mismatch", None);
        assert_eq!(line["request"], "introspect");
        assert!(line.get("token_exp").is_none());
    }
    println!("CHECK shared_secret_mismatch=ok");

    // 3. 期限切れ: 本物のアクセストークンの期限を過去にして署名し直す (試験用の鍵)
    let expired = resign(&access, &key(Kind::Access), |c| {
        c.insert("exp".into(), json!(jwt::now() - 60));
    });
    assert_eq!(
        introspect_status(&server, &expired, Some(SECRET)).await,
        (200, false)
    );
    let line = only(take_lines("expired"), "expired", Some("access"));
    assert!(line["token_exp"].is_string());
    println!("CHECK expired=ok");

    // 4. 署名不一致 (期限は先): 別の鍵で署名したもの。種類と期限は本文から読んだ手がかり
    let wrong_key = resign(&access, STRANGER_KEY, |_| {});
    assert_eq!(
        introspect_status(&server, &wrong_key, Some(SECRET)).await,
        (200, false)
    );
    let line = only(
        take_lines("signature"),
        "signature_mismatch",
        Some("access"),
    );
    assert!(line["token_exp"].is_string());
    // 読めない文字列は other
    assert_eq!(
        introspect_status(&server, "not-a-token", Some(SECRET)).await,
        (200, false)
    );
    only(take_lines("malformed"), "other", None);
    println!("CHECK signature_mismatch=ok");

    // 5. 失効 (連携が無い): 連携の記録に無い gid のアクセストークン
    let no_grant = resign(&access, &key(Kind::Access), |c| {
        c.insert("gid".into(), json!("ffffffffffffffffffffffffffffffff"));
    });
    assert_eq!(
        introspect_status(&server, &no_grant, Some(SECRET)).await,
        (200, false)
    );
    only(take_lines("revoked_grant"), "revoked", Some("access"));

    // 5b. 失効 (ログアウトした世代 / 作り直された 90 日トークン)
    let cookie = server.login("member").await;
    let short = server.session_token(&cookie).await;
    server
        .client
        .get(server.url("/logout"))
        .header(header::COOKIE, &cookie)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .unwrap();
    let _ = take_lines("logout_setup");
    assert_eq!(
        introspect_status(&server, &short, Some(SECRET)).await,
        (200, false)
    );
    only(take_lines("revoked_session"), "revoked", Some("session"));

    let cookie = server.login("member").await;
    let issue_connector = || async {
        let res = server
            .client
            .post(server.url("/token"))
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, &server.base)
            .send()
            .await
            .unwrap();
        let body: Value = res.json().await.unwrap();
        body["token"].as_str().unwrap().to_string()
    };
    let first = issue_connector().await;
    let _second = issue_connector().await;
    let _ = take_lines("connector_setup");
    assert_eq!(
        introspect_status(&server, &first, Some(SECRET)).await,
        (200, false)
    );
    only(
        take_lines("revoked_connector"),
        "revoked",
        Some("connector"),
    );
    println!("CHECK revoked=ok");

    // 6. リフレッシュの拒否 (oauth_token): 期限切れ / 署名不一致 / 失効 (再利用)
    let expired_refresh = resign(&refresh_token, &key(Kind::Refresh), |c| {
        c.insert("exp".into(), json!(jwt::now() - 5));
    });
    let (status, body) = refresh(&server, &expired_refresh).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    let line = only(take_lines("refresh_expired"), "expired", Some("refresh"));
    assert_eq!(line["request"], "oauth_token");

    let stranger_refresh = resign(&refresh_token, STRANGER_KEY, |_| {});
    refresh(&server, &stranger_refresh).await;
    only(
        take_lines("refresh_signature"),
        "signature_mismatch",
        Some("refresh"),
    );

    let (status, renewed) = refresh(&server, &refresh_token).await;
    assert_eq!(status, 200);
    assert!(take_lines("refresh_ok").is_empty());
    // 回転済みの古いトークンを再び出すと、連携ごと失効
    let (status, _) = refresh(&server, &refresh_token).await;
    assert_eq!(status, 400);
    only(take_lines("refresh_reuse"), "revoked", Some("refresh"));
    let _ = renewed;
    println!("CHECK refresh_reasons=ok");

    // 7. ユーザー情報の窓口 (userinfo) も同じ区分
    let res = server
        .client
        .get(server.url("/oauth/userinfo"))
        .bearer_auth(&expired)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let line = only(take_lines("userinfo"), "expired", Some("access"));
    assert_eq!(line["request"], "userinfo");
    println!("CHECK userinfo_reason=ok");
}

/// ログに出た全行に、トークン・鍵・共有秘密・IP アドレスが入っていないこと
#[tokio::test]
async fn logs_never_contain_secrets() {
    let _capture_guard = CAPTURE_LOCK.lock().await;
    reject_log::capture();
    let server = start_with(|cfg| cfg.introspect_secret = Some(SECRET.into())).await;
    let (access, refresh_token) = issue(&server).await;
    let _ = reject_log::take_captured();
    let stranger = resign(&access, STRANGER_KEY, |_| {});
    let expired = resign(&access, &key(Kind::Access), |c| {
        c.insert("exp".into(), json!(jwt::now() - 1));
    });
    for (token, secret) in [
        (stranger.as_str(), Some(SECRET)),
        (expired.as_str(), Some(SECRET)),
        (access.as_str(), Some("wrong")),
        (access.as_str(), None),
    ] {
        introspect_status(&server, token, secret).await;
    }
    refresh(&server, &resign(&refresh_token, STRANGER_KEY, |_| {})).await;
    let lines = reject_log::take_captured();
    assert!(lines.len() >= 5, "{lines:?}");
    let forbidden: Vec<String> = [
        &access,
        &refresh_token,
        &stranger,
        &expired,
        &SECRET.to_string(),
        &STRANGER_KEY.to_string(),
        &OLD_KEY.to_string(),
        &key(Kind::Access),
        &key(Kind::Refresh),
        &key(Kind::Session),
        &key(Kind::Connector),
        &JWT_SECRET.to_string(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let ip = regex_lite_ipv4();
    for line in &lines {
        for secret in &forbidden {
            assert!(
                !line.contains(secret.as_str()),
                "秘密がログに入った: {line}"
            );
        }
        // トークンらしい形 (a.b.c の base64url) と IPv4 の形が無いこと
        assert!(
            !line
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
                .any(|word| word.matches('.').count() == 2 && word.len() > 40),
            "{line}"
        );
        assert!(!ip(line), "IP アドレスの形: {line}");
    }
    println!(
        "CHECK logs_scanned lines={} secrets_or_tokens_or_ip_found=0",
        lines.len()
    );
}

/// 依存を足さない IPv4 の形の検出 (数字 1〜3 桁が 4 つ、ドットでつながる)
fn regex_lite_ipv4() -> impl Fn(&str) -> bool {
    |line: &str| {
        line.split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .any(|word| {
                let parts: Vec<&str> = word.split('.').collect();
                parts.len() == 4
                    && parts.iter().all(|p| {
                        !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit())
                    })
            })
    }
}

// ---- 対策2: 鍵の移行期間 ----

fn old_key_token(claims: Value) -> String {
    jwt::sign(&claims, OLD_KEY)
}

#[tokio::test]
async fn previous_key_window_accepts_old_tokens_and_issues_with_new_keys_only() {
    let _capture_guard = CAPTURE_LOCK.lock().await;
    reject_log::capture();
    let until = jwt::now() + 3;
    let server = start_with(|cfg| {
        cfg.introspect_secret = Some(SECRET.into());
        cfg.legacy_secret = Some(OLD_KEY.into());
        cfg.legacy_verify_until = Some(until);
    })
    .await;
    // 新鍵で発行した連携 (新旧の両方を確かめるための土台。連携の記録は新旧で共通)
    let (access_new, refresh_new) = issue(&server).await;
    let gid = jwt::verify(&access_new, &key(Kind::Access)).unwrap()["gid"].clone();
    let user = "1001";
    let now = jwt::now();
    let _ = reject_log::take_captured();

    // 旧鍵で署名した OAuth アクセス / リフレッシュ (3.0.1 の形: 同じ連携 gid を持つ)
    let old_access = old_key_token(json!({
        "sub": user, "id": user, "username": "member_user", "scope": "mcp", "gid": gid,
        "type": "mcp_access_token", "iat": now, "exp": now + 3600, "can_edit": false, "roles": []
    }));
    let old_refresh_for_legacy_check = old_key_token(json!({
        "sub": user, "id": user, "username": "member_user", "scope": "mcp", "gid": gid,
        "type": "mcp_refresh_token", "client_id": "toro-ai-1", "iat": now, "exp": now + 86400
    }));
    // 旧鍵で署名した、期限切れ / 種類違い (リフレッシュをアクセスとして出す)
    let old_expired = old_key_token(json!({
        "sub": user, "id": user, "gid": gid, "type": "mcp_access_token", "iat": now - 100, "exp": now - 10
    }));

    // 移行期間中 (a): 旧鍵のアクセストークンが通る。通したことがログに残る
    assert_eq!(
        introspect_status(&server, &old_access, Some(SECRET)).await,
        (200, true)
    );
    let line = only(
        take_lines("legacy_access"),
        "legacy_key_accepted",
        Some("access"),
    );
    assert_eq!(line["request"], "introspect");
    println!("CHECK window_old_access_accepted=ok");
    // (b): 新鍵のアクセストークンも通る (ログは出ない)
    assert_eq!(
        introspect_status(&server, &access_new, Some(SECRET)).await,
        (200, true)
    );
    assert!(take_lines("new_access").is_empty());
    println!("CHECK window_new_access_accepted=ok");
    // (c): 旧鍵の期限切れは expired、旧鍵のリフレッシュはアクセスとしては通らない (other)
    assert_eq!(
        introspect_status(&server, &old_expired, Some(SECRET)).await,
        (200, false)
    );
    only(take_lines("legacy_expired"), "expired", Some("access"));
    assert_eq!(
        introspect_status(&server, &old_refresh_for_legacy_check, Some(SECRET)).await,
        (200, false)
    );
    only(take_lines("legacy_wrong_kind"), "other", Some("refresh"));
    println!("CHECK window_legacy_edge_cases=ok");

    // (d): 旧鍵のリフレッシュで更新できる。発行されるものは新鍵だけで署名されている
    // 連携の世代 (jti) は、新しい連携の現在の世代に合わせる必要があるので、新鍵で発行した連携のリフレッシュ本文から取る
    let current = jwt::verify(&refresh_new, &key(Kind::Refresh)).unwrap();
    let old_refresh = old_key_token(json!({
        "sub": user, "id": user, "username": "member_user", "scope": "mcp", "gid": gid,
        "jti": current["jti"], "type": "mcp_refresh_token", "client_id": "toro-ai-1",
        "iat": now, "exp": now + 86400, "can_edit": false
    }));
    let (status, renewed) = refresh(&server, &old_refresh).await;
    assert_eq!(status, 200, "{renewed}");
    let renewed_access = renewed["access_token"].as_str().unwrap();
    let renewed_refresh = renewed["refresh_token"].as_str().unwrap();
    assert!(
        jwt::verify(renewed_access, &key(Kind::Access)).is_some(),
        "新鍵で署名"
    );
    assert!(
        jwt::verify(renewed_refresh, &key(Kind::Refresh)).is_some(),
        "新鍵で署名"
    );
    assert!(
        jwt::verify(renewed_access, OLD_KEY).is_none(),
        "旧鍵では署名しない"
    );
    assert!(
        jwt::verify(renewed_refresh, OLD_KEY).is_none(),
        "旧鍵では署名しない"
    );
    only(
        take_lines("legacy_refresh"),
        "legacy_key_accepted",
        Some("refresh"),
    );
    println!("CHECK window_issue_new_key_only=ok (access, refresh)");

    // 90 日トークンの発行も新鍵だけ
    let cookie = server.login("member").await;
    let res = server
        .client
        .post(server.url("/token"))
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, &server.base)
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    let connector = body["token"].as_str().unwrap();
    assert!(jwt::verify(connector, &key(Kind::Connector)).is_some());
    assert!(jwt::verify(connector, OLD_KEY).is_none());
    let _ = take_lines("connector_issue");
    println!("CHECK window_issue_new_key_only=ok (connector)");

    // 期間の終了: 期限を過ぎると、旧鍵のトークンは拒否される (署名不一致)。新鍵のものは通る
    let wait = (until - jwt::now() + 2).max(0) as u64;
    tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    assert_eq!(
        introspect_status(&server, &old_access, Some(SECRET)).await,
        (200, false)
    );
    only(
        take_lines("after_window"),
        "signature_mismatch",
        Some("access"),
    );
    assert_eq!(
        introspect_status(&server, renewed_access, Some(SECRET)).await,
        (200, true)
    );
    let (status, _) = refresh(&server, &old_refresh).await;
    assert_eq!(status, 400);
    only(
        take_lines("after_window_refresh"),
        "signature_mismatch",
        Some("refresh"),
    );
    println!("CHECK after_window_old_rejected_new_accepted=ok");
    let _ = session::ACCESS_TOKEN_TYPE;
}

#[tokio::test]
async fn without_the_window_setting_the_previous_key_is_ignored() {
    let _capture_guard = CAPTURE_LOCK.lock().await;
    // JWT_SECRET が env にあっても、JWT_LEGACY_VERIFY_UNTIL が無ければ旧鍵では通さない (現行の挙動のまま)
    reject_log::capture();
    let server = start_with(|cfg| cfg.introspect_secret = Some(SECRET.into())).await;
    let (access, _) = issue(&server).await;
    let gid = jwt::verify(&access, &key(Kind::Access)).unwrap()["gid"].clone();
    let now = jwt::now();
    let old = old_key_token(json!({
        "sub": "1001", "id": "1001", "gid": gid, "type": "mcp_access_token", "iat": now, "exp": now + 3600
    }));
    let _ = reject_log::take_captured();
    assert_eq!(
        introspect_status(&server, &old, Some(SECRET)).await,
        (200, false)
    );
    only(
        take_lines("no_window"),
        "signature_mismatch",
        Some("access"),
    );
    println!("CHECK no_window_old_key_rejected=ok");
}

#[test]
fn window_setting_is_bounded_and_needs_the_previous_key() {
    use toro_auth::config::{Config, MAX_LEGACY_WINDOW_SECS};
    let set_base = || unsafe {
        for kind in Kind::ALL {
            std::env::set_var(kind.env_name(), format!("{:x<40}", kind.env_name()));
        }
        std::env::set_var("DISCORD_CLIENT_SECRET", "s");
        std::env::set_var("DISCORD_CLIENT_ID", "c");
        std::env::set_var("DISCORD_GUILD_ID", "g");
        std::env::set_var("JWT_SECRET", OLD_KEY);
    };
    set_base();
    let now = jwt::now();
    let try_until = |value: Option<i64>| {
        unsafe {
            match value {
                Some(v) => std::env::set_var("JWT_LEGACY_VERIFY_UNTIL", v.to_string()),
                None => std::env::remove_var("JWT_LEGACY_VERIFY_UNTIL"),
            }
        }
        Config::from_env()
    };
    // 未設定: 旧鍵は読まない
    let cfg = try_until(None).unwrap();
    assert!(cfg.legacy_key().is_none());
    // 範囲内
    let cfg = try_until(Some(now + 30 * 86400)).unwrap();
    assert_eq!(cfg.legacy_key(), Some(OLD_KEY));
    // 90 日を超える / 過去 / 数でない
    assert!(try_until(Some(now + MAX_LEGACY_WINDOW_SECS + 3600)).is_err());
    assert!(try_until(Some(now - 1)).is_err());
    unsafe { std::env::set_var("JWT_LEGACY_VERIFY_UNTIL", "tomorrow") };
    assert!(Config::from_env().is_err());
    // 旧鍵が無い / 短い / 新鍵と同じ
    unsafe {
        std::env::set_var("JWT_LEGACY_VERIFY_UNTIL", (now + 86400).to_string());
        std::env::remove_var("JWT_SECRET");
    }
    assert!(Config::from_env().is_err());
    unsafe { std::env::set_var("JWT_SECRET", "short") };
    assert!(Config::from_env().is_err());
    unsafe { std::env::set_var("JWT_SECRET", format!("{:x<40}", Kind::Access.env_name())) };
    assert!(Config::from_env().is_err());
    unsafe { std::env::remove_var("JWT_LEGACY_VERIFY_UNTIL") };
    let _ = encode_uri_component;
    println!("CHECK window_setting_bounds=ok");
}
