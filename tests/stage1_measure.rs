//! 第1段階の実測 (方法B): ローカルの検証用サーバー (試験用の鍵、偽の Discord) だけで、トークンの有効期間と失効の境界を測る。
//! 本番のトークン・鍵・サーバーは使わない。出力は `MEASURE ...` の行 (値は期間と真偽だけで、トークン本体は出さない)。
//! 実行: cargo test --test stage1_measure -- --nocapture --test-threads=1

mod common;

use std::time::{Duration, Instant};

use axum::http::header;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use serde_json::{Value, json};
use toro_auth::jwt::{self, Kind};
use toro_auth::util::{encode_uri_component, sha256_base64url};

const CLIENT_REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier";

fn payload(token: &str) -> Value {
    let part = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

fn span(token: &str) -> i64 {
    let p = payload(token);
    p["exp"].as_i64().unwrap() - p["iat"].as_i64().unwrap()
}

fn authorize_path() -> String {
    let challenge = sha256_base64url(VERIFIER.as_bytes());
    format!(
        "/oauth/authorize?client_id=toro-ai-1&response_type=code&scope=mcp&state=st%20ate&code_challenge={challenge}&code_challenge_method=S256&redirect_uri={}",
        encode_uri_component(CLIENT_REDIRECT)
    )
}

async fn consent_and_code(server: &TestServer, cookie: &str) -> (String, String) {
    let page = server
        .get_with_cookie(&authorize_path(), cookie)
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
    let consent = query_param(&format!("http://x{approve}"), "consent").unwrap();
    let res = server.get_with_cookie(&approve, cookie).await;
    assert_eq!(res.status(), 302);
    (consent, query_param(&location(&res), "code").unwrap())
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

async fn exchange(server: &TestServer, code: &str) -> Value {
    token_request(
        server,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", "toro-ai-1"),
            ("code_verifier", VERIFIER),
        ],
    )
    .await
    .json()
    .await
    .unwrap()
}

async fn issue(server: &TestServer) -> (String, String) {
    let cookie = server.login("member").await;
    let (_, code) = consent_and_code(server, &cookie).await;
    let t = exchange(server, &code).await;
    (
        t["access_token"].as_str().unwrap().into(),
        t["refresh_token"].as_str().unwrap().into(),
    )
}

async fn refresh(server: &TestServer, refresh: &str) -> (u16, String) {
    let res = token_request(
        server,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", "toro-ai-1"),
        ],
    )
    .await;
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap();
    (status, body["error"].as_str().unwrap_or("-").to_string())
}

/// M1: 各トークンを本物の経路で発行し、署名に入る期限 (exp - iat) と応答の expires_in を読む
#[tokio::test]
async fn m1_issued_lifetimes() {
    let server = start().await;

    // ログインの state (/login の 302 の state)
    let start_res = server
        .get("/login?redirect=https%3A%2F%2Fwiki.torosaba.net%2F")
        .await;
    let state = query_param(&location(&start_res), "state").unwrap();
    let sp = payload(&state);
    println!(
        "MEASURE login_state_lifetime_s={}",
        sp["exp"].as_i64().unwrap() - jwt::now()
    );

    // ブラウザのセッション (Cookie の Max-Age と署名の期限)
    let (cookie, _) = server
        .login_to("member", "https://wiki.torosaba.net/")
        .await;
    let session_token = cookie.split_once('=').unwrap().1;
    let decoded = url::form_urlencoded::parse(format!("v={session_token}").as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned();
    println!("MEASURE browser_session_lifetime_s={}", span(&decoded));

    // API 用の短い期限のトークン
    let short = server.session_token(&cookie).await;
    println!("MEASURE api_session_token_lifetime_s={}", span(&short));

    // 90 日コネクタトークン
    let res = server
        .client
        .post(server.url("/token"))
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, &server.base)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    println!(
        "MEASURE connector_token_lifetime_s={}",
        span(body["token"].as_str().unwrap())
    );

    // 同意 (承認リンク)・認可コード・アクセス・リフレッシュ
    let (consent, code) = consent_and_code(&server, &cookie).await;
    println!(
        "MEASURE consent_lifetime_s={}",
        payload(&consent)["exp"].as_i64().unwrap() - jwt::now()
    );
    let code_exp = payload(&code)["exp"].as_i64().unwrap();
    println!("MEASURE auth_code_lifetime_s={}", code_exp - jwt::now());
    let t = exchange(&server, &code).await;
    println!(
        "MEASURE access_token_lifetime_s={} expires_in={}",
        span(t["access_token"].as_str().unwrap()),
        t["expires_in"]
    );
    println!(
        "MEASURE refresh_token_lifetime_s={}",
        span(t["refresh_token"].as_str().unwrap())
    );
    // OAUTH_IDLE_DAYS 未設定時の既定 (Config::from_env を、試験用の値だけで通す)
    for kind in jwt::Kind::ALL {
        unsafe { std::env::set_var(kind.env_name(), format!("{:x<40}", kind.env_name())) };
    }
    unsafe {
        std::env::set_var("DISCORD_CLIENT_SECRET", "s");
        std::env::set_var("DISCORD_CLIENT_ID", "c");
        std::env::set_var("DISCORD_GUILD_ID", "g");
        std::env::remove_var("OAUTH_IDLE_DAYS");
    }
    let cfg = toro_auth::config::Config::from_env().unwrap();
    println!("MEASURE oauth_idle_default_s={}", cfg.oauth_idle_seconds);
}

/// M2: アクセストークンの失効の境界。本物の経路で発行したものを、期限 now+3 秒で再署名 (試験用の鍵) し、introspect で見る
#[tokio::test]
async fn m2_access_expiry_boundary() {
    let server = start().await;
    let (access, _) = issue(&server).await;
    let mut claims = jwt::verify(&access, &key(Kind::Access)).unwrap();
    let t0 = jwt::now();
    claims.insert("exp".into(), json!(t0 + 3));
    let token = jwt::sign(&Value::Object(claims), &key(Kind::Access));
    let start = Instant::now();
    for _ in 0..6 {
        let active = server.introspect(&token).await.is_some();
        println!(
            "MEASURE access_boundary elapsed_since_t0={:.1}s exp=t0+3 active={active}",
            start.elapsed().as_secs_f32()
        );
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
}

/// M3: リフレッシュトークンの失効の境界。連携ごとに 1 回だけ更新を試みる (成功すると世代が進むため)
#[tokio::test]
async fn m3_refresh_expiry_boundary() {
    let server = start().await;
    let mut tokens = Vec::new();
    for _ in 0..4 {
        let (_, r) = issue(&server).await;
        let mut claims = jwt::verify(&r, &key(Kind::Refresh)).unwrap();
        claims.insert("exp".into(), json!(jwt::now() + 3));
        tokens.push(jwt::sign(&Value::Object(claims), &key(Kind::Refresh)));
    }
    let start = Instant::now();
    for (i, wait_ms) in [800u64, 1000, 2400, 1000].iter().enumerate() {
        tokio::time::sleep(Duration::from_millis(*wait_ms)).await;
        let (status, error) = refresh(&server, &tokens[i]).await;
        println!(
            "MEASURE refresh_boundary elapsed_since_t0={:.1}s exp=t0+3 status={status} error={error}",
            start.elapsed().as_secs_f32()
        );
    }
}
