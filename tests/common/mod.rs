//! 結合試験の共通部品: 偽の Discord / GitHub と、試験用に起動した本体
#![allow(dead_code)]

use std::sync::Arc;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use toro_auth::App;
use toro_auth::config::Config;

pub const GUILD: &str = "000000000000000000";
pub const JWT_SECRET: &str = "test-secret-test-secret-test-secret";
pub const WIKI_ORIGIN: &str = "https://wiki.torosaba.net";

async fn spawn(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

fn json_response(status: u16, body: Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// 認可コード (= 試験の利用者の種類) を `tok-<code>` に換えるだけの Discord
async fn start_fake_discord() -> String {
    let router = Router::new().fallback(|req: Request| async move {
        let (parts, body) = req.into_parts();
        let body = String::from_utf8(to_bytes(body, usize::MAX).await.unwrap().to_vec()).unwrap();
        let path = parts.uri.path().to_string();
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("")
            .to_string();

        match path.as_str() {
            "/oauth2/token" => {
                let code = url::form_urlencoded::parse(body.as_bytes())
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                if code == "bad" {
                    return json_response(400, json!({ "error": "invalid_grant" }));
                }
                json_response(200, json!({ "access_token": format!("tok-{code}"), "token_type": "Bearer" }))
            }
            "/users/@me" => {
                let (id, name) = match token.as_str() {
                    "tok-member" => ("1001", "member_user"),
                    "tok-other" => ("3003", "other_user"),
                    "tok-xss" => ("4004", "<img src=x onerror=alert(1)>"),
                    _ => ("2002", "outsider_user"),
                };
                json_response(
                    200,
                    json!({ "id": id, "username": name, "global_name": null, "avatar": "abc", "discriminator": "0" }),
                )
            }
            p if p == format!("/users/@me/guilds/{GUILD}/member") => match token.as_str() {
                "tok-outsider" => json_response(404, json!({ "message": "Unknown Guild" })),
                _ => json_response(200, json!({ "roles": ["role-a", "role-b"] })),
            },
            "/users/@me/guilds" => json_response(200, json!([])),
            // 本物と同じく、Bot トークンでだけ読める
            p if p == format!("/guilds/{GUILD}/roles") => {
                let is_bot = parts
                    .headers
                    .get(header::AUTHORIZATION)
                    .is_some_and(|h| h.as_bytes().starts_with(b"Bot "));
                if !is_bot {
                    return json_response(401, json!({ "message": "401: Unauthorized" }));
                }
                json_response(
                    200,
                    json!([
                        { "id": "role-a", "name": "<b>管理者</b>" },
                        { "id": "everyone", "name": "@everyone" },
                    ]),
                )
            }
            // いまのロール (Bot トークンでだけ読める)。トークンに入っているものとは、わざと違う値にしてある
            p if p.starts_with(&format!("/guilds/{GUILD}/members/")) => {
                let is_bot = parts
                    .headers
                    .get(header::AUTHORIZATION)
                    .is_some_and(|h| h.as_bytes().starts_with(b"Bot "));
                if !is_bot {
                    return json_response(401, json!({ "message": "401: Unauthorized" }));
                }
                match p.rsplit('/').next().unwrap_or("") {
                    "6006" => json_response(200, json!({ "roles": [] })),
                    "7007" => json_response(200, json!({ "roles": ["role-live"] })),
                    "8008" => json_response(404, json!({ "message": "Unknown Member" })),
                    "9009" => json_response(500, json!({ "message": "boom" })),
                    _ => json_response(200, json!({ "roles": ["role-a", "role-b"] })),
                }
            }
            _ => json_response(404, json!({ "message": "not found" })),
        }
    });
    spawn(router).await
}

pub struct TestServer {
    pub base: String,
    /// api / mcp のトークンの確認を受ける内側のポート
    pub internal: String,
    pub client: reqwest::Client,
}

pub async fn start() -> TestServer {
    start_with(|_| {}).await
}

pub async fn start_with(customize: impl FnOnce(&mut Config)) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal = format!("http://{}", internal_listener.local_addr().unwrap());

    let state_dir =
        std::env::temp_dir().join(format!("toro-auth-test-{}", toro_auth::util::random_hex(8)));
    std::fs::create_dir_all(&state_dir).unwrap();

    let mut cfg = Config {
        port: 0,
        internal_port: 0,
        issuer: base.clone(),
        wiki_url: WIKI_ORIGIN.into(),
        cors_origins: vec![WIKI_ORIGIN.into()],
        jwt_secret: JWT_SECRET.into(),
        discord_client_id: "client".into(),
        discord_client_secret: "secret".into(),
        discord_redirect_uri: format!("{base}/callback"),
        discord_guild_id: GUILD.into(),
        discord_required_role_id: None,
        discord_bot_token: None,
        discord_api: start_fake_discord().await,
        state_dir: state_dir.to_string_lossy().into_owned(),
        oauth_idle_seconds: 30 * 86400,
        body_read_timeout_secs: 30,
    };
    customize(&mut cfg);

    let app = Arc::new(App::new(cfg).unwrap());
    let router = toro_auth::routes::router(app.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let internal_router = toro_auth::internal::router(app);
    tokio::spawn(async move {
        axum::serve(internal_listener, internal_router)
            .await
            .unwrap()
    });

    TestServer {
        base,
        internal,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}
/// 応答ヘッダーを読みやすくする
pub fn set_cookies(res: &reqwest::Response) -> Vec<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

pub fn location(res: &reqwest::Response) -> String {
    res.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string()
}

pub fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// `Set-Cookie: name=value; ...` の `name=value`
pub fn cookie_pair(cookies: &[String], name: &str) -> Option<String> {
    cookies
        .iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_string())
}

impl TestServer {
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client.get(self.url(path)).send().await.unwrap()
    }

    /// Wiki の画面と同じように、Cookie を API 用の短いトークンに換える
    pub async fn session_token(&self, cookie: &str) -> String {
        let res = self
            .client
            .post(self.url("/session-token"))
            .header(header::COOKIE, cookie)
            .header(header::ORIGIN, WIKI_ORIGIN)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        body["token"].as_str().unwrap().to_string()
    }

    pub async fn get_with_cookie(&self, path: &str, cookie: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .header(header::COOKIE, cookie)
            .send()
            .await
            .unwrap()
    }

    /// ログインを最初から最後まで通す。戻り値は (Cookie ヘッダーの値, 最後の 302 の行き先)
    pub async fn login_to(&self, code: &str, redirect: &str) -> (String, String) {
        let start = self
            .get(&format!(
                "/login?redirect={}",
                toro_auth::util::encode_uri_component(redirect)
            ))
            .await;
        assert_eq!(start.status(), 302);
        let state = query_param(&location(&start), "state").unwrap();
        let nonce = cookie_pair(&set_cookies(&start), "__Host-toro_login_nonce").unwrap();

        let callback = self
            .get_with_cookie(
                &format!(
                    "/callback?code={code}&state={}",
                    toro_auth::util::encode_uri_component(&state)
                ),
                &nonce,
            )
            .await;
        assert_eq!(callback.status(), 302, "callback for {code}");
        let cookie = cookie_pair(&set_cookies(&callback), "__Host-toro_session").unwrap();
        (cookie, location(&callback))
    }

    pub async fn login(&self, code: &str) -> String {
        self.login_to(code, "https://wiki.torosaba.net/").await.0
    }

    /// api / mcp と同じように、内側のポートでトークンを確かめる。通れば `claims`、通らなければ None
    pub async fn introspect(&self, token: &str) -> Option<Value> {
        let res = self
            .client
            .post(format!("{}/introspect", self.internal))
            .json(&json!({ "token": token }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        (body["active"] == true).then(|| body["claims"].clone())
    }
}
