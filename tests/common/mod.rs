//! 結合試験の共通部品: 偽の Discord / GitHub と、試験用に起動した本体
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::to_bytes;
use axum::extract::Request;
use axum::http::{Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use toro_auth::App;
use toro_auth::config::Config;

pub const GUILD: &str = "000000000000000000";
pub const JWT_SECRET: &str = "test-secret-test-secret-test-secret";

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
            _ => json_response(404, json!({ "message": "not found" })),
        }
    });
    spawn(router).await
}

/// 原稿を覚えておくだけの GitHub
#[derive(Default)]
pub struct FakeGitHub {
    /// エンコードされたままのパス → (sha, 本文)
    pub files: Mutex<HashMap<String, (String, String)>>,
    pub commits: Mutex<Vec<Value>>,
    pub requests: Mutex<Vec<String>>,
}

async fn start_fake_github(state: Arc<FakeGitHub>) -> String {
    let router = Router::new().fallback(move |req: Request| {
        let state = state.clone();
        async move {
            let (parts, body) = req.into_parts();
            let body = to_bytes(body, usize::MAX).await.unwrap();
            let path = parts.uri.path().to_string();
            state.requests.lock().unwrap().push(parts.uri.to_string());

            if path.ends_with("/search/code") {
                return json_response(
                    200,
                    json!({ "items": [
                        { "path": "docs/hit.md", "repository": { "full_name": "TORO-Server/TORO-Wiki" } },
                        { "path": "docs/secret.md", "repository": { "full_name": "TORO-Server/Private" } },
                        { "path": "README.md", "repository": { "full_name": "TORO-Server/TORO-Wiki" } },
                    ] }),
                );
            }
            if path.ends_with("/git/trees/main") {
                return json_response(
                    200,
                    json!({ "tree": [
                        { "path": "docs/01_About/a.md", "type": "blob" },
                        { "path": "docs/02_Guide/b.md", "type": "blob" },
                        { "path": "docs/image.png", "type": "blob" },
                        { "path": "docs/01_About", "type": "tree" },
                        { "path": "README.md", "type": "blob" },
                    ] }),
                );
            }

            let Some(file_path) = path.strip_prefix("/repos/TORO-Server/TORO-Wiki/contents/") else {
                return json_response(404, json!({ "message": "Not Found" }));
            };
            let file_path = file_path.to_string();
            if parts.method == Method::GET {
                let files = state.files.lock().unwrap();
                return match files.get(&file_path) {
                    Some((sha, content)) => {
                        // 本物と同じく、60 文字ごとに改行が入った base64
                        let encoded = STANDARD.encode(content);
                        let wrapped: Vec<String> =
                            encoded.as_bytes().chunks(60).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
                        json_response(
                            200,
                            json!({ "path": file_path, "sha": sha, "size": content.len(), "content": wrapped.join("\n") }),
                        )
                    }
                    None => json_response(404, json!({ "message": "Not Found" })),
                };
            }

            let payload: Value = serde_json::from_slice(&body).unwrap();
            let mut files = state.files.lock().unwrap();
            if let Some((sha, _)) = files.get(&file_path)
                && payload["sha"].as_str() != Some(sha) {
                    return json_response(409, json!({ "message": format!("{file_path} does not match {sha}") }));
                }
            let new_sha = format!("sha-{}", state.commits.lock().unwrap().len() + 1);
            let content = String::from_utf8(STANDARD.decode(payload["content"].as_str().unwrap()).unwrap()).unwrap();
            files.insert(file_path, (new_sha.clone(), content));
            state.commits.lock().unwrap().push(payload);
            json_response(200, json!({ "commit": { "sha": "commit-1" }, "content": { "sha": new_sha } }))
        }
    });
    spawn(router).await
}

pub struct TestServer {
    pub base: String,
    pub client: reqwest::Client,
    pub github: Arc<FakeGitHub>,
}

pub async fn start() -> TestServer {
    start_with(|_| {}).await
}

pub async fn start_with(customize: impl FnOnce(&mut Config)) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let github = Arc::new(FakeGitHub::default());

    let mut cfg = Config {
        port: 0,
        issuer: base.clone(),
        mcp_url: "https://mcp.torosaba.net".into(),
        cookie_domain: String::new(),
        jwt_secret: JWT_SECRET.into(),
        discord_client_id: "client".into(),
        discord_client_secret: "secret".into(),
        discord_redirect_uri: format!("{base}/api/auth/callback"),
        discord_guild_id: GUILD.into(),
        discord_required_role_id: None,
        discord_bot_token: None,
        discord_api: start_fake_discord().await,
        github_token: "gh-token".into(),
        github_owner: "TORO-Server".into(),
        github_repo: "TORO-Wiki".into(),
        github_branch: "main".into(),
        github_api: start_fake_github(github.clone()).await,
        // 誰も待っていないポート
        mc_status_addr: "127.0.0.1:9".into(),
        mc_status_host: "torosaba.net".into(),
    };
    customize(&mut cfg);

    let router = toro_auth::routes::router(Arc::new(App::new(cfg).unwrap()));
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    TestServer {
        base,
        client,
        github,
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
                "/api/auth/login?redirect={}",
                toro_auth::util::encode_uri_component(redirect)
            ))
            .await;
        assert_eq!(start.status(), 302);
        let state = query_param(&location(&start), "state").unwrap();
        let nonce = cookie_pair(&set_cookies(&start), "toro_login_nonce").unwrap();

        let callback = self
            .get_with_cookie(
                &format!(
                    "/api/auth/callback?code={code}&state={}",
                    toro_auth::util::encode_uri_component(&state)
                ),
                &nonce,
            )
            .await;
        assert_eq!(callback.status(), 302, "callback for {code}");
        let cookie = cookie_pair(&set_cookies(&callback), "toro_session").unwrap();
        (cookie, location(&callback))
    }

    pub async fn login(&self, code: &str) -> String {
        self.login_to(code, "https://wiki.torosaba.net/").await.0
    }

    pub fn put_file(&self, encoded_path: &str, sha: &str, content: &str) {
        self.github.files.lock().unwrap().insert(
            encoded_path.to_string(),
            (sha.to_string(), content.to_string()),
        );
    }

    /// JSON-RPC を 1 回呼ぶ
    pub async fn rpc(
        &self,
        method: &str,
        params: Value,
        bearer: Option<&str>,
    ) -> reqwest::Response {
        let mut request = self
            .client
            .post(self.url("/mcp"))
            .json(&json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params }));
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        request.send().await.unwrap()
    }

    /// ツールを呼び、結果の本文と isError を返す
    pub async fn tool(&self, name: &str, arguments: Value, bearer: Option<&str>) -> (String, bool) {
        let res = self
            .rpc(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
                bearer,
            )
            .await;
        assert_eq!(res.status(), 200);
        let body: Value = res.json().await.unwrap();
        let result = &body["result"];
        (
            result["content"][0]["text"].as_str().unwrap().to_string(),
            result["isError"] == true,
        )
    }
}
