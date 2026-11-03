//! GitHub API (Wiki 原稿のリポジトリ)

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::StatusCode;
use serde_json::{Map, Value, json};

use super::path;
use crate::App;
use crate::auth::session::Session;
use crate::util::encode_uri_component;

fn request(app: &App, method: reqwest::Method, url: String) -> reqwest::RequestBuilder {
    app.http
        .request(method, url)
        .bearer_auth(&app.cfg.github_token)
        .header("Accept", "application/vnd.github.v3+json")
}

fn repo_url(app: &App) -> String {
    format!(
        "{}/repos/{}/{}",
        app.cfg.github_api, app.cfg.github_owner, app.cfg.github_repo
    )
}

fn encode_segments(path: &str) -> String {
    path.split('/')
        .map(encode_uri_component)
        .collect::<Vec<_>>()
        .join("/")
}

pub struct WikiFile {
    pub path: String,
    pub sha: String,
    pub content: String,
    pub size: u64,
}

/// `path` は wiki::path::normalize を通したもの
pub async fn get_file(app: &App, clean_path: &str) -> Result<Option<WikiFile>, String> {
    let url = format!(
        "{}/contents/{}?ref={}",
        repo_url(app),
        encode_segments(clean_path),
        encode_uri_component(&app.cfg.github_branch)
    );
    let res = request(app, reqwest::Method::GET, url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        let text = res.text().await.unwrap_or_default();
        return Err(format!("GitHub API error ({}): {text}", status.as_u16()));
    }
    let data: Value = res.json().await.map_err(|e| e.to_string())?;
    let encoded: String = data["content"]
        .as_str()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes = STANDARD.decode(encoded).map_err(|e| e.to_string())?;
    Ok(Some(WikiFile {
        path: data["path"].as_str().unwrap_or(clean_path).to_string(),
        sha: data["sha"].as_str().unwrap_or("").to_string(),
        content: String::from_utf8_lossy(&bytes).into_owned(),
        size: data["size"].as_u64().unwrap_or(0),
    }))
}

pub struct Commit<'a> {
    pub path: &'a str,
    pub content: &'a str,
    pub sha: Option<&'a str>,
    pub message: Option<&'a str>,
    pub user: &'a Session,
}

/// 原稿を保存してコミットする。戻り値は (コミットの SHA, ファイルの SHA)
pub async fn commit_file(app: &App, commit: &Commit<'_>) -> Result<(String, String), String> {
    let clean_path = path::normalize(commit.path).ok_or_else(|| "Invalid path".to_string())?;

    let current_sha = match commit.sha.filter(|s| !s.is_empty()) {
        Some(sha) => Some(sha.to_string()),
        None => get_file(app, &clean_path).await?.map(|file| file.sha),
    };

    let user = commit.user;
    let display_name = user.display_name();
    let email = format!("{}+discord@users.noreply.torosaba.net", user.id());
    let message = match commit.message.filter(|m| !m.is_empty()) {
        Some(message) => format!("{message}\n\nCo-authored-by: {display_name} <{email}>"),
        None => format!(
            "Wiki update: {clean_path}\n\nEdited via Browser/API by Discord user {display_name} ({})",
            user.id()
        ),
    };
    let author = json!({ "name": format!("{display_name} (via Discord)"), "email": email });

    let mut payload = Map::new();
    payload.insert("message".into(), json!(message));
    payload.insert("content".into(), json!(STANDARD.encode(commit.content)));
    payload.insert("branch".into(), json!(app.cfg.github_branch));
    payload.insert("committer".into(), author.clone());
    payload.insert("author".into(), author);
    if let Some(sha) = current_sha {
        payload.insert("sha".into(), json!(sha));
    }

    let url = format!(
        "{}/contents/{}",
        repo_url(app),
        encode_segments(&clean_path)
    );
    let res = request(app, reqwest::Method::PUT, url)
        .json(&Value::Object(payload))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    if !status.is_success() {
        let text = res.text().await.unwrap_or_default();
        return Err(format!("GitHub Commit error ({}): {text}", status.as_u16()));
    }
    let data: Value = res.json().await.map_err(|e| e.to_string())?;
    Ok((
        data["commit"]["sha"].as_str().unwrap_or("").to_string(),
        data["content"]["sha"].as_str().unwrap_or("").to_string(),
    ))
}

pub struct DocBlob {
    /// docs/ から始まるパス
    pub path: String,
    pub sha: String,
}

/// docs/ の下の原稿のパスと SHA。取得に失敗したら None
pub async fn doc_blobs(app: &App) -> Option<Vec<DocBlob>> {
    let url = format!(
        "{}/git/trees/{}?recursive=1",
        repo_url(app),
        encode_uri_component(&app.cfg.github_branch)
    );
    let res = request(app, reqwest::Method::GET, url).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let data: Value = res.json().await.ok()?;
    Some(
        data["tree"]
            .as_array()?
            .iter()
            .filter(|item| item["type"] == "blob")
            .filter_map(|item| {
                let path = item["path"].as_str()?;
                let is_doc = path.starts_with("docs/") && path.ends_with(".md");
                is_doc.then(|| DocBlob {
                    path: path.to_string(),
                    sha: item["sha"].as_str().unwrap_or("").to_string(),
                })
            })
            .collect(),
    )
}

/// docs/ の下の原稿の一覧 (docs/ を除いたパス)。取得に失敗したら空
pub async fn list_pages(app: &App, category: Option<&str>) -> Vec<String> {
    doc_blobs(app)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|blob| blob.path.trim_start_matches("docs/").to_string())
        .filter(|path| category.is_none_or(|c| path.starts_with(c)))
        .collect()
}

/// 原稿の本文を SHA で読む
pub async fn blob_text(app: &App, sha: &str) -> Option<String> {
    let url = format!("{}/git/blobs/{sha}", repo_url(app));
    let res = request(app, reqwest::Method::GET, url).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let data: Value = res.json().await.ok()?;
    decode_content(&data["content"]).ok()
}

fn decode_content(content: &Value) -> Result<String, String> {
    let encoded: String = content
        .as_str()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes = STANDARD.decode(encoded).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
