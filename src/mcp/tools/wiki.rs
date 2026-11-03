//! Wiki のツール

use serde_json::Value;

use super::{arg, failure, success};
use crate::App;
use crate::auth::session::Session;
use crate::wiki::github::{self, Commit};
use crate::wiki::path;

/// 検索結果を返す上限
const MAX_SEARCH_RESULTS: usize = 30;

fn bullets(items: &[String]) -> String {
    items
        .iter()
        .map(|item| format!("- {item}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub async fn list_pages(app: &App, args: &Value) -> Value {
    let pages = github::list_pages(app, args["category"].as_str()).await;
    success(&format!(
        "取得ドキュメント総数: {}\n\n{}",
        pages.len(),
        bullets(&pages)
    ))
}

pub async fn get_page(app: &App, args: &Value) -> Value {
    let requested = arg(args, "path");
    if requested.is_empty() {
        return failure("Error: \"path\" 引数は必須です。");
    }
    let not_found = || {
        failure(&format!(
            "Error: 指定されたパス \"{requested}\" にドキュメントが見つかりません。"
        ))
    };
    let Some(clean_path) = path::normalize(requested) else {
        return not_found();
    };
    match github::get_file(app, &clean_path).await {
        Ok(Some(file)) => success(&format!(
            "=== Path: {} (SHA: {}) ===\n\n{}",
            file.path, file.sha, file.content
        )),
        Ok(None) => not_found(),
        Err(message) => failure(&format!("内部エラー: {message}")),
    }
}

pub async fn save_page(app: &App, args: &Value, session: Option<&Session>) -> Value {
    let Some(user) = session else {
        return failure(
            "認証エラー: Wiki の保存・編集を行うには Discord 認証が必要です。認可フローを完了させてください。",
        );
    };
    if !user.can_write() {
        return failure(&format!(
            "権限エラー: ユーザー \"{}\" には TORO Server Wiki の編集権限（メンバーシップと write の許可）がありません。",
            user.username()
        ));
    }

    let requested = arg(args, "path");
    let content = arg(args, "content");
    if requested.is_empty() || content.is_empty() {
        return failure("Error: \"path\" および \"content\" は必須です。");
    }
    if path::normalize(requested).is_none() {
        return failure(&format!("Error: パス \"{requested}\" は使えません。"));
    }

    let message = args["message"]
        .as_str()
        .unwrap_or("Update via AI Connector");
    let commit_message = format!("docs: {message} (by {} via TORO Server)", user.username());
    let commit = Commit {
        path: requested,
        content,
        sha: args["sha"].as_str(),
        message: Some(&commit_message),
        user,
    };
    match github::commit_file(app, &commit).await {
        Ok((commit_sha, _)) => success(&format!(
            "コミット成功！\n- コミット SHA: {commit_sha}\n- ファイル: {requested}\n- コミット者: {}",
            user.username()
        )),
        Err(message) => failure(&format!("コミット失敗: {message}")),
    }
}

pub async fn search(app: &App, args: &Value) -> Value {
    let query = arg(args, "query");
    let Some(hits) = app.wiki_index.search(app, query).await else {
        return failure("Error: Wiki の検索に失敗しました。しばらくしてからやり直してください。");
    };
    let body = if hits.is_empty() {
        "一致するドキュメントは見つかりませんでした。".to_string()
    } else if hits.len() > MAX_SEARCH_RESULTS {
        format!(
            "{}\n\n(ほかに {} 件)",
            bullets(&hits[..MAX_SEARCH_RESULTS]),
            hits.len() - MAX_SEARCH_RESULTS
        )
    } else {
        bullets(&hits)
    };
    success(&format!("検索結果 \"{query}\":\n\n{body}"))
}
