//! auth.torosaba.net のトップページ: ログインの情報とトークンの発行だけを置く

use axum::http::header::{self, HeaderValue};
use axum::response::Response;

use crate::App;
use crate::auth::account::iso8601;
use crate::auth::discord;
use crate::auth::session::{self, Session};
use crate::http::{self, Ctx};
use crate::template::{escape, insert_block, render};

const JST_OFFSET: i64 = 9 * 3600;
/// トークンを画面に出すので、自分のスクリプトと画像のほかは読ませない。枠にも入れさせない
const CSP_HOME: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data: https://map.torosaba.net https://cdn.discordapp.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub async fn handle(app: &App, ctx: &Ctx) -> Response {
    let block = match session::from_cookie(app, ctx) {
        Some(session) => session_block(app, &session).await,
        None => include_str!("../assets/home/guest.html").to_string(),
    };
    let page = insert_block(
        include_str!("../assets/home/home.html"),
        "USER_BLOCK",
        &block,
    );
    let mut res = http::html(page, 200);
    res.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP_HOME),
    );
    res
}

async fn session_block(app: &App, session: &Session) -> String {
    let (edit_class, edit_label, gauge_class) = if session.can_edit() {
        ("good", "編集できます", "")
    } else {
        ("warn", "読むだけ", "empty")
    };
    let expires_at = app.tokens.expires_at(session.id());
    let (token_status, token_action) = match expires_at {
        Some(exp) => (
            format!("{} まで有効", &iso8601(exp + JST_OFFSET)[..10]),
            "トークンを再作成する",
        ),
        None => ("未発行".to_string(), "トークンを発行する"),
    };
    let block = render(
        include_str!("../assets/home/session.html"),
        &[
            ("AVATAR_URL", session.avatar_url()),
            ("DISPLAY_NAME", session.display_name()),
            ("USERNAME", session.username()),
            ("ID", session.id()),
            ("EDIT_CLASS", edit_class),
            ("EDIT_LABEL", edit_label),
            ("GAUGE_CLASS", gauge_class),
            ("TOKEN_STATUS", &token_status),
            ("TOKEN_ACTION", token_action),
            (
                "TOKEN_EXISTS",
                if expires_at.is_some() {
                    "true"
                } else {
                    "false"
                },
            ),
        ],
    );
    insert_block(&block, "ROLE_LIST", &role_list(app, session).await)
}

/// 名前が分かるロールは名前で、分からないものは ID で、すべて並べる
async fn role_list(app: &App, session: &Session) -> String {
    let ids = session.role_ids();
    if ids.is_empty() {
        return "なし".to_string();
    }
    let names = discord::role_names(app).await;
    let items: String = ids
        .iter()
        .map(|id| {
            let label = names.get(*id).map_or(*id, String::as_str);
            format!("<li>{}</li>", escape(label))
        })
        .collect();
    format!("<ul class=\"roles\">{items}</ul>")
}
