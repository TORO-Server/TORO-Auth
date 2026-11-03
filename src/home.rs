//! auth.torosaba.net のトップページ: ログインの情報とトークンの発行だけを置く

use axum::http::header::{self, HeaderValue};
use axum::response::Response;

use crate::App;
use crate::auth::account::iso8601;
use crate::auth::session::{self, Session};
use crate::http::{self, Ctx};
use crate::template::{insert_block, render};

const JST_OFFSET: i64 = 9 * 3600;

pub fn handle(app: &App, ctx: &Ctx) -> Response {
    let block = session::from_cookie(app, ctx).map_or_else(
        || include_str!("../assets/home/guest.html").to_string(),
        |session| session_block(app, &session),
    );
    let page = insert_block(
        include_str!("../assets/home/home.html"),
        "USER_BLOCK",
        &block,
    );
    let mut res = http::html(page, 200);
    // トークン発行のボタンがあるので、枠に入れさせない
    res.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    res
}

fn session_block(app: &App, session: &Session) -> String {
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
    render(
        include_str!("../assets/home/session.html"),
        &[
            ("AVATAR_URL", session.avatar_url()),
            ("DISPLAY_NAME", session.display_name()),
            ("USERNAME", session.username()),
            ("ID", session.id()),
            ("EDIT_CLASS", edit_class),
            ("EDIT_LABEL", edit_label),
            ("GAUGE_CLASS", gauge_class),
            ("ROLES", &session.role_count().to_string()),
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
    )
}
