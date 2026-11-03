//! auth.torosaba.net のトップページ

use axum::http::header::{self, HeaderValue};
use axum::response::Response;

use crate::App;
use crate::auth::session::{self, Session};
use crate::http::{self, Ctx};
use crate::template::{insert_block, render};

pub fn handle(app: &App, ctx: &Ctx) -> Response {
    let session = session::from_cookie(app, ctx);
    let (link, label) = match session {
        Some(_) => ("/api/auth/logout", "LOGOUT"),
        None => ("/api/auth/login", "LOGIN"),
    };
    let page = render(
        include_str!("../assets/home/home.html"),
        &[("LOGIN_LINK", link), ("LOGIN_LABEL", label)],
    );
    let block = session.as_ref().map_or_else(
        || include_str!("../assets/home/guest.html").to_string(),
        session_block,
    );
    let mut res = http::html(insert_block(&page, "USER_BLOCK", &block), 200);
    // トークン発行のボタンがあるので、枠に入れさせない
    res.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    res
}

fn session_block(session: &Session) -> String {
    let (edit_class, edit_label) = if session.can_edit() {
        ("term-green", "[ENABLED] TORO SERVER MEMBER")
    } else {
        ("term-yellow", "[READ ONLY] GUEST ACCESS")
    };
    render(
        include_str!("../assets/home/session.html"),
        &[
            ("DISPLAY_NAME", session.display_name()),
            ("USERNAME", session.username()),
            ("ID", session.id()),
            ("EDIT_CLASS", edit_class),
            ("EDIT_LABEL", edit_label),
            ("ROLES", &session.role_count().to_string()),
        ],
    )
}
