//! ブラウザで開いたときの接続手順の画面

use crate::auth::session::Session;
use crate::template::{insert_block, render};

pub fn render_page(session: Option<&Session>) -> String {
    let block = match session {
        Some(session) => {
            let (edit_class, edit_label) = if session.can_edit() {
                ("text-green", "[有効] TORO サーバー所属メンバー")
            } else {
                ("text-yellow", "[閲覧のみ] ゲストアクセス")
            };
            render(
                include_str!("../../assets/mcp/guide_session.html"),
                &[
                    ("USERNAME", session.username()),
                    ("ID", session.id()),
                    ("EDIT_CLASS", edit_class),
                    ("EDIT_LABEL", edit_label),
                ],
            )
        }
        None => include_str!("../../assets/mcp/guide_guest.html").to_string(),
    };
    insert_block(
        include_str!("../../assets/mcp/guide.html"),
        "USER_BLOCK",
        &block,
    )
}
