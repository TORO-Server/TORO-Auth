//! ブラウザで開いたときの接続手順の画面。誰が見ても同じ (mcp.torosaba.net には Cookie が届かない)

use crate::template::insert_block;

pub fn render_page() -> String {
    insert_block(
        include_str!("../../assets/mcp/guide.html"),
        "USER_BLOCK",
        include_str!("../../assets/mcp/guide_auth.html"),
    )
}
