//! ブラウザで開いたときの接続手順の画面。誰が見ても同じ (mcp.torosaba.net には Cookie が届かない)

use crate::config::Config;
use crate::template::{insert_block, with_asset_version};

pub fn render_page(cfg: &Config) -> String {
    let page = insert_block(
        include_str!("../../assets/mcp/guide.html"),
        "USER_BLOCK",
        include_str!("../../assets/mcp/guide_auth.html"),
    );
    with_asset_version(&cfg.fill_links(&page))
}
