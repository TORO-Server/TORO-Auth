//! 画面から案内する Wiki のページ。URL は `Config` だけが持つ
//!
//! auth の役割は、だれなのかを確かめること (ログイン、トークンの発行、OAuth の認可)。
//! データ (api) と AI クライアントの接続先 (mcp) は別のサービスで、auth はそこへの案内だけを持つ。
//! 人向けの正本は Wiki の「サービスのURLと役割」のページ。

use crate::config::Config;
use crate::template;
use crate::util::encode_uri_component;

const CONNECT_PAGE: &str = "AIクライアントの接続方法";

impl Config {
    /// Wiki のページの URL。末尾の / まで付ける (無いと Wiki が 301 で付け直す)
    fn wiki_page(&self, name: &str) -> String {
        format!("{}/wiki/{}/", self.wiki_url, encode_uri_component(name))
    }

    /// 人向けの、AI クライアントのつなぎ方のページ
    pub fn connect_page(&self) -> String {
        self.wiki_page(CONNECT_PAGE)
    }

    /// 画面の中の `{{CONNECT_PAGE}}` に、設定の URL を入れる
    pub fn fill_links(&self, html: &str) -> String {
        template::render(html, &[("CONNECT_PAGE", &self.connect_page())])
    }
}
