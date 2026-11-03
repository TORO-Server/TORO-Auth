//! 各サービスの URL と役割。URL はここが読む `Config` だけが持ち、画面も API の応答もここから作る
//!
//! - auth: だれなのかを確かめる (ログイン、トークンの発行、OAuth の認可)
//! - api: データを読み書きする (REST API)
//! - mcp: AI クライアントがつなぐ (Remote MCP)
//!
//! 人向けの正本は Wiki の「サービスのURLと役割」のページ。

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use url::Url;

use crate::config::Config;
use crate::template;
use crate::util::encode_uri_component;

const ROLES_PAGE: &str = "サービスのURLと役割";
const CONNECT_PAGE: &str = "AIクライアントの接続方法";

/// リクエストのホストが担当する役割
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Auth,
    Api,
    Mcp,
}

fn host_of(url: &str) -> Option<String> {
    Url::parse(url).ok()?.host_str().map(str::to_string)
}

/// 本体を埋め込んだ TORO のアイコン。Gemini は CSP で外部の画像を読めないので、AI クライアントにはこれを伝える
pub fn icon_data_uri() -> String {
    let png = STANDARD.encode(include_bytes!("../assets/icons/icon-64.png"));
    format!("data:image/png;base64,{png}")
}

impl Config {
    /// 知らないホストは auth として扱う (手元の開発環境の localhost など)
    pub fn role_of(&self, host: &str) -> Role {
        if host_of(&self.mcp_url).as_deref() == Some(host) {
            Role::Mcp
        } else if host_of(&self.api_url).as_deref() == Some(host) {
            Role::Api
        } else {
            Role::Auth
        }
    }

    /// 機械向けの URL の一覧
    pub fn services(&self) -> Value {
        json!({ "auth": self.issuer, "api": self.api_url, "mcp": self.mcp_url })
    }

    /// Wiki のページの URL。末尾の / まで付ける (無いと Wiki が 301 で付け直す)
    fn wiki_page(&self, name: &str) -> String {
        format!("{}/wiki/{}/", self.wiki_url, encode_uri_component(name))
    }

    /// 人向けの、URL と役割のページ
    pub fn roles_page(&self) -> String {
        self.wiki_page(ROLES_PAGE)
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
