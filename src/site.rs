//! 各サービスの URL と役割。URL はここが読む `Config` だけが持ち、画面も API の応答もここから作る
//!
//! - auth: だれなのかを確かめる (ログイン、トークンの発行、OAuth の認可)
//! - api: データを読み書きする (REST API)
//! - mcp: AI クライアントがつなぐ (Remote MCP)
//!
//! 人向けの正本は Wiki の「サービスのURLと役割」のページ。

use serde_json::{Value, json};
use url::Url;

use crate::config::Config;
use crate::template;
use crate::util::encode_uri_component;

const ROLES_PAGE: &str = "サービスのURLと役割";

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

    /// 人向けの正本のページ
    pub fn roles_page(&self) -> String {
        format!(
            "{}/wiki/{}",
            self.wiki_url,
            encode_uri_component(ROLES_PAGE)
        )
    }

    /// 画面の中の `{{AUTH_URL}}` などに、設定の URL を入れる
    pub fn fill_links(&self, html: &str) -> String {
        template::render(
            html,
            &[
                ("AUTH_URL", &self.issuer),
                ("API_URL", &self.api_url),
                ("MCP_URL", &self.mcp_url),
                ("WIKI_URL", &self.wiki_url),
                ("ROLES_PAGE", &self.roles_page()),
            ],
        )
    }
}
