//! TORO Server 共通認証 (auth.torosaba.net) と AI コネクタ (mcp.torosaba.net)。
//!
//! 機能ごとにモジュールを分けている:
//! - `auth`: Discord ログイン、セッション、API トークン
//! - `oauth`: AI クライアント向けの OAuth 2.0 認可サーバー
//! - `wiki`: GitHub 上の Wiki 原稿の読み書き
//! - `mcp`: Remote MCP サーバーとツール
//! - `minecraft`: Minecraft サーバーの稼働状態の取得
//! - `home` / `openapi` / `static_files`: 画面と仕様書
//!
//! 共通の部品は `config` / `http` / `jwt` / `template` / `util`、
//! URL から各機能への振り分けは `routes` にある。

pub mod auth;
pub mod config;
pub mod home;
pub mod http;
pub mod jwt;
pub mod mcp;
pub mod minecraft;
pub mod oauth;
pub mod openapi;
pub mod routes;
pub mod static_files;
pub mod template;
pub mod util;
pub mod wiki;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use config::Config;

/// リクエストをまたいで共有するもの
pub struct App {
    pub cfg: Config,
    pub http: reqwest::Client,
    /// 使い終わった認可コードの jti と有効期限 (再利用を断るため)
    pub used_codes: Mutex<HashMap<String, i64>>,
}

impl App {
    pub fn new(cfg: Config) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .user_agent("TORO-Auth-Gateway")
            .build()?;
        Ok(Self {
            cfg,
            http,
            used_codes: Mutex::new(HashMap::new()),
        })
    }
}
