//! TORO Server の共通認証 (auth)、REST API (api)、AI コネクタ (mcp)。役割と URL は `site` を見てください。
//!
//! 機能ごとにモジュールを分けている:
//! - `auth`: Discord ログイン、セッション、API トークン
//! - `oauth`: AI クライアント向けの OAuth 2.0 認可サーバー
//! - `wiki`: GitHub 上の Wiki 原稿の読み書き
//! - `mcp`: Remote MCP サーバーとツール
//! - `minecraft`: Minecraft サーバーの稼働状態の取得
//! - `home` / `openapi` / `static_files`: 画面と仕様書
//!
//! - `api`: api.torosaba.net の入り口
//!
//! 共通の部品は `config` / `site` / `http` / `jwt` / `template` / `util`、
//! URL から各機能への振り分けは `routes` にある。

pub mod api;
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
pub mod site;
pub mod static_files;
pub mod template;
pub mod util;
pub mod wiki;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use config::Config;
use tokio::sync::Semaphore;

/// 同時に処理するリクエストの上限 (ボディは最大 2 MiB なので、メモリは約 512 MiB まで)
const MAX_CONCURRENT_REQUESTS: usize = 256;
/// 開けたままにできる SSE の上限
pub const MAX_SSE_STREAMS: usize = 128;

/// リクエストをまたいで共有するもの
pub struct App {
    pub cfg: Config,
    pub http: reqwest::Client,
    /// 使い終わった認可コードの jti と有効期限 (再利用を断るため)
    pub used_codes: Mutex<HashMap<String, i64>>,
    pub requests: Semaphore,
    pub sse_streams: Arc<Semaphore>,
    pub wiki_index: wiki::search::Index,
    pub tokens: auth::tokens::TokenStore,
}

impl App {
    pub fn new(cfg: Config) -> Result<Self, reqwest::Error> {
        let wiki_index_ttl = Duration::from_secs(cfg.wiki_index_ttl_secs);
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .user_agent("TORO-Auth-Gateway")
            .build()?;
        let tokens = auth::tokens::TokenStore::load(&cfg.state_dir);
        Ok(Self {
            cfg,
            tokens,
            http,
            used_codes: Mutex::new(HashMap::new()),
            requests: Semaphore::new(MAX_CONCURRENT_REQUESTS),
            sse_streams: Arc::new(Semaphore::new(MAX_SSE_STREAMS)),
            wiki_index: wiki::search::Index::new(wiki_index_ttl),
        })
    }
}
