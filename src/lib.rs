//! TORO Server の共通認証 (auth.torosaba.net)。
//!
//! だれなのかを確かめるところだけを受け持つ。データ (api) と AI コネクタ (mcp) は別のサービスで、
//! 利用者のトークンは `internal` の確認の窓口で auth に尋ねる。
//!
//! 機能ごとにモジュールを分けている:
//! - `auth`: Discord ログイン、セッション、API トークン
//! - `oauth`: AI クライアント向けの OAuth 2.0 認可サーバー
//! - `internal`: api / mcp からのトークンの確認 (内側のポートだけ)
//! - `home` / `static_files`: 画面
//!
//! 共通の部品は `config` / `site` / `http` / `jwt` / `template` / `util`、
//! URL から各機能への振り分けは `routes` にある。

pub mod auth;
pub mod config;
pub mod home;
pub mod http;
pub mod internal;
pub mod jwt;
pub mod oauth;
pub mod routes;
pub mod site;
pub mod static_files;
pub mod template;
pub mod util;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use config::Config;
use tokio::sync::Semaphore;

/// 同時に処理するリクエストの上限 (ボディは最大 2 MiB なので、メモリは約 512 MiB まで)
const MAX_CONCURRENT_REQUESTS: usize = 256;

/// リクエストをまたいで共有するもの
pub struct App {
    pub cfg: Config,
    pub http: reqwest::Client,
    /// 使い終わった認可コードの jti と有効期限 (再利用を断るため)
    pub used_codes: Mutex<HashMap<String, i64>>,
    pub requests: Semaphore,
    pub tokens: auth::tokens::TokenStore,
    /// OAuth の連携の、最後に使った時刻 (使わないまま期間が過ぎると無効にする)
    pub grants: oauth::grants::GrantStore,
    pub role_names: auth::discord::RoleNames,
    /// 利用者のいまのロール (確認の窓口が、権限の判断に使う)
    pub live_roles: auth::discord::LiveRolesCache,
}

impl App {
    pub fn new(cfg: Config) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .user_agent("TORO-Auth-Gateway")
            .build()?;
        let tokens = auth::tokens::TokenStore::load(&cfg.state_dir);
        let grants = oauth::grants::GrantStore::load(&cfg.state_dir);
        Ok(Self {
            cfg,
            tokens,
            grants,
            role_names: Default::default(),
            live_roles: Default::default(),
            http,
            used_codes: Mutex::new(HashMap::new()),
            requests: Semaphore::new(MAX_CONCURRENT_REQUESTS),
        })
    }

    /// 一度きりのトークン (認可コードや consent) の jti を記録し、消費する。初出なら true
    pub fn consume_jti(&self, jti: &str, exp: i64) -> bool {
        let mut used = self.used_codes.lock().expect("used_codes lock");
        let now = jwt::now();
        used.retain(|_, until| *until >= now);
        used.insert(jti.to_string(), exp).is_none()
    }
}
