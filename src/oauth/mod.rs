//! AI クライアント向けの OAuth 2.0 認可サーバー
//!
//! - `metadata`: 発見用のメタデータ (RFC 8414 / RFC 9728)
//! - `register`: 動的クライアント登録 (RFC 7591)
//! - `authorize`: 認可エンドポイントと同意の流れ
//! - `client`: クライアントの見分け方と、戻り先の検査
//! - `grants`: 連携の、最後に使った時刻の記録 (使っている間は続き、一定期間使わないと無効になる)
//! - `pages`: 同意画面などの HTML
//! - `token`: トークンエンドポイント
//! - `userinfo`: OIDC UserInfo

pub mod authorize;
pub mod client;
pub mod grants;
pub mod metadata;
pub mod pages;
pub mod register;
pub mod token;
pub mod userinfo;

pub(crate) const CODE_TYPE: &str = "oauth_code";
pub(crate) const REFRESH_TOKEN_TYPE: &str = "mcp_refresh_token";
// scope を省いたクライアントへの既定は読み取りだけにする。write と mcp は、
// クライアントが明示して求め、同意画面に出たときだけ発行する
pub(crate) const DEFAULT_SCOPE: &str = "read";
