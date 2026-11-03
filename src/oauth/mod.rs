//! AI クライアント向けの OAuth 2.0 認可サーバー
//!
//! - `metadata`: 発見用のメタデータ (RFC 8414 / RFC 9728)
//! - `register`: 動的クライアント登録 (RFC 7591)
//! - `authorize`: 認可エンドポイントと同意の流れ
//! - `pages`: 同意画面などの HTML
//! - `token`: トークンエンドポイント
//! - `userinfo`: OIDC UserInfo

pub mod authorize;
pub mod metadata;
pub mod pages;
pub mod register;
pub mod token;
pub mod userinfo;

pub(crate) const CODE_TYPE: &str = "oauth_code";
pub(crate) const REFRESH_TOKEN_TYPE: &str = "mcp_refresh_token";
pub(crate) const DEFAULT_SCOPE: &str = "read write mcp";
