//! Discord ログインと、`.torosaba.net` で共有するセッション
//!
//! - `session`: Cookie / Bearer からのセッションの取り出し
//! - `login`: Discord へのログインとコールバック
//! - `discord`: Discord API
//! - `account`: ログイン後の操作 (自分の情報、ログアウト、API トークン)

pub mod account;
pub mod discord;
pub mod login;
pub mod session;
pub mod tokens;
