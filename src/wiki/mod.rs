//! GitHub 上の Wiki 原稿の読み書き
//!
//! - `path`: 原稿のパスの検査と正規化
//! - `github`: GitHub API
//! - `api`: ブラウザ向けの REST API (/api/docs/*)

pub mod api;
pub mod github;
pub mod path;
