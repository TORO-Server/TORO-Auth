//! Remote MCP サーバー (mcp.torosaba.net)
//!
//! - `transport`: HTTP / SSE と JSON-RPC の受け口
//! - `guide`: ブラウザで開いたときの接続手順の画面
//! - `tools`: ツールの定義と実行 (機能ごとのファイルに分けてある)

pub mod tools;
pub mod transport;
