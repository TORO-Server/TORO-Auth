//! TORO Server 全般のツール

use serde_json::Value;

use super::success;
use crate::App;
use crate::minecraft;

pub async fn status(app: &App) -> Value {
    let cfg = &app.cfg;
    let Ok(status) = minecraft::ping(&cfg.mc_status_addr, &cfg.mc_status_host).await else {
        return success(
            "[TORO Server (Minecraft) 稼働状態]\n- 状態: [OFFLINE] オフライン\n- 接続アドレス: torosaba.net",
        );
    };

    let version = if status.version.is_empty() {
        "不明"
    } else {
        &status.version
    };
    let mut lines = vec![
        "[TORO Server (Minecraft) 稼働状態]".to_string(),
        "- 状態: [ONLINE] オンライン".to_string(),
        format!("- バージョン: {version}"),
        "- 接続アドレス: torosaba.net".to_string(),
        format!("- プレイヤー数: {} / {}", status.online, status.max),
    ];
    if !status.players.is_empty() {
        lines.push(format!("- ログイン中: {}", status.players.join(", ")));
    }
    if !status.motd.is_empty() {
        lines.push(format!("- MOTD: {}", status.motd.join(" / ")));
    }
    success(&lines.join("\n"))
}

pub fn info() -> Value {
    success(
        "【TORO Server 各種サービス一覧】
- 公式Webサイト: https://www.torosaba.net/
- 公式Wiki: https://wiki.torosaba.net/
- 2Dワールドマップ: https://map.torosaba.net/
- 3Dワールドマップ (BlueMap): https://3d-map.torosaba.net/
- 認証・AIコネクタゲートウェイ: https://auth.torosaba.net/
- Remote MCP サーバー: https://mcp.torosaba.net/
- Minecraft 接続先: torosaba.net",
    )
}
