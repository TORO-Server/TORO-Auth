# toro-auth

TORO Server の共通認証サービスです。Rust で書かれています。

役割は「だれなのかを確かめる」ことだけです。Discord でのログイン、トークンの発行、AI クライアント向けの OAuth 2.0 の認可を受け持ちます。データを読み書きするのは [TORO-API](https://github.com/TORO-Server/TORO-API)、AI クライアントの接続先は [TORO-MCP](https://github.com/TORO-Server/TORO-MCP) です。

## 動かしてみる

```bash
cargo test   # 試験。偽の Discord を自動で立てるので、秘密もネットワークも要りません
cargo run    # 動かす。必須の環境変数は .env.example を見てください
```

設定の名前と既定値の正本は [.env.example](.env.example) です。秘密の値 (`JWT_SECRET` と `DISCORD_CLIENT_SECRET`) だけを、置き場の外の環境変数に書きます。

## 関連文書

- トークンの確認、OAuth のログインの続き方、機能ごとのソースの場所、安全のための決まり: [docs/design.md](docs/design.md)
- サービス全体の構成: [ServerImage-TORO の docs/architecture.md](https://github.com/TORO-Server/ServerImage-TORO/blob/main/docs/architecture.md)
- 文章の書き方: [WRITING-STYLE.md](https://github.com/TORO-Server/TORO-Website/blob/main/docs/WRITING-STYLE.md)
