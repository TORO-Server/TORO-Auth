# toro-auth

TORO Server の共通認証サービスです。Rust で書かれています。

役割は「だれなのかを確かめる」ことだけです。Discord でのログイン、トークン (本人確認済みの印になる文字列) の発行、AI クライアント (AI を使うアプリ) 向けの OAuth 2.0 (パスワードを渡さずにアプリへ利用を許す決まり) の認可を受け持ちます。データを読み書きするのは [TORO-API](https://github.com/TORO-Server/TORO-API)、AI クライアントの接続先は [TORO-MCP](https://github.com/TORO-Server/TORO-MCP) です。

## 動かしてみる

```bash
cargo test   # 試験。偽の Discord を自動で立てるので、秘密もネットワークも要りません
cargo run    # 動かす。必須の環境変数は .env.example を見てください
```

設定の名前と既定値の正本は [.env.example](.env.example) です。秘密の値 (`JWT_SECRET` と `DISCORD_CLIENT_SECRET`) だけを、置き場の外の環境変数に書きます。

## 関連文書

- トークンの確認、OAuth のログインの続き方、機能ごとのソースの場所、安全のための決まり: [docs/design.md](docs/design.md)
