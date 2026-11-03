# toro-auth

TORO Server の共通認証 (auth.torosaba.net) と AI コネクタ (mcp.torosaba.net) です。Rust 製で、TORO のサーバーの上で動きます。
Cloudflare Workers の toro-auth の置き換えで、公開している URL と応答の形はそのままです。

```
ブラウザ / AI クライアント → Cloudflare → cloudflared ─→ toro-auth:8080 ─┬─ Discord API (ログイン)
                                                                           ├─ GitHub API (Wiki の原稿)
                                                                           └─ toro-velocity:25565 (稼働状態)
```

データベースは使いません。セッションもトークンも署名付きの JWT です。再起動して失うのは、使用済みの認可コードの記録 (有効期限は 5 分) だけです。

## 機能ごとの置き場所

| 機能 | ソース | 画面・定義 | 試験 |
| --- | --- | --- | --- |
| Discord ログイン、セッション、API トークン | `src/auth/` | `assets/auth/` | `tests/auth.rs` |
| AI クライアント向けの OAuth 2.0 | `src/oauth/` | `assets/oauth/` | `tests/oauth.rs` |
| Wiki の原稿の読み書き (GitHub) | `src/wiki/` | | `tests/wiki.rs` |
| Remote MCP サーバーとツール | `src/mcp/` | `assets/mcp/` | `tests/mcp.rs` |
| Minecraft の稼働状態 | `src/minecraft.rs` | | 同じファイル内 |
| トップページ | `src/home.rs` | `assets/home/` | `tests/auth.rs` |
| OpenAPI 仕様 | `src/openapi.rs` | `assets/openapi/` | `tests/auth.rs` |

共通の部品: `src/routes.rs` (URL の振り分け)、`src/http.rs` (応答と CORS)、`src/jwt.rs`、`src/template.rs`、`src/config.rs`。

- URL を足す: 機能のモジュールにハンドラーを書き、`src/routes.rs` に 1 行足す
- MCP のツールを足す: `assets/mcp/tools.json` に定義を、`src/mcp/tools/` に実行を書き、`tools/mod.rs` の `call` に 1 行足す

## 開発

```bash
cargo test
```

`tests/common/mod.rs` が偽の Discord と GitHub を立てるので、試験に秘密やネットワークは要りません。

手元で動かすときは `.env.example` の必須の値を環境変数に入れ、`COOKIE_DOMAIN=` (空) と `PUBLIC_AUTH_URL=http://localhost:8080` を足して `cargo run` します。

## 設定

`.env.example` を見てください。秘密でない値の既定は本番の値なので、本番の env ファイルに書くのは秘密だけです。

## イメージ

GitHub Actions が、試験に通ったものだけを GHCR に置きます (linux/amd64)。タグ `v*` を打つとバージョンのタグが付きます。

## Worker 版との違い

応答の形は同じですが、次の穴は塞いであります。

- `/oauth/authorize?auto=1` や `approved=1` を付けた URL を踏ませるだけで、攻撃者の `redirect_uri` に認可コードが渡っていた → 承認のリンクに、セッションと要求の内容に結び付けた署名を入れた。Discord ログイン直後にコードを出さず、同意画面に戻す
- `redirect_uri` に `javascript:` や他人の http のサイトを指定できた → https (手元は http)、アプリの独自スキームだけにした。同意画面に戻り先を表示する
- ログインの `state` に署名もブラウザとの結び付きも無かった → 署名し、Cookie と照合する
- PKCE は `code_verifier` を省略すると検査されなかった → 必須にした (challenge があるとき)
- 認可コードを何度でも使えた → 一度だけ
- リフレッシュトークンや認可コードを、アクセストークンとして使えた → type で区別する
- 利用者の名前や `client_id` を HTML にそのまま埋め込んでいた → すべてエスケープする
- Wiki のパスの `..` の検査が保存の API だけだった → 読み書きのどの入口でも検査する
- `wiki_search` に `repo:` を混ぜると他のリポジトリの結果が見えた → このリポジトリの docs/ に絞る
- `/api/auth/token` が GET でも発行していた → POST だけ

変えたもの:

- 稼働状態を外部の api.mcsrvstat.us でなく、Server List Ping で直接尋ねる
- ロールは Bot トークンが無くても、利用者のトークン (guilds.members.read) で読む
- 案内画面のスクリーンショットは data: URI をやめて `/_assets/` から返す
