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

## 画面

| ホスト | 雰囲気 | スタイル |
| --- | --- | --- |
| mcp.torosaba.net | 草原の上に、黒地に白い角丸枠の窓とコマンド。文字が 1 字ずつ流れる窓 | `assets/mcp/theme.css` |
| auth.torosaba.net | 青いグラデーションの窓と銀の枠、指のカーソル、ステータスの画面 | `assets/auth/theme.css` |

16 ビット時代の RPG の画面の文法を、自作の CSS とドット絵だけで作っています。既存の作品の名前、用語、素材は使いません。

フォントは DotGothic16 (SIL Open Font License 1.1) を `assets/fonts/` に同梱し、自前で配っています (`/_assets/pixel.woff2`、ライセンスは `/_assets/OFL.txt`)。

## 開発

```bash
cargo test
```

`tests/common/mod.rs` が偽の Discord と GitHub を立てるので、試験に秘密やネットワークは要りません。

手元で動かすときは `.env.example` の必須の値を環境変数に入れ、`PUBLIC_AUTH_URL=http://localhost:8080` と、画面を動かす Origin を `CORS_ORIGINS` に足して `cargo run` します。

## 設定

`.env.example` を見てください。秘密でない値の既定は本番の値なので、本番の env ファイルに書くのは秘密だけです。

## イメージ

GitHub Actions が、試験に通ったものだけを GHCR に置きます (linux/amd64)。タグ `v*` を打つとバージョンのタグが付きます。

## セキュリティの考え方

- **セッション Cookie は auth.torosaba.net だけのもの** (`__Host-`)。他のサブドメインのサーバーには渡らず、差し替えもできない。Wiki は同じサイトの fetch なので今までどおり届く
- **Cookie で変更できるのは、信頼する Origin からだけ** (`CORS_ORIGINS` と自分自身)。他のサブドメインは信じない
- **MCP は Bearer だけ**。mcp.torosaba.net は Cookie を見ない
- **トークンから新しいトークンは作れない**。90 日トークンの発行と OAuth の同意は、ブラウザのセッションが要る
- **認可コードを出すのは、本人が同意画面で承認したときだけ**。承認のリンクはセッションと要求の内容に結び付けて署名してある
- **`client_id` を信じない**。ブランド名は戻り先のホストが本物のときだけ出し、それ以外は `UNVERIFIED` と戻り先を見せる
- **PKCE は S256 が必須**。Google Account Linking の戻り先だけ省略できる
- **scope を守る**。Wiki の変更には `write` か `mcp` が要る

試験は `tests/security.rs`。

### 知ったうえで残しているもの

- トークンを個別に失効できない。全部を無効にするには `JWT_SECRET` を変える
- `can_edit` はトークンの発行時のまま。ギルドを抜けても、トークンの期限 (30 / 90 日、リフレッシュ 180 日) までは編集できる
- リフレッシュトークンを更新時に取り替えない。クライアントにも結び付けていない
- 使用済みの認可コードの記録はメモリの中だけ。再起動の直後は、5 分以内のコードをもう一度使える
- `/api/auth/logout` は GET でも動く (他のサイトのリンクでログアウトさせられるが、それ以上のことはできない)
- 匿名の Wiki の読み取りは、サーバーの GitHub トークンの枠を使う。Cloudflare のレート制限で守る
- 動的登録は誰でもできて、内容を保存しない。戻り先は同意画面で利用者が確かめる

## Worker 版との違い

応答の形は同じですが、次を変えました。

- Discord ログイン直後にコードを出さず、同意画面に戻す。同意画面に戻り先と scope を出す
- 上の「セキュリティの考え方」のとおり、Cookie、CORS、PKCE、scope の扱いを厳しくした
- `redirect_uri` は https (手元は http)、アプリの独自スキームだけ
- ログインの `state` は署名し、Cookie と照合する
- 認可コードは一度だけ。リフレッシュトークンや認可コードをアクセストークンとして使えない
- 値はすべて HTML エスケープする。Wiki のパスはどの入口でも `..` を断る
- `wiki_search` は GitHub のコード検索 (TORO-Wiki を索引していない) をやめ、原稿をメモリに持って自分で探す
- `/api/auth/token` は POST だけ
- MCP は、無効なトークンに 401 と `WWW-Authenticate` を返す (クライアントが再認可できるように)。通知への応答は 202、`DELETE` は 405
- 稼働状態は外部の api.mcsrvstat.us でなく、Server List Ping で直接尋ねる
- ロールは Bot トークンが無くても、利用者のトークン (guilds.members.read) で読む
- mcp.torosaba.net の案内画面は、ログイン状態を表示しない (認証の管理は auth.torosaba.net)
- 案内画面のスクリーンショットは data: URI をやめて `/_assets/` から返す
