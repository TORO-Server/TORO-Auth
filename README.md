# toro-auth

TORO Server の認証、REST API、AI コネクタのサーバーです。Rust 製で、TORO のサーバーの上で動きます。

## 3 つの窓口

| URL | 役割 | ここにあるもの |
| --- | --- | --- |
| `https://auth.torosaba.net/` | だれなのかを確かめる | Discord ログイン、トークンの発行、OAuth 2.0 の認可 |
| `https://api.torosaba.net/` | データを読み書きする | Wiki の原稿の取得と保存、OpenAPI の仕様書 |
| `https://mcp.torosaba.net/` | AI クライアントがつなぐ | Remote MCP サーバー。ブラウザで開くと Wiki の「AIクライアントの接続方法」へ移動する |

ホストごとに、自分の役割の URL にだけ答えます (`src/routes.rs`)。以前の URL は正しいホストへ 308 で転送します。

**URL の正本は 1 か所です。** 別の場所に書き写さないでください。

- コード: `Config` (`src/config.rs`) だけが URL を持ち、画面も API の応答もここから作ります (`src/site.rs`)
- プログラム向け: `https://api.torosaba.net/` の JSON
- 人向け: Wiki の「サービスのURLと役割」のページ

```
ブラウザ / AI クライアント → Cloudflare → cloudflared ─→ toro-auth:8080 ─┬─ Discord API (ログイン)
                                                                           ├─ GitHub API (Wiki の原稿)
                                                                           └─ toro-velocity:25565 (稼働状態)
```
データベースは使いません。セッションもトークンも署名付きの JWT です。ディスクに残すのは、90 日トークンの世代の記録 (`STATE_DIR`、既定は `/data`) だけです。トークンそのものは保存せず、発行の応答で一度だけ返します。再起動して失うのは、使用済みの認可コードの記録 (有効期限は 5 分) だけです。

## 機能ごとの置き場所

| 機能 | ソース | 画面・定義 | 試験 |
| --- | --- | --- | --- |
| Discord ログイン、セッション、API トークンの発行と再作成 | `src/auth/` | `assets/auth/` | `tests/auth.rs` |
| AI クライアント向けの OAuth 2.0 | `src/oauth/` | `assets/oauth/` | `tests/oauth.rs` |
| Wiki の原稿の読み書き (GitHub) | `src/wiki/` | | `tests/wiki.rs` |
| Remote MCP サーバーとツール | `src/mcp/` | `assets/mcp/` | `tests/mcp.rs` |
| アイコン (Wiki と同じ TORO のアイコン) | `src/static_files.rs` | `assets/icons/` | `tests/mcp.rs` |
| Minecraft の稼働状態 | `src/minecraft.rs` | | 同じファイル内 |
| トップページ | `src/home.rs` | `assets/home/` | `tests/auth.rs` |
| REST API の入り口 | `src/api.rs` | | `tests/hosts.rs` |
| OpenAPI 仕様 | `src/openapi.rs` | `assets/openapi/` | `tests/hosts.rs` |

共通の部品: `src/routes.rs` (URL の振り分け)、`src/http.rs` (応答と CORS)、`src/jwt.rs`、`src/template.rs`、`src/config.rs`。

- URL を足す: 機能のモジュールにハンドラーを書き、`src/routes.rs` に 1 行足す
- MCP のツールを足す: `assets/mcp/tools.json` に定義を、`src/mcp/tools/` に実行を書き、`tools/mod.rs` の `call` に 1 行足す

## 画面

auth.torosaba.net の画面は、夜の色に沈めた Dynmap の立体の地図の上に、青いグラデーションの窓と銀の枠、指のカーソルです (`assets/auth/theme.css`)。ログインの情報とトークンの発行だけを置きます。mcp.torosaba.net は画面を持ちません。コネクタの名前はどのクライアントでも `TORO Server` です。

背景は map.torosaba.net の本物のタイルです。地図が更新されれば背景も変わり、読めないときは単色になります。

16 ビット時代の RPG の画面の文法を、自作の CSS とドット絵だけで作っています。既存の作品の名前、用語、素材は使いません。

フォントは DotGothic16 (SIL Open Font License 1.1) を `assets/fonts/` に同梱し、自前で配っています (`/_assets/pixel.woff2`、ライセンスは `/_assets/OFL.txt`)。

## 開発

```bash
cargo test
```

`tests/common/mod.rs` が偽の Discord と GitHub を立てるので、試験に秘密やネットワークは要りません。

画面のスクリプトは TypeScript で書きます (`assets/home/token.ts`)。`build.rs` がビルドのときに JavaScript にしてバイナリに埋め込むので、ビルドに Node は要りません。型は CI の `tsc` が確かめます。

手元で動かすときは `.env.example` の必須の値を環境変数に入れ、`PUBLIC_AUTH_URL=http://localhost:8080`、`PUBLIC_API_URL=http://api.localhost:8080`、`PUBLIC_MCP_URL=http://mcp.localhost:8080` と、画面を動かす Origin を `CORS_ORIGINS` に足して `cargo run` します。ブラウザは `*.localhost` を手元につなぎます。

## 設定

`.env.example` を見てください。秘密でない値の既定は本番の値なので、本番の env ファイルに書くのは秘密だけです。

## イメージ

GitHub Actions が、試験に通ったものだけを GHCR に置きます (linux/amd64)。タグ `v*` を打つとバージョンのタグが付きます。

## セキュリティの考え方

- **セッション Cookie は auth.torosaba.net だけのもの** (`__Host-`)。他のサブドメインのサーバーには渡らず、差し替えもできない。Wiki は同じサイトの fetch なので今までどおり届く
- **Cookie で変更できるのは、信頼する Origin からだけ** (`CORS_ORIGINS` と自分自身)。他のサブドメインは信じない
- **API は Bearer だけ**。Wiki の画面は Cookie を 10 分のトークンに換えて (`/api/auth/session-token`) API を呼ぶ
- **MCP は Bearer だけ**。mcp.torosaba.net は Cookie を見ない
- **トークンから新しいトークンは作れない**。90 日トークンの発行と OAuth の同意は、ブラウザのセッションが要る
- **認可コードを出すのは、本人が同意画面で承認したときだけ**。承認のリンクはセッションと要求の内容に結び付けて署名してある
- **`client_id` を信じない**。ブランド名は戻り先のホストが本物のときだけ出し、それ以外は `UNVERIFIED` と戻り先を見せる
- **PKCE は S256 が必須**。Google Account Linking の戻り先だけ省略できる
- **scope を守る**。Wiki の変更には `write` か `mcp` が要る

試験は `tests/security.rs`。

### 知ったうえで残しているもの

- 90 日トークンは再作成で失効するが、OAuth のトークンを個別に失効できない。全部を無効にするには `JWT_SECRET` を変える
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
