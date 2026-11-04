# toro-auth

TORO Server の共通認証 (auth.torosaba.net) のサーバーです。Rust 製で、TORO のサーバーの上で動きます。

役割は「だれなのかを確かめる」ことだけです。以前はここに REST API と AI コネクタも同居していましたが、v2.0.0 で分けました。

## 3 つのサービス

| URL | 役割 | リポジトリ |
| --- | --- | --- |
| `https://auth.torosaba.net/` | だれなのかを確かめる: Discord ログイン、トークンの発行、OAuth 2.0 の認可 | このリポジトリ (`TORO-Server/TORO-Auth`) |
| `https://api.torosaba.net/` | データを読み書きする: Wiki の原稿、稼働状態、OpenAPI の仕様書 | `TORO-Server/TORO-API` |
| `https://mcp.torosaba.net/` | AI クライアントがつなぐ: Remote MCP サーバー | `TORO-Server/TORO-MCP` |

3 つは別々のコンテナで動き、別々にリリースします。api と mcp は署名の鍵 (`JWT_SECRET`) を持ちません。利用者の Bearer トークンは、auth の内側のポートで確かめます (下の「トークンの確認」)。

**URL の正本は 1 か所です。** 別の場所に書き写さないでください。

- コード: `Config` (`src/config.rs`) だけが URL を持ち、画面もここから作ります (`src/site.rs`)。api と mcp も、それぞれ自分の `Config` だけが持ちます
- プログラム向け: `https://api.torosaba.net/` の JSON
- 人向け: Wiki の「サービスのURLと役割」のページ

```
ブラウザ ───→ Cloudflare → cloudflared ─→ toro-auth:8080 ─── Discord API (ログイン)
                                              ▲
api / mcp ───── toro-auth:8081 /introspect ───┘   (Docker の内側のネットワークだけ)
```
データベースは使いません。セッションもトークンも署名付きの JWT です。ディスクに残すのは、90 日トークンの世代の記録 (`STATE_DIR`、既定は `/data`) だけです。トークンそのものは保存せず、発行の応答で一度だけ返します。再起動して失うのは、使用済みの認可コードの記録 (有効期限は 5 分) だけです。

## トークンの確認

`POST /introspect` (内側のポート `INTERNAL_PORT`、既定は 8081) は、api / mcp が利用者のトークンを確かめるための窓口です (RFC 7662 に倣った形)。

```
POST /introspect   {"token": "<Bearer のトークン>"}
200 {"active": true, "claims": {"id": "...", "username": "...", "can_edit": true, "scope": "..."}}
200 {"active": false}
```

- 通るのは、利用者の権限を表すトークンだけです (ブラウザのセッション、OAuth のアクセストークン、いまの世代の 90 日トークン)。認可コードやリフレッシュトークン、期限切れ、再作成で置き換えられた 90 日トークンは `active: false` です
- **このポートは Cloudflare のトンネルにも、ホストの `ports:` にも載せません。** Docker の内側のネットワークだけで届かせます。渡されたトークンの中身を返すだけなので、トークンを持たない者には何も渡りません
- 失効はこの場で効きます (api / mcp は結果をためません)
- **`claims.roles` は、トークンの値ではなく、いまの Discord のロールです** (`DISCORD_BOT_TOKEN` があるとき)。トークンに入っているロールは発行した時点のもので、30〜90 日古くなります。OAuth のアクセストークンは、そもそもロールが空で発行されます。権限の判断 (Admin かどうかなど) に使う側 (mcp / toro-guard) が、古いロールや空のロールで判断しないよう、確認のたびにここで調べて差し替えます (利用者ごとに 60 秒だけ覚えるので、ロールを外すと最長 60 秒で効きます)
- `claims.roles_source` が、その値の出どころです: `live` (いまの Discord で確かめた。ギルドを抜けた人は空のロール)、`unavailable` (Discord に尋ねられなかった。**ロールは空にして返します。古い値は信じません**)、`token` (Bot トークンが無く、トークンの値のまま)。権限の判断をする側は、`live` だけを信じてください

## 機能ごとの置き場所

| 機能 | ソース | 画面・定義 | 試験 |
| --- | --- | --- | --- |
| Discord ログイン、セッション、API トークンの発行と再作成 | `src/auth/` | `assets/auth/` | `tests/auth.rs` |
| AI クライアント向けの OAuth 2.0 | `src/oauth/` | `assets/oauth/` | `tests/oauth.rs` |
| api / mcp からのトークンの確認 | `src/internal.rs` | | `tests/hosts.rs` |
| 以前の URL の転送 | `src/routes.rs` | | `tests/hosts.rs` |
| アイコンとフォント | `src/static_files.rs` | `assets/icons/` `assets/fonts/` | `tests/hosts.rs` |
| トップページ | `src/home.rs` | `assets/home/` | `tests/auth.rs` |

共通の部品: `src/routes.rs` (URL の振り分け)、`src/http.rs` (応答と CORS)、`src/jwt.rs`、`src/template.rs`、`src/config.rs`。

URL を足すときは、機能のモジュールにハンドラーを書き、`src/routes.rs` に 1 行足します。

OAuth の保護されたリソースのメタデータ (RFC 9728) は、リソースの持ち主である mcp が答えます。認可サーバーのメタデータ (RFC 8414) はここです。

## 以前の URL

auth にあった `/mcp` `/sse` `/api/mcp` `/api/docs/*` `/openapi.json` `/.well-known/oauth-protected-resource*` は、正しいホストへ 308 で転送します (`moved_from_auth`)。

## 画面

auth.torosaba.net の画面は、夜の色に沈めた Dynmap の立体の地図の上に、青いグラデーションの窓と銀の枠、指のカーソルです (`assets/auth/theme.css`)。ログインの情報とトークンの発行だけを置きます。コネクタの名前はどのクライアントでも `TORO Server` です。

背景は map.torosaba.net の本物のタイルです。地図が更新されれば背景も変わり、読めないときは単色になります。

16 ビット時代の RPG の画面の文法を、自作の CSS とドット絵だけで作っています。既存の作品の名前、用語、素材は使いません。

フォントは DotGothic16 (SIL Open Font License 1.1) を `assets/fonts/` に同梱し、自前で配っています (`/_assets/pixel.woff2`、ライセンスは `/_assets/OFL.txt`)。

## 開発

```bash
cargo test
```

`tests/common/mod.rs` が偽の Discord を立てるので、試験に秘密やネットワークは要りません。

画面のスクリプトは TypeScript で書きます (`assets/home/token.ts`)。`build.rs` がビルドのときに JavaScript にしてバイナリに埋め込むので、ビルドに Node は要りません。型は CI の `tsc` が確かめます。

手元で動かすときは `.env.example` の必須の値を環境変数に入れ、`PUBLIC_AUTH_URL=http://localhost:8080` と、画面を動かす Origin を `CORS_ORIGINS` に足して `cargo run` します。api と mcp を一緒に動かすなら、それぞれの `AUTH_INTERNAL_URL` を `http://localhost:8081` にします。

## 設定

`.env.example` を見てください。秘密でない値の既定は本番の値なので、本番の env ファイルに書くのは秘密だけです (`JWT_SECRET` と `DISCORD_CLIENT_SECRET`)。GitHub のトークンは api が持つので、ここには要りません。

## イメージ

GitHub Actions が、試験に通ったものだけを GHCR に置きます (linux/amd64)。タグ `v*` を打つとバージョンのタグが付きます。

## v1.x からの切り替え

v1.x は 1 つのコンテナが 3 つのホストすべてに答えていました。v2 へは、次の順で切り替えます。

1. `toro-api` と `toro-mcp` を、`toro-auth` と同じ Docker のネットワークに起動する。`toro-api` の env ファイルに `GITHUB_TOKEN` を入れる
2. `toro-auth` を v2 にする。`toro-auth.env` の `GITHUB_TOKEN` は使わなくなる。内側のポート 8081 は `ports:` に載せない
3. 確かめる: `toro-api` と `toro-mcp` のコンテナの中から、`toro-auth:8081/healthz` に届くこと
4. Cloudflare のトンネルの公開ルートを変える: `api.torosaba.net` → `http://toro-api:8080`、`mcp.torosaba.net` → `http://toro-mcp:8080`、`auth.torosaba.net` は `http://toro-auth:8080` のまま

戻すときは、ルートを `http://toro-auth:8080` に戻し、`toro-auth` を v1.3.6 のタグにします。

## セキュリティの考え方

- **セッション Cookie は auth.torosaba.net だけのもの** (`__Host-`)。他のサブドメインのサーバーには渡らず、差し替えもできない。Wiki は同じサイトの fetch なので今までどおり届く
- **Cookie で変更できるのは、信頼する Origin からだけ** (`CORS_ORIGINS` と自分自身)。他のサブドメインは信じない
- **api と mcp は Bearer だけ**。Cookie を見ない。Wiki の画面は Cookie を 10 分のトークンに換えて (`/api/auth/session-token`) API を呼ぶ
- **署名の鍵は auth だけが持つ**。api と mcp が侵害されても、トークンは作れない
- **トークンから新しいトークンは作れない**。90 日トークンの発行と OAuth の同意は、ブラウザのセッションが要る
- **認可コードを出すのは、本人が同意画面で承認したときだけ**。承認のリンクはセッションと要求の内容に結び付けて署名してある
- **`client_id` を信じない**。ブランド名は戻り先のホストが本物のときだけ出し、それ以外は `UNVERIFIED` と戻り先を見せる
- **PKCE は S256 が必須**。Google Account Linking の戻り先だけ省略できる
- **`redirect_uri` は https (手元は http) とアプリの独自スキームだけ**。ログインの `state` は署名し、Cookie と照合する
- **認可コードは一度だけ**。リフレッシュトークンや認可コードを、アクセストークンとしては使えない。`/api/auth/token` は POST だけ
- 画面に出す値はすべて HTML エスケープする。ロールは Bot トークンが無くても、利用者のトークン (guilds.members.read) で読む
- **scope を守る**。Wiki の変更には `write` か `mcp` が要る (判断するのは api / mcp。scope は確認の応答で渡す)

試験は `tests/security.rs`。

### 知ったうえで残しているもの

- 90 日トークンは再作成で失効するが、OAuth のトークンを個別に失効できない。全部を無効にするには `JWT_SECRET` を変える
- `can_edit` はトークンの発行時のまま。ギルドを抜けても、トークンの期限 (30 / 90 日、リフレッシュ 180 日) までは編集できる
- リフレッシュトークンを更新時に取り替えない。クライアントにも結び付けていない
- 使用済みの認可コードの記録はメモリの中だけ。再起動の直後は、5 分以内のコードをもう一度使える
- `/api/auth/logout` は GET でも動く (他のサイトのリンクでログアウトさせられるが、それ以上のことはできない)
- 動的登録は誰でもできて、内容を保存しない。戻り先は同意画面で利用者が確かめる
- 内側のポートは認証を持たない。ネットワークで守る (Docker の内側だけに置く)
- auth が止まると、api と mcp は Bearer 付きのリクエストを確かめられず 503 を返す。Bearer の無い読み取りは影響を受けない
