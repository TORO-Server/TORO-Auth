# toro-auth

TORO Server の共通認証 (auth.torosaba.net) のサーバーです。Rust 製で、TORO のサーバーの上で動きます。

役割は「だれなのかを確かめる」ことだけです。

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
データベースは使いません。セッションもトークンも署名付きの JWT です。ディスクに残すのは、90 日トークンの世代の記録と、OAuth の連携の「最後に使った時刻」の記録 (`STATE_DIR`、既定は `/data`) だけです。トークンそのものは保存せず、発行の応答で一度だけ返します。再起動して失うのは、使用済みの認可コードの記録 (有効期限は 5 分) だけです。

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
- **`claims.can_edit` も、いまのロールから決めます** (`DISCORD_REQUIRED_ROLE_ID` のロールがあるか。指定が無ければメンバー全員)。ロールを外すと、最長 60 秒で Wiki を編集できなくなります
- `claims.roles_source` が、その値の出どころです: `live` (いまの Discord で確かめた。ギルドを抜けた人は空のロールで `can_edit` は false)、`unavailable` (Discord に尋ねられなかった。**ロールは空、`can_edit` は false にして返します。古い値は信じません**)、`token` (Bot トークンが無く、トークンの値のまま)。権限の判断をする側は、`live` だけを信じてください

## OAuth のログインの続き方 (使っている間は続き、使わないと無効になる)

OAuth の連携 (認可コードをトークンに換えたときに 1 つできる) は、**使っている間はログインが続き、`OAUTH_IDLE_DAYS` (既定 30 日) 使わないと無効になります。**

- アクセストークンとリフレッシュトークンに、連携の ID (`gid`) が入ります。連携の「最後に使った時刻」を `STATE_DIR/oauth-grants.json` に覚えます (トークンそのものは覚えません)
- トークンが確認されるたびに (api / mcp / toro-guard の `/introspect`、userinfo、リフレッシュ) 最後に使った時刻を更新します。書き出しは 5 分ごとにまとめます (落ちたときに失うのは、その分の「使った」だけです)
- 最後に使ってから期間を過ぎた連携は、アクセストークンもリフレッシュトークンも通りません (`invalid_grant`: "not used for a while")。**もう一度ログインして連携します。** 一度無効になった連携は、あとから使っても戻りません
- リフレッシュのたびに、新しいリフレッシュトークンを返します (署名の期限 180 日も、使っている間は延びます)。アクセストークンの署名の期限 (30 日) は、リフレッシュで新しくなります。リフレッシュしないクライアントは、30 日で連携し直しになります
- 記録を失った (ファイルが消えた・壊れた) 連携は、無効になります (安全な側)。クライアントは、もう一度連携します
- `gid` を持たないトークンは通りません
- 1 人が持てる連携は 32 個までです。超えると、いちばん長く使っていないものから無効になります
- 90 日トークン (`/token`) には、この仕組みは掛かりません (再作成か、期限 90 日で終わります)
## 機能ごとの置き場所

| 機能 | ソース | 画面・定義 | 試験 |
| --- | --- | --- | --- |
| Discord ログイン、セッション、API トークンの発行と再作成 | `src/auth/` | `assets/auth/` | `tests/auth.rs` |
| AI クライアント向けの OAuth 2.0 | `src/oauth/` | `assets/oauth/` | `tests/oauth.rs` |
| api / mcp からのトークンの確認 | `src/internal.rs` | | `tests/hosts.rs` |
| アイコンとフォント | `src/static_files.rs` | `assets/icons/` `assets/fonts/` | `tests/hosts.rs` |
| トップページ | `src/home.rs` | `assets/home/` | `tests/auth.rs` |

共通の部品: `src/routes.rs` (URL の振り分け)、`src/http.rs` (応答と CORS)、`src/jwt.rs`、`src/template.rs`、`src/config.rs`。

URL を足すときは、機能のモジュールにハンドラーを書き、`src/routes.rs` に 1 行足します。

OAuth の保護されたリソースのメタデータ (RFC 9728) は、リソースの持ち主である mcp が答えます。認可サーバーのメタデータ (RFC 8414) はここです。

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

## セキュリティの考え方

- **セッション Cookie は auth.torosaba.net だけのもの** (`__Host-`)。他のサブドメインのサーバーには渡らず、差し替えもできない。Wiki は同じサイトの fetch なので今までどおり届く
- **Cookie で変更できるのは、信頼する Origin からだけ** (`CORS_ORIGINS` と自分自身)。他のサブドメインは信じない。90 日トークンの発行と再作成は、auth 自身の画面からだけ (Wiki の画面が作れるのは 10 分のトークンだけ)
- **api と mcp は Bearer だけ**。Cookie を見ない。Wiki の画面は Cookie を 10 分のトークンに換えて (`/session-token`) API を呼ぶ
- **署名の鍵は auth だけが持つ**。api と mcp が侵害されても、トークンは作れない
- **トークンから新しいトークンは作れない**。90 日トークンの発行と OAuth の同意は、ブラウザのセッションが要る
- **認可コードを出すのは、本人が同意画面で承認したときだけ**。承認のリンクはセッションと要求の内容に結び付けて署名してある。ブラウザの先読みでは承認しない
- **`client_id` を信じない**。ブランド名は戻り先のホストが本物のとき (ポートの指定も無いとき) だけ出し、それ以外は「未確認」と戻り先を見せる。google.com はサブドメインをまとめて信じず、決まったホストだけ
- **PKCE は S256 が必須**。Google Account Linking の戻り先 (`oauth-redirect.googleusercontent.com` と `oauth-redirect-sandbox.googleusercontent.com`) だけ省略できる
- **`redirect_uri` は https (手元は http) とアプリの独自スキームだけ**。`user@host` の形は断る。ログインの `state` は署名し、Cookie と照合する
- **認可コードは一度だけ**。リフレッシュトークンや認可コードを、アクセストークンとしては使えない。`/token` は POST だけ
- **期限の無いトークンは通さない**。発行するトークンには必ず `exp` が入る
- **画面は CSP で守る**。スクリプトを動かすのはトップページの自分のスクリプトだけで、他の画面にはスクリプトが無い
- 画面に出す値はすべて HTML エスケープする。ロールは Bot トークンが無くても、利用者のトークン (guilds.members.read) で読む
- **scope を守る**。Wiki の変更には `write` か `mcp` が要る。mcp の管理用のツールには `mcp` が要る (判断するのは api / mcp / guard。scope は確認の応答で渡す)。`mcp` を求める同意画面には、Admin 以上の人が何を許すことになるかを書く
- **遅い送信で同時処理の枠を埋めさせない**。ボディは 30 秒で読み切れなければ 408 で切る

試験は `tests/security.rs`。

### 知ったうえで残しているもの

- 90 日トークンは再作成で失効するが、OAuth のトークンを個別に失効できない。全部を無効にするには `JWT_SECRET` を変える
- `can_edit` と `roles` がいまの値になるのは、確認の窓口の答えだけ。auth の画面と `/session` の表示は、トークンの発行時の値 (表示だけで、権限の判断には使わない)。Bot トークンが無いときは、確認の窓口の答えも発行時の値のまま
- リフレッシュトークンは、更新のたびに新しくする (署名の期限を延ばすため)。古いものも、連携が有効なあいだは使えるので、盗まれたときの再利用の検知はしていない。発行したときの `client_id` と違う値を送ると断るが、`client_id` を送らなければ確かめない (公開クライアントなので、秘密ではない)
- 使用済みの認可コードの記録はメモリの中だけ。再起動の直後は、5 分以内のコードをもう一度使える
- `/logout` は GET でも動く (他のサイトのリンクでログアウトさせられるが、それ以上のことはできない)
- 動的登録は誰でもできて、内容を保存しない。戻り先は同意画面で利用者が確かめる
- 内側のポートは認証を持たない。ネットワークで守る (Docker の内側だけに置く)
- auth が止まると、api と mcp は Bearer 付きのリクエストを確かめられず 503 を返す。Bearer の無い読み取りは影響を受けない
