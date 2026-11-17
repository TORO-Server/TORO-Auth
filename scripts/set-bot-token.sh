#!/bin/bash
# Discord の Bot トークンを認証サービスの env ファイルに入れて、認証サービスを入れ直す (サーバーの上で動かす)。
#   必須の環境変数: TORO_AUTH_ENV (env ファイルのパス)、AUTH_SERVICE (compose のサービス名)
#   入力は画面に出ない。ギルドのロールを読めるトークンだけを保存する。
set -euo pipefail

ENV_FILE="${TORO_AUTH_ENV:?TORO_AUTH_ENV に env ファイルのパスを指定してください}"
AUTH_SERVICE="${AUTH_SERVICE:?AUTH_SERVICE に compose の認証サービス名を指定してください}"
COMPOSE_DIR="${TORO_COMPOSE_DIR:-/home/toroserver}"

[ -f "$ENV_FILE" ] || { echo "$ENV_FILE がありません" >&2; exit 1; }

# ギルド ID は env ファイルから読む (リポジトリに実値を書かない)
GUILD_ID=$(grep '^DISCORD_GUILD_ID=' "$ENV_FILE" | tail -n 1 | cut -d '=' -f 2-)
[ -n "$GUILD_ID" ] || { echo "DISCORD_GUILD_ID が $ENV_FILE にありません" >&2; exit 1; }

read -rsp "DISCORD_BOT_TOKEN: " token
echo
token=${token//[[:space:]]/}
[ -n "$token" ] || { echo "空なので、何も変えませんでした"; exit 0; }

code=$(printf 'Authorization: Bot %s\n' "$token" | curl -s -o /dev/null -w '%{http_code}' -H @- \
  "https://discord.com/api/v10/guilds/$GUILD_ID/roles")
case "$code" in
  200) echo "OK: ギルドのロールを読めました" ;;
  401) echo "NG: トークンが正しくありません (401)。保存しませんでした"; exit 1 ;;
  403|404) echo "NG: この Bot はギルドに入っていません ($code)。招待してから、もう一度実行してください"; exit 1 ;;
  *) echo "NG: Discord の応答が $code です。保存しませんでした"; exit 1 ;;
esac

tmp=$(mktemp "$ENV_FILE.XXXXXX")
chmod --reference="$ENV_FILE" "$tmp"
chgrp --reference="$ENV_FILE" "$tmp"
{ grep -v '^DISCORD_BOT_TOKEN=' "$ENV_FILE" || true; printf 'DISCORD_BOT_TOKEN=%s\n' "$token"; } > "$tmp"
mv "$tmp" "$ENV_FILE"

cd "$COMPOSE_DIR"
docker compose up -d --no-deps --force-recreate "$AUTH_SERVICE"
echo "完了。auth.torosaba.net を開き直すと、ロールの名前が出ます"
