#!/bin/bash
# toro-auth.env の秘密を入力する (サーバーの上で動かす)。
#   入力は画面に出ない。空のまま Enter を押すと、今の値を残す。
#   JWT_SECRET は変えない (変えると全員がログアウトされる)。
set -euo pipefail

ENV_FILE="${TORO_AUTH_ENV:-/home/toroserver/toro-auth.env}"

[ -f "$ENV_FILE" ] || { echo "$ENV_FILE がありません" >&2; exit 1; }

# Client ID は env ファイルから読む (リポジトリに実値を書かない)
DISCORD_CLIENT_ID=$(grep '^DISCORD_CLIENT_ID=' "$ENV_FILE" | tail -n 1 | cut -d '=' -f 2-)
[ -n "$DISCORD_CLIENT_ID" ] || { echo "DISCORD_CLIENT_ID が $ENV_FILE にありません" >&2; exit 1; }

# 値を置き換えて、同じ場所にまるごと書き戻す (途中で失敗しても壊さない)
set_value() {
  local name=$1 value=$2 tmp
  tmp=$(mktemp "$ENV_FILE.XXXXXX")
  chmod --reference="$ENV_FILE" "$tmp"
  chgrp --reference="$ENV_FILE" "$tmp"
  { grep -v "^$name=" "$ENV_FILE" || true; printf '%s=%s\n' "$name" "$value"; } > "$tmp"
  mv "$tmp" "$ENV_FILE"
}

ask_secret() {
  local label=$1 name=$2 value
  read -rsp "$label: " value
  echo >&2
  value=${value//[[:space:]]/}
  if [ -n "$value" ]; then
    set_value "$name" "$value"
    printf '%s' "$value"
  fi
}

echo "--- 1/2 Discord の Client Secret"
echo "  Reset Secret を押すと、切り替えが終わるまで新規ログインができなくなります。"
discord=$(ask_secret "DISCORD_CLIENT_SECRET" DISCORD_CLIENT_SECRET)
if [ -n "$discord" ]; then
  code=$(printf 'user = "%s:%s"\n' "$DISCORD_CLIENT_ID" "$discord" | curl -s -o /dev/null -w '%{http_code}' -K - \
    -d 'grant_type=client_credentials&scope=identify' https://discord.com/api/v10/oauth2/token)
  [ "$code" = 200 ] && echo "  OK: Discord に受け付けられました" || echo "  NG: Discord の応答が $code です。値を確かめて、もう一度実行してください"
fi

echo
echo "--- 2/2 Wiki を編集できるロール"
read -rp "DISCORD_REQUIRED_ROLE_ID (ギルドの全員のままなら空で Enter): " role
role=${role//[[:space:]]/}
if [ -n "$role" ]; then
  case "$role" in
    *[!0-9]*) echo "  NG: ロール ID は数字だけです。保存しませんでした" ;;
    *) set_value DISCORD_REQUIRED_ROLE_ID "$role"; echo "  OK: 保存しました" ;;
  esac
fi

echo
echo "完了。設定されている項目 (値は表示しません):"
while IFS='=' read -r name value; do
  [ -n "$name" ] || continue
  [ -n "$value" ] && state="設定済み" || state="空"
  printf '  %-26s %s\n' "$name" "$state"
done < "$ENV_FILE"
