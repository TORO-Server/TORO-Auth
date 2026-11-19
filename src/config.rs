//! 環境変数からの設定。秘密と Discord の ID は env で必須 (リポジトリに実値を書かない)。それ以外の値の既定は本番の値にしてある

use crate::jwt::{Keys, Kind, MIN_KEY_BYTES};

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    /// api / mcp からのトークンの確認を受ける内側のポート (公開しない)
    pub internal_port: u16,
    /// 認可サーバーの公開 URL (末尾の / なし)
    pub issuer: String,
    /// Wiki の公開 URL (末尾の / なし)
    pub wiki_url: String,
    /// Cookie 付きで API を呼べる Origin (他のサブドメインは信じない)
    pub cors_origins: Vec<String>,

    /// トークンの種類ごとの署名の鍵
    pub jwt_keys: Keys,
    /// 鍵の移行期間の旧鍵 (3.0.1 までの `JWT_SECRET`)。検証だけに使い、発行には使わない。
    /// `JWT_LEGACY_VERIFY_UNTIL` (UNIX 秒) を設定したときだけ読む。種類は Connector / Access / Refresh だけ
    pub legacy_secret: Option<String>,
    /// 旧鍵での検証を受け付ける期限 (UNIX 秒)。起動時から `MAX_LEGACY_WINDOW_SECS` 以内でなければ起動しない
    pub legacy_verify_until: Option<i64>,
    /// `/introspect` を呼ぶ側 (api / mcp) の共有秘密。設定すると、`X-Toro-Token` が一致しない呼び出しを断る。
    /// 無いときは、これまでどおり内側のネットワークの到達だけを信じる (呼び出し側へ秘密を渡してから設定する)
    pub introspect_secret: Option<String>,

    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub discord_redirect_uri: String,
    pub discord_guild_id: String,
    pub discord_required_role_id: Option<String>,
    pub discord_bot_token: Option<String>,
    pub discord_api: String,

    /// 再起動しても残す記録の置き場所 (90 日トークンの世代、OAuth の連携)
    pub state_dir: String,
    /// OAuth の連携を、使わないまま置いてよい秒数。これを過ぎた連携は、トークンが通らなくなる (使っている間は続く)
    pub oauth_idle_seconds: i64,
    /// リクエストのボディを読み切るまで待つ秒数。遅い送信で同時処理の枠を埋めさせない
    pub body_read_timeout_secs: u64,
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn or_default(name: &str, default: &str) -> String {
    optional(name).unwrap_or_else(|| default.to_string())
}

fn trimmed(name: &str, default: &str) -> String {
    or_default(name, default).trim_end_matches('/').to_string()
}

/// 旧鍵での検証を受け付けてよい最長の期間 (秒)。これより先の期限は設定できない
pub const MAX_LEGACY_WINDOW_SECS: i64 = 90 * 86400;

/// 移行期間の設定。`JWT_LEGACY_VERIFY_UNTIL` が無ければ旧鍵は読まない (`JWT_SECRET` が env に残っていても無視する)。
/// 値の中身はエラーにも出さない
fn legacy_from_env(new_keys: &[String; 7]) -> Result<(Option<String>, Option<i64>), String> {
    let Some(until) = optional("JWT_LEGACY_VERIFY_UNTIL") else {
        return Ok((None, None));
    };
    let until: i64 = until
        .parse()
        .map_err(|_| "JWT_LEGACY_VERIFY_UNTIL must be a UNIX time in seconds".to_string())?;
    let now = crate::jwt::now();
    if until <= now || until > now + MAX_LEGACY_WINDOW_SECS {
        return Err(format!(
            "JWT_LEGACY_VERIFY_UNTIL must be in the future and within {} days",
            MAX_LEGACY_WINDOW_SECS / 86400
        ));
    }
    let Some(secret) = optional("JWT_SECRET") else {
        return Err("JWT_LEGACY_VERIFY_UNTIL needs JWT_SECRET (the previous key)".to_string());
    };
    if secret.len() < MIN_KEY_BYTES {
        return Err(format!("JWT_SECRET must be at least {MIN_KEY_BYTES} bytes"));
    }
    if new_keys.contains(&secret) {
        return Err("JWT_SECRET (previous key) must differ from the new keys".to_string());
    }
    Ok((Some(secret), Some(until)))
}

impl Config {
    /// Cookie 付きのリクエストを受けてよい送り元か (自分自身と、指定の Origin)
    pub fn is_trusted_origin(&self, origin: &str) -> bool {
        origin == self.issuer || self.cors_origins.iter().any(|o| o == origin)
    }

    /// 移行期間の旧鍵。期限を過ぎたら None (旧鍵で署名されたトークンは、そこから通らなくなる)
    pub fn legacy_key(&self) -> Option<&str> {
        match (&self.legacy_secret, self.legacy_verify_until) {
            (Some(secret), Some(until)) if crate::jwt::now() <= until => Some(secret),
            _ => None,
        }
    }

    pub fn from_env() -> Result<Self, String> {
        let mut missing = Vec::new();
        let mut required = |name: &'static str| {
            optional(name).unwrap_or_else(|| {
                missing.push(name);
                String::new()
            })
        };
        let key_values = Kind::ALL.map(|kind| required(kind.env_name()));
        let discord_client_secret = required("DISCORD_CLIENT_SECRET");
        let discord_client_id = required("DISCORD_CLIENT_ID");
        let discord_guild_id = required("DISCORD_GUILD_ID");
        if !missing.is_empty() {
            return Err(format!(
                "missing environment variables: {}",
                missing.join(", ")
            ));
        }
        let (legacy_secret, legacy_verify_until) = legacy_from_env(&key_values)?;
        let jwt_keys = Keys::new(key_values)?;
        let introspect_secret = optional("INTROSPECT_SECRET");
        if introspect_secret
            .as_ref()
            .is_some_and(|secret| secret.len() < MIN_KEY_BYTES)
        {
            return Err(format!(
                "INTROSPECT_SECRET must be at least {MIN_KEY_BYTES} bytes"
            ));
        }

        let issuer = trimmed("PUBLIC_AUTH_URL", "https://auth.torosaba.net");
        Ok(Self {
            port: or_default("PORT", "8080")
                .parse()
                .map_err(|_| "PORT must be a number".to_string())?,
            internal_port: or_default("INTERNAL_PORT", "8081")
                .parse()
                .map_err(|_| "INTERNAL_PORT must be a number".to_string())?,
            discord_redirect_uri: or_default("DISCORD_REDIRECT_URI", &format!("{issuer}/callback")),
            issuer,
            wiki_url: trimmed("PUBLIC_WIKI_URL", "https://wiki.torosaba.net"),
            cors_origins: or_default("CORS_ORIGINS", "https://wiki.torosaba.net")
                .split(',')
                .map(|origin| origin.trim().to_string())
                .filter(|origin| !origin.is_empty())
                .collect(),
            jwt_keys,
            legacy_secret,
            legacy_verify_until,
            introspect_secret,
            discord_client_id,
            discord_client_secret,
            discord_guild_id,
            discord_required_role_id: optional("DISCORD_REQUIRED_ROLE_ID"),
            discord_bot_token: optional("DISCORD_BOT_TOKEN"),
            discord_api: trimmed("DISCORD_API", "https://discord.com/api/v10"),
            state_dir: or_default("STATE_DIR", "/data"),
            oauth_idle_seconds: or_default("OAUTH_IDLE_DAYS", "30")
                .parse::<i64>()
                .ok()
                .filter(|days| *days > 0)
                .ok_or_else(|| "OAUTH_IDLE_DAYS must be a positive number".to_string())?
                * 86400,
            body_read_timeout_secs: 30,
        })
    }
}
