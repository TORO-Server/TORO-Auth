//! 環境変数からの設定。秘密でない値の既定は、本番の値にしてある (秘密だけを env ファイルに書けばよい)

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    /// 認可サーバーの公開 URL (末尾の / なし)
    pub issuer: String,
    /// REST API の公開 URL (末尾の / なし)
    pub api_url: String,
    /// MCP サーバーの公開 URL (末尾の / なし)
    pub mcp_url: String,
    /// Wiki の公開 URL (末尾の / なし)
    pub wiki_url: String,
    /// Cookie 付きで API を呼べる Origin (他のサブドメインは信じない)
    pub cors_origins: Vec<String>,

    pub jwt_secret: String,

    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub discord_redirect_uri: String,
    pub discord_guild_id: String,
    pub discord_required_role_id: Option<String>,
    pub discord_bot_token: Option<String>,
    pub discord_api: String,

    pub github_token: String,
    pub github_owner: String,
    pub github_repo: String,
    pub github_branch: String,
    pub github_api: String,
    /// Wiki の検索が、原稿の変更を見に行く間隔
    pub wiki_index_ttl_secs: u64,

    /// 稼働状態を尋ねる先 (host:port)
    pub mc_status_addr: String,
    /// 尋ねるときに名乗るホスト名 (Velocity の forced-hosts 用)
    pub mc_status_host: String,

    /// 再起動しても残す記録の置き場所 (90 日トークンの世代)
    pub state_dir: String,
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

impl Config {
    /// Cookie 付きのリクエストを受けてよい送り元か (自分自身と、指定の Origin)
    pub fn is_trusted_origin(&self, origin: &str) -> bool {
        origin == self.issuer || self.cors_origins.iter().any(|o| o == origin)
    }

    pub fn from_env() -> Result<Self, String> {
        let mut missing = Vec::new();
        let mut required = |name: &'static str| {
            optional(name).unwrap_or_else(|| {
                missing.push(name);
                String::new()
            })
        };
        let jwt_secret = required("JWT_SECRET");
        let discord_client_secret = required("DISCORD_CLIENT_SECRET");
        let github_token = required("GITHUB_TOKEN");
        if !missing.is_empty() {
            return Err(format!(
                "missing environment variables: {}",
                missing.join(", ")
            ));
        }
        if jwt_secret.len() < 32 {
            return Err("JWT_SECRET must be at least 32 bytes".into());
        }

        let issuer = trimmed("PUBLIC_AUTH_URL", "https://auth.torosaba.net");
        Ok(Self {
            port: or_default("PORT", "8080")
                .parse()
                .map_err(|_| "PORT must be a number".to_string())?,
            discord_redirect_uri: or_default(
                "DISCORD_REDIRECT_URI",
                &format!("{issuer}/api/auth/callback"),
            ),
            issuer,
            api_url: trimmed("PUBLIC_API_URL", "https://api.torosaba.net"),
            mcp_url: trimmed("PUBLIC_MCP_URL", "https://mcp.torosaba.net"),
            wiki_url: trimmed("PUBLIC_WIKI_URL", "https://wiki.torosaba.net"),
            cors_origins: or_default("CORS_ORIGINS", "https://wiki.torosaba.net")
                .split(',')
                .map(|origin| origin.trim().to_string())
                .filter(|origin| !origin.is_empty())
                .collect(),
            jwt_secret,
            discord_client_id: or_default("DISCORD_CLIENT_ID", "0000000000000000000"),
            discord_client_secret,
            discord_guild_id: or_default("DISCORD_GUILD_ID", "000000000000000000"),
            discord_required_role_id: optional("DISCORD_REQUIRED_ROLE_ID"),
            discord_bot_token: optional("DISCORD_BOT_TOKEN"),
            discord_api: trimmed("DISCORD_API", "https://discord.com/api/v10"),
            github_token,
            github_owner: or_default("GITHUB_OWNER", "TORO-Server"),
            github_repo: or_default("GITHUB_REPO", "TORO-Wiki"),
            github_branch: or_default("GITHUB_BRANCH", "main"),
            github_api: trimmed("GITHUB_API", "https://api.github.com"),
            wiki_index_ttl_secs: 300,
            mc_status_addr: or_default("MC_STATUS_ADDR", "toro-velocity:25565"),
            mc_status_host: or_default("MC_STATUS_HOST", "torosaba.net"),
            state_dir: or_default("STATE_DIR", "/data"),
        })
    }
}
