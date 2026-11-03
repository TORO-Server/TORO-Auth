//! Discord API

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::App;

const ROLE_NAMES_TTL: Duration = Duration::from_secs(300);
/// 名前が取れなくても ID は出せるので、画面を長く待たせない
const ROLE_NAMES_TIMEOUT: Duration = Duration::from_secs(3);

fn text(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_string)
}

/// 認可コードをアクセストークンに換える。失敗は Discord の説明をそのまま返す
pub async fn exchange_code(app: &App, code: &str) -> Result<Result<String, String>, String> {
    let cfg = &app.cfg;
    let res = app
        .http
        .post(format!("{}/oauth2/token", cfg.discord_api))
        .form(&[
            ("client_id", cfg.discord_client_id.as_str()),
            ("client_secret", cfg.discord_client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", cfg.discord_redirect_uri.as_str()),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Ok(Err(res.text().await.unwrap_or_default()));
    }
    let data: Value = res.json().await.map_err(|e| e.to_string())?;
    Ok(text(&data, "access_token").ok_or_else(|| "no access_token in response".to_string()))
}

pub struct DiscordUser {
    pub id: String,
    pub username: String,
    pub global_name: Option<String>,
    pub avatar: Option<String>,
    pub discriminator: String,
}

impl DiscordUser {
    pub fn avatar_url(&self) -> String {
        match &self.avatar {
            Some(avatar) => format!(
                "https://cdn.discordapp.com/avatars/{}/{avatar}.png",
                self.id
            ),
            None => {
                let index = self.discriminator.parse::<u32>().unwrap_or(0) % 5;
                format!("https://cdn.discordapp.com/embed/avatars/{index}.png")
            }
        }
    }
}

pub async fn fetch_user(app: &App, access_token: &str) -> Option<DiscordUser> {
    let res = app
        .http
        .get(format!("{}/users/@me", app.cfg.discord_api))
        .bearer_auth(access_token)
        .send()
        .await
        .ok()?;
    if !res.status().is_success() {
        return None;
    }
    let data: Value = res.json().await.ok()?;
    Some(DiscordUser {
        id: text(&data, "id")?,
        username: text(&data, "username")?,
        global_name: text(&data, "global_name"),
        avatar: text(&data, "avatar"),
        discriminator: text(&data, "discriminator").unwrap_or_else(|| "0".into()),
    })
}

pub struct Membership {
    pub is_member: bool,
    pub roles: Vec<String>,
}

fn roles_of(member: &Value) -> Vec<String> {
    member
        .get("roles")
        .and_then(Value::as_array)
        .map(|roles| {
            roles
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// ギルドの所属とロールを調べる。
/// Bot トークン → 利用者のトークン (guilds.members.read) → 所属ギルドの一覧、の順に試す
pub async fn membership(app: &App, user_id: &str, access_token: &str) -> Membership {
    let cfg = &app.cfg;
    let guild = &cfg.discord_guild_id;

    if let Some(bot_token) = &cfg.discord_bot_token {
        let res = app
            .http
            .get(format!(
                "{}/guilds/{guild}/members/{user_id}",
                cfg.discord_api
            ))
            .header("Authorization", format!("Bot {bot_token}"))
            .send()
            .await;
        if let Some(member) = member_json(res).await {
            return Membership {
                is_member: true,
                roles: roles_of(&member),
            };
        }
    }

    let res = app
        .http
        .get(format!(
            "{}/users/@me/guilds/{guild}/member",
            cfg.discord_api
        ))
        .bearer_auth(access_token)
        .send()
        .await;
    if let Some(member) = member_json(res).await {
        return Membership {
            is_member: true,
            roles: roles_of(&member),
        };
    }

    let res = app
        .http
        .get(format!("{}/users/@me/guilds", cfg.discord_api))
        .bearer_auth(access_token)
        .send()
        .await;
    let is_member = member_json(res)
        .await
        .and_then(|guilds| {
            guilds
                .as_array()
                .map(|list| list.iter().any(|g| g["id"] == guild.as_str()))
        })
        .unwrap_or(false);
    Membership {
        is_member,
        roles: Vec::new(),
    }
}

/// ギルドのロールの名前を、少しの間覚えておく
#[derive(Default)]
pub struct RoleNames {
    cached: Mutex<Option<(Instant, HashMap<String, String>)>>,
}

impl RoleNames {
    fn fresh(&self) -> Option<HashMap<String, String>> {
        let cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        cached
            .as_ref()
            .filter(|(fetched_at, _)| fetched_at.elapsed() < ROLE_NAMES_TTL)
            .map(|(_, names)| names.clone())
    }

    fn store(&self, names: HashMap<String, String>) {
        *self.cached.lock().unwrap_or_else(PoisonError::into_inner) = Some((Instant::now(), names));
    }
}

/// ロール ID → 名前。名前は Bot トークンでしか読めないので、無ければ空のまま返す
pub async fn role_names(app: &App) -> HashMap<String, String> {
    let Some(bot_token) = &app.cfg.discord_bot_token else {
        return HashMap::new();
    };
    if let Some(names) = app.role_names.fresh() {
        return names;
    }
    let res = app
        .http
        .get(format!(
            "{}/guilds/{}/roles",
            app.cfg.discord_api, app.cfg.discord_guild_id
        ))
        .header("Authorization", format!("Bot {bot_token}"))
        .timeout(ROLE_NAMES_TIMEOUT)
        .send()
        .await;
    let Some(roles) = member_json(res).await else {
        return HashMap::new();
    };
    let names: HashMap<String, String> = roles
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|role| Some((text(role, "id")?, text(role, "name")?)))
        .collect();
    app.role_names.store(names.clone());
    names
}

async fn member_json(res: reqwest::Result<reqwest::Response>) -> Option<Value> {
    let res = res.ok()?;
    if !res.status().is_success() {
        return None;
    }
    res.json().await.ok()
}
