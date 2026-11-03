//! 認可を求めてきたクライアントの見分け方
//!
//! `client_id` は誰でも好きに名乗れる (動的登録の内容も保存していない) ので、名前を信じない。
//! ブランド名を見せるのは、戻り先のホストが本物と一致するときだけ。

use url::Url;

use crate::util::is_loopback_host;

const GEMINI: &str = "Google Gemini";

/// クライアントへの戻り先として受け付ける URI か。
/// ウェブは https (手元は http も)、デスクトップアプリの独自スキームも通す
pub fn is_valid_redirect_uri(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if url.fragment().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => url.host_str().is_some_and(is_loopback_host),
        "javascript" | "data" | "vbscript" | "file" | "about" | "blob" | "filesystem"
        | "view-source" | "jar" | "ftp" | "ws" | "wss" | "mailto" | "tel" | "sms" | "intent"
        | "chrome" | "resource" => false,
        _ => true,
    }
}

/// 利用者に見せる戻り先
pub fn redirect_target_label(uri: &str) -> String {
    match Url::parse(uri) {
        Ok(url) => match url.host_str() {
            Some(host) => format!("{}://{host}", url.scheme()),
            None => format!("{}:", url.scheme()),
        },
        Err(_) => uri.to_string(),
    }
}

fn is_host_or_subdomain(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// 戻り先のホストから分かる、知っているクライアントの名前
fn known_client(redirect_uri: &str) -> Option<&'static str> {
    let url = Url::parse(redirect_uri).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?;
    if ["claude.ai", "claude.com", "anthropic.com"]
        .iter()
        .any(|d| is_host_or_subdomain(host, d))
    {
        return Some("Claude");
    }
    if ["chatgpt.com", "openai.com"]
        .iter()
        .any(|d| is_host_or_subdomain(host, d))
    {
        return Some("ChatGPT");
    }
    // googleusercontent.com は他人のコンテンツも置かれるので、Account Linking の戻り先だけ
    if is_host_or_subdomain(host, "google.com")
        || host == "oauth-redirect.googleusercontent.com"
        || host == "oauth-redirect-sandbox.googleusercontent.com"
    {
        return Some(GEMINI);
    }
    None
}

pub fn display_name(client_id: &str, redirect_uri: &str) -> String {
    known_client(redirect_uri).map_or_else(|| format!("UNVERIFIED: {client_id}"), str::to_string)
}

/// PKCE (S256) を省略してよいか。Google Account Linking だけは使わないので、戻り先が本物のときに限り許す
pub fn may_omit_pkce(redirect_uri: &str) -> bool {
    known_client(redirect_uri) == Some(GEMINI)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_rules() {
        for good in [
            "https://claude.ai/api/mcp/auth_callback",
            "http://localhost:6274/callback",
            "http://127.0.0.1:33418/",
            "cursor://anysphere.cursor-retrieval/oauth/callback",
            "com.example.app:/oauth2redirect",
        ] {
            assert!(is_valid_redirect_uri(good), "{good}");
        }
        for bad in [
            "http://evil.example/cb",
            "javascript:alert(1)",
            " JavaScript:alert(1)",
            "data:text/html,x",
            "mailto:a@example.com",
            "view-source:https://a.example/",
            "https://a.example/cb#frag",
            "not a url",
        ] {
            assert!(!is_valid_redirect_uri(bad), "{bad}");
        }
    }

    #[test]
    fn brand_names_need_the_real_host() {
        assert_eq!(display_name("x", "https://claude.ai/cb"), "Claude");
        assert_eq!(display_name("x", "https://chatgpt.com/cb"), "ChatGPT");
        assert_eq!(display_name("x", "https://oauth.google.com/cb"), GEMINI);
        for spoof in [
            "https://evil.example/claude",
            "https://claude.ai.evil.example/cb",
            "https://evilclaude.ai/cb",
            "https://claude.ai@evil.example/cb",
            "https://evil.googleusercontent.com/google",
            "http://claude.ai/cb",
        ] {
            assert!(
                display_name("x", spoof).starts_with("UNVERIFIED"),
                "{spoof}"
            );
        }
        assert!(display_name("claude", "https://a.example/").starts_with("UNVERIFIED"));
    }

    #[test]
    fn only_google_may_omit_pkce() {
        assert!(may_omit_pkce(
            "https://oauth-redirect.googleusercontent.com/r/x"
        ));
        assert!(!may_omit_pkce("https://claude.ai/cb"));
        assert!(!may_omit_pkce("https://evil.example/google"));
    }
}
