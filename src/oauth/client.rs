//! 認可を求めてきたクライアントの見分け方
//!
//! `client_id` は誰でも好きに名乗れる (動的登録の内容も保存していない) ので、名前を信じない。
//! ブランド名を見せるのは、戻り先のホストが本物と一致するときだけ。

use url::Url;

use crate::util::is_loopback_host;

const GEMINI: &str = "Google Gemini";
/// Google Account Linking の戻り先。PKCE を省略してよいのは、ここだけ
const GOOGLE_LINKING_HOSTS: [&str; 2] = [
    "oauth-redirect.googleusercontent.com",
    "oauth-redirect-sandbox.googleusercontent.com",
];
/// google.com には他人のコンテンツを置けるホストもあるので、サブドメインをまとめて信じない
const GEMINI_HOSTS: [&str; 2] = ["gemini.google.com", "oauth.google.com"];
/// 画面に出す client_id の長さ
const MAX_SHOWN_CLIENT_ID_CHARS: usize = 64;

/// クライアントへの戻り先として受け付ける URI か。
/// ウェブは https (手元は http も)、デスクトップアプリの独自スキームも通す
pub fn is_valid_redirect_uri(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    // user@host の形は、送り先の見た目をごまかせるだけで、使う理由が無い
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
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
        Ok(url) => match (url.host_str(), url.port()) {
            (Some(host), Some(port)) => format!("{}://{host}:{port}", url.scheme()),
            (Some(host), None) => format!("{}://{host}", url.scheme()),
            (None, _) => format!("{}:", url.scheme()),
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

/// https で、ポートの指定も無い戻り先のホスト
fn plain_https_host(url: &Url) -> Option<&str> {
    if url.scheme() != "https" || url.port().is_some() {
        return None;
    }
    url.host_str()
}

/// 戻り先のホストから分かる、知っているクライアントの名前
fn known_client(redirect_uri: &str) -> Option<&'static str> {
    let url = Url::parse(redirect_uri).ok()?;
    let host = plain_https_host(&url)?;
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
    if GOOGLE_LINKING_HOSTS.contains(&host) || GEMINI_HOSTS.contains(&host) {
        return Some(GEMINI);
    }
    None
}

/// 文字の向きを変える文字や、見えない文字か
fn is_invisible(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

pub fn display_name(client_id: &str, redirect_uri: &str) -> String {
    known_client(redirect_uri).map_or_else(
        || {
            let shown: String = client_id
                .chars()
                .filter(|c| !is_invisible(*c))
                .take(MAX_SHOWN_CLIENT_ID_CHARS)
                .collect();
            format!("未確認: {shown}")
        },
        str::to_string,
    )
}

/// PKCE (S256) を省略してよいか。Google Account Linking だけは使わないので、戻り先が本物のときに限り許す
pub fn may_omit_pkce(redirect_uri: &str) -> bool {
    Url::parse(redirect_uri).is_ok_and(|url| {
        plain_https_host(&url).is_some_and(|host| GOOGLE_LINKING_HOSTS.contains(&host))
    })
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
            "https://claude.ai@evil.example/cb",
            "https://user:pw@a.example/cb",
            "not a url",
        ] {
            assert!(!is_valid_redirect_uri(bad), "{bad}");
        }
    }

    #[test]
    fn the_shown_target_includes_a_port() {
        assert_eq!(
            redirect_target_label("https://a.example/cb"),
            "https://a.example"
        );
        assert_eq!(
            redirect_target_label("https://a.example:443/cb"),
            "https://a.example"
        );
        assert_eq!(
            redirect_target_label("https://a.example:8443/cb"),
            "https://a.example:8443"
        );
        assert_eq!(
            redirect_target_label("http://localhost:6274/cb"),
            "http://localhost:6274"
        );
        assert_eq!(
            redirect_target_label("com.example.app:/oauth2redirect"),
            "com.example.app:"
        );
    }

    #[test]
    fn brand_names_need_the_real_host() {
        assert_eq!(display_name("x", "https://claude.ai/cb"), "Claude");
        assert_eq!(display_name("x", "https://chatgpt.com/cb"), "ChatGPT");
        for gemini in [
            "https://oauth.google.com/cb",
            "https://gemini.google.com/cb",
            "https://oauth-redirect.googleusercontent.com/r/x",
            "https://oauth-redirect-sandbox.googleusercontent.com/r/x",
        ] {
            assert_eq!(display_name("x", gemini), GEMINI, "{gemini}");
        }
        for spoof in [
            "https://evil.example/claude",
            "https://claude.ai.evil.example/cb",
            "https://evilclaude.ai/cb",
            "https://claude.ai@evil.example/cb",
            "https://evil.googleusercontent.com/google",
            "http://claude.ai/cb",
            "https://claude.ai:8443/cb",
            // 他人のコンテンツも置かれるホスト
            "https://sites.google.com/view/x",
            "https://docs.google.com/x",
            "https://script.google.com/x",
            "https://google.com/x",
            "https://oauth.google.com:8443/cb",
        ] {
            assert!(display_name("x", spoof).starts_with("未確認"), "{spoof}");
        }
        assert!(display_name("claude", "https://a.example/").starts_with("未確認"));
    }

    #[test]
    fn the_shown_client_id_is_short_and_printable() {
        assert_eq!(
            display_name("a\u{202E}b\u{200B}c\nd", "https://a.example/"),
            "未確認: abcd"
        );
        let long = "x".repeat(MAX_SHOWN_CLIENT_ID_CHARS + 1);
        assert_eq!(
            display_name(&long, "https://a.example/"),
            format!("未確認: {}", "x".repeat(MAX_SHOWN_CLIENT_ID_CHARS))
        );
    }

    #[test]
    fn only_the_account_linking_hosts_may_omit_pkce() {
        for linking in [
            "https://oauth-redirect.googleusercontent.com/r/x",
            "https://oauth-redirect-sandbox.googleusercontent.com/r/x",
        ] {
            assert!(may_omit_pkce(linking), "{linking}");
        }
        for other in [
            "https://claude.ai/cb",
            "https://evil.example/google",
            "https://gemini.google.com/cb",
            "https://oauth.google.com/cb",
            "https://sites.google.com/view/x",
            "https://google.com/x",
            "https://oauth-redirect.googleusercontent.com.evil.example/r/x",
            "https://evil.googleusercontent.com/r/x",
            "https://oauth-redirect.googleusercontent.com:8443/r/x",
            "http://oauth-redirect.googleusercontent.com/r/x",
            "not a url",
        ] {
            assert!(!may_omit_pkce(other), "{other}");
        }
    }
}
