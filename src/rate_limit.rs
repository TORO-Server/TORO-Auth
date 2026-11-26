//! auth のレート制限。Cloudflare の ruleset `auth_rate_limit` (F-05 c1) の同等措置。
//!
//! 2026-11-27 03:00 JST の DNS 切替で torosaba.net が Cloudflare Tunnel を離れ、
//! 直接経路となったため、Cloudflare 側の規則は適用されなくなった。その代替として、
//! 対象の 3 経路への要求をこのサービス内で数える。
//!
//! 規則: クライアント IP ごとに直近 10 秒で 20 件まで。21 件目で 10 秒間の遮断に入る。
//! 遮断中の要求は数えない。遮断が明けたら計数は空の状態から始まる。
//!
//! クライアント IP は toro-edge が設定する `X-Toro-Client-Ip` から読む。Caddy が
//! 客の書いた値を除去し、`Cf-Connecting-Ip` へ接続元の IP を入れるため、この値は
//! 信頼できる。ヘッダーが無い場合（直接のコンソール経路）は 1 つの共有キーで数える。
//! Cloudflare の規則も直接の迂回路には適用されなかったため、この扱いは整合する。
//!
//! 制限超過への応答は 429 Too Many Requests と `Retry-After: 10` である。
//! 2026-11-20 の実測では Cloudflare の block も 21 件目から 429 を返し、
//! 10 秒後に復帰したため、応答は同一である。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

/// 制限の対象経路。Cloudflare の規則と同一。
pub const LIMITED_PATHS: [&str; 3] = ["/login", "/oauth/register", "/oauth/token"];
/// 計数する時間幅（秒）。
pub const WINDOW_SECS: u64 = 10;
/// 1 つの時間幅あたりに許す要求数。
pub const MAX_REQUESTS: usize = 20;
/// 制限超過後に遮断する時間（秒）。
pub const BLOCK_SECS: u64 = 10;
/// `Retry-After` ヘッダーの値。`BLOCK_SECS` と同一。
pub const RETRY_AFTER: &str = "10";

/// toro-edge が設定するクライアント IP のヘッダー。
const CLIENT_IP_HEADER: &str = "x-toro-client-ip";

/// 制限の対象経路かどうか。
pub fn is_limited_path(path: &str) -> bool {
    LIMITED_PATHS.contains(&path)
}

/// 要求元の識別子。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClientKey {
    /// ヘッダーから読んだクライアント IP。
    Ip(IpAddr),
    /// ヘッダーが無い直接接続。すべて 1 つの共有キーで数える。
    Direct,
}

/// 要求ヘッダーから要求元の識別子を読み取る。
pub fn client_key(headers: &HeaderMap) -> ClientKey {
    let Some(value) = headers.get(CLIENT_IP_HEADER) else {
        return ClientKey::Direct;
    };
    let Ok(text) = value.to_str() else {
        return ClientKey::Direct;
    };
    // 複数値の場合は先頭だけを見る。
    let first = text.split(',').next().unwrap_or("").trim();
    match first.parse::<IpAddr>() {
        Ok(ip) => ClientKey::Ip(ip),
        Err(_) => ClientKey::Direct,
    }
}

#[derive(Debug, Default)]
struct Entry {
    /// 直近の要求時刻。古いものから順に入る。
    hits: VecDeque<Instant>,
    /// 遮断中の場合は遮断の終了時刻。
    blocked_until: Option<Instant>,
}

#[derive(Debug, Default)]
struct State {
    entries: HashMap<ClientKey, Entry>,
}

/// auth のレート制限。1 プロセス内で共有する。
#[derive(Debug, Default)]
pub struct AuthRateLimit {
    state: Mutex<State>,
}

impl AuthRateLimit {
    pub fn new() -> Self {
        Self::default()
    }

    /// 要求を許す場合は true。制限超過の場合は false。
    pub fn allow(&self, key: &ClientKey) -> bool {
        self.allow_at(key, Instant::now())
    }

    fn allow_at(&self, key: &ClientKey, now: Instant) -> bool {
        let mut state = self.state.lock().expect("rate limit lock");
        let window = Duration::from_secs(WINDOW_SECS);
        // 活動の無い項目を捨てて地図の肥大を防ぐ。
        state.entries.retain(|_, entry| {
            entry.blocked_until.is_some_and(|until| until > now)
                || entry
                    .hits
                    .back()
                    .is_some_and(|last| now.saturating_duration_since(*last) < window)
        });
        let entry = state.entries.entry(key.clone()).or_default();
        if let Some(until) = entry.blocked_until {
            if now < until {
                return false;
            }
            entry.blocked_until = None;
        }
        while entry
            .hits
            .front()
            .is_some_and(|first| now.saturating_duration_since(*first) >= window)
        {
            entry.hits.pop_front();
        }
        if entry.hits.len() >= MAX_REQUESTS {
            entry.blocked_until = Some(now + Duration::from_secs(BLOCK_SECS));
            return false;
        }
        entry.hits.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> AuthRateLimit {
        AuthRateLimit::new()
    }

    fn key(ip: &str) -> ClientKey {
        ClientKey::Ip(ip.parse().unwrap())
    }

    #[test]
    fn allows_twenty_then_blocks() {
        let limit = limiter();
        let key = key("203.0.113.7");
        let now = Instant::now();
        for _ in 0..MAX_REQUESTS {
            assert!(limit.allow_at(&key, now));
        }
        assert!(!limit.allow_at(&key, now));
    }

    #[test]
    fn block_lasts_ten_seconds_then_allows() {
        let limit = limiter();
        let key = key("203.0.113.7");
        let now = Instant::now();
        for _ in 0..MAX_REQUESTS {
            assert!(limit.allow_at(&key, now));
        }
        assert!(!limit.allow_at(&key, now));
        // 遮断中は 9 秒後でも通らない。
        assert!(!limit.allow_at(&key, now + Duration::from_secs(9)));
        // 10 秒後に遮断が明け、計数は空から始まる。
        assert!(limit.allow_at(&key, now + Duration::from_secs(10)));
    }

    #[test]
    fn window_slides() {
        let limit = limiter();
        let key = key("203.0.113.7");
        let now = Instant::now();
        for _ in 0..MAX_REQUESTS {
            assert!(limit.allow_at(&key, now));
        }
        // 10 秒後には最初の 20 件が時間幅の外へ出るため通る。
        assert!(limit.allow_at(&key, now + Duration::from_secs(10)));
    }

    #[test]
    fn keys_are_independent() {
        let limit = limiter();
        let first = key("203.0.113.7");
        let second = key("198.51.100.1");
        let now = Instant::now();
        for _ in 0..MAX_REQUESTS {
            assert!(limit.allow_at(&first, now));
        }
        assert!(!limit.allow_at(&first, now));
        assert!(limit.allow_at(&second, now));
    }

    #[test]
    fn client_key_reads_the_edge_header() {
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_IP_HEADER, "203.0.113.7".parse().unwrap());
        assert_eq!(client_key(&headers), key("203.0.113.7"));

        headers.insert(CLIENT_IP_HEADER, "2001:db8::1".parse().unwrap());
        assert_eq!(client_key(&headers), key("2001:db8::1"));

        // 複数値の場合は先頭だけを見る。
        headers.insert(
            CLIENT_IP_HEADER,
            "203.0.113.7, 198.51.100.1".parse().unwrap(),
        );
        assert_eq!(client_key(&headers), key("203.0.113.7"));

        // 値が IP ではない場合は直接接続として扱う。
        headers.insert(CLIENT_IP_HEADER, "not-an-ip".parse().unwrap());
        assert_eq!(client_key(&headers), ClientKey::Direct);

        // ヘッダーが無い場合も直接接続として扱う。
        let empty = HeaderMap::new();
        assert_eq!(client_key(&empty), ClientKey::Direct);
    }

    #[test]
    fn limited_paths_match_the_cloudflare_rule() {
        assert!(is_limited_path("/login"));
        assert!(is_limited_path("/oauth/register"));
        assert!(is_limited_path("/oauth/token"));
        assert!(!is_limited_path("/"));
        assert!(!is_limited_path("/oauth/authorize"));
        assert!(!is_limited_path("/oauth/userinfo"));
        assert!(!is_limited_path("/healthz"));
    }
}
