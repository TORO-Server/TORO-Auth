//! Wiki の全文検索。原稿をメモリに持って、自分で探す
//!
//! GitHub のコード検索は TORO-Wiki を索引していない (常に 0 件を返す) ので使わない。
//! 取り直すのは変わった原稿だけ。ツリーを見に行くのも一定時間に 1 回なので、
//! 検索が何度来ても GitHub の利用枠をほとんど使わない。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures_util::{StreamExt, stream};
use tokio::sync::Mutex;

use super::github;
use crate::App;

/// 原稿を同時に取りに行く数
const FETCH_CONCURRENCY: usize = 8;
/// パスに語が含まれるときの重み (本文の出現回数より優先する)
const PATH_MATCH_WEIGHT: usize = 1000;

struct Doc {
    sha: String,
    lowercase_text: String,
}

#[derive(Default)]
struct State {
    checked_at: Option<Instant>,
    /// docs/ を除いたパス → 原稿
    docs: HashMap<String, Doc>,
}

pub struct Index {
    ttl: Duration,
    state: Mutex<State>,
}

impl Index {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            state: Mutex::new(State::default()),
        }
    }

    /// 語をすべて含む原稿のパスを、よく一致する順に返す。一度も原稿を読めていないなら None
    pub async fn search(&self, app: &App, query: &str) -> Option<Vec<String>> {
        let mut state = self.state.lock().await;
        refresh(&mut state, self.ttl, app).await;
        if state.docs.is_empty() {
            return None;
        }

        let lowercase_query = query.to_lowercase();
        let terms: Vec<&str> = lowercase_query.split_whitespace().collect();
        if terms.is_empty() {
            return Some(Vec::new());
        }
        let mut hits: Vec<(usize, &String)> = state
            .docs
            .iter()
            .filter_map(|(path, doc)| score(path, &doc.lowercase_text, &terms).map(|s| (s, path)))
            .collect();
        hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
        Some(hits.into_iter().map(|(_, path)| path.clone()).collect())
    }
}

/// すべての語を含むときだけ点数を返す
fn score(path: &str, lowercase_text: &str, terms: &[&str]) -> Option<usize> {
    let lowercase_path = path.to_lowercase();
    let mut total = 0;
    for term in terms {
        let in_path = lowercase_path.matches(term).count();
        let in_text = lowercase_text.matches(term).count();
        if in_path + in_text == 0 {
            return None;
        }
        total += in_path * PATH_MATCH_WEIGHT + in_text;
    }
    Some(total)
}

async fn refresh(state: &mut State, ttl: Duration, app: &App) {
    if state.checked_at.is_some_and(|at| at.elapsed() < ttl) {
        return;
    }
    // 失敗しても一定時間は聞き直さない (GitHub の障害中に検索が来るたびに叩かない)
    state.checked_at = Some(Instant::now());

    let Some(blobs) = github::doc_blobs(app).await else {
        eprintln!("wiki search: could not read the document tree");
        return;
    };

    let current: Vec<(String, String)> = blobs
        .into_iter()
        .filter_map(|blob| {
            let path = blob.path.strip_prefix("docs/")?.to_string();
            Some((path, blob.sha))
        })
        .collect();
    state
        .docs
        .retain(|path, _| current.iter().any(|(p, _)| p == path));

    let changed: Vec<(String, String)> = current
        .into_iter()
        .filter(|(path, sha)| state.docs.get(path).is_none_or(|doc| doc.sha != *sha))
        .collect();
    let fetched: Vec<_> = stream::iter(changed)
        .map(|(path, sha)| async move {
            let text = github::blob_text(app, &sha).await;
            (path, sha, text)
        })
        .buffer_unordered(FETCH_CONCURRENCY)
        .collect()
        .await;

    for (path, sha, text) in fetched {
        match text {
            Some(text) => {
                let lowercase_text = text.to_lowercase();
                state.docs.insert(
                    path,
                    Doc {
                        sha,
                        lowercase_text,
                    },
                );
            }
            // 古い内容を残し、次の更新でまた取りに行く
            None => eprintln!("wiki search: could not read {path}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::score;

    #[test]
    fn all_terms_must_match_and_paths_rank_higher() {
        let in_text = score("guide.md", "traincarts を使う", &["traincarts"]).unwrap();
        let in_path = score("traincarts.md", "説明", &["traincarts"]).unwrap();
        assert!(in_path > in_text);
        assert_eq!(score("a.md", "traincarts", &["traincarts", "無い語"]), None);
        assert!(score("a.md", "電車 と 駅", &["電車", "駅"]).is_some());
    }
}
