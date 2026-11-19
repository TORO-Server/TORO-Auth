//! ブラウザのセッションの世代の記録
//!
//! 利用者ごとに世代の番号を 1 つ覚える。セッションのトークンには、発行したときの番号 (`sgen`) を入れる。
//! `/logout` で番号を進めると、前の番号のセッションは (Cookie を残していても、盗まれていても) 通らなくなる。
//! 番号の記録が無い利用者は 0。記録を失うと、進めた番号が 0 に戻り、ログアウト済みのセッションが生き返りうるので、
//! 記録は /data に永続させる。読めないときは起動を止めず、番号の無い状態 (0) として始める
//! (鍵を分けた時点で、その前のトークンは通らない)。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use crate::util::write_private_atomic;

const FILE_NAME: &str = "session-generations.json";

type Records = HashMap<String, u64>;

pub struct SessionGenerations {
    path: PathBuf,
    records: Mutex<Records>,
}

impl SessionGenerations {
    pub fn load(state_dir: &str) -> Self {
        let path = Path::new(state_dir).join(FILE_NAME);
        let records = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                eprintln!("{}: {e}", path.display());
                Records::new()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Records::new(),
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                Records::new()
            }
        };
        Self {
            path,
            records: Mutex::new(records),
        }
    }

    /// いまの世代。記録が無ければ 0
    pub fn current(&self, user_id: &str) -> u64 {
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(user_id)
            .copied()
            .unwrap_or(0)
    }

    /// 世代を 1 つ進めて返す。保存できなければ何も変えない (失効させたと偽らない)
    pub fn advance(&self, user_id: &str) -> std::io::Result<u64> {
        let mut records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let next_value = records.get(user_id).copied().unwrap_or(0) + 1;
        let mut next = records.clone();
        next.insert(user_id.to_string(), next_value);
        write_private_atomic(&self.path, &serde_json::to_vec(&next)?)?;
        *records = next;
        Ok(next_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::random_hex;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("toro-auth-gen-{name}-{}", random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn advancing_changes_only_that_account_and_survives_a_restart() {
        let dir = temp_dir("advance");
        let store = SessionGenerations::load(dir.to_str().unwrap());
        assert_eq!(store.current("1"), 0);
        assert_eq!(store.advance("1").unwrap(), 1);
        assert_eq!(store.advance("1").unwrap(), 2);
        assert_eq!(store.current("1"), 2);
        assert_eq!(store.current("2"), 0);

        let reloaded = SessionGenerations::load(dir.to_str().unwrap());
        assert_eq!(reloaded.current("1"), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let store = SessionGenerations::load(dir.to_str().unwrap());
        store.advance("1").unwrap();
        let mode = std::fs::metadata(dir.join(FILE_NAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_save_changes_nothing() {
        let dir = temp_dir("failure");
        let store = SessionGenerations::load(dir.to_str().unwrap());
        store.advance("1").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(store.advance("1").is_err());
        assert_eq!(store.current("1"), 1);
    }

    #[test]
    fn a_broken_file_starts_from_zero() {
        let dir = temp_dir("broken");
        std::fs::write(dir.join(FILE_NAME), "{not json").unwrap();
        let store = SessionGenerations::load(dir.to_str().unwrap());
        assert_eq!(store.current("1"), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
