//! 90 日トークンの世代の記録
//!
//! 利用者ごとに、いま有効なトークンの世代を 1 つだけ覚える。再作成で世代を換えると、前のトークンは通らなくなる。
//! トークンそのものは覚えない (あとから見せることはできないし、記録が漏れても署名は作れない)。
//! 世代は乱数なので、記録を失っても昔のトークンが生き返ることはない。

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use crate::jwt;
use crate::util::random_hex;

const FILE_NAME: &str = "connector-tokens.json";

/// 利用者の ID → (世代, 期限)
type Records = HashMap<String, (String, i64)>;

pub struct TokenStore {
    path: PathBuf,
    records: Mutex<Records>,
}

impl TokenStore {
    /// 読めない記録は無いものとして始める。すべての 90 日トークンが無効になるだけで、安全な側に倒れる
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

    /// 世代を新しくして返す。保存できなければ何も変えない (前のトークンを無効にしたと偽らない)
    pub fn rotate(&self, user_id: &str, exp: i64) -> std::io::Result<String> {
        let mut records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let generation = random_hex(16);
        let now = jwt::now();
        let mut next = records.clone();
        next.retain(|_, (_, record_exp)| *record_exp > now);
        next.insert(user_id.to_string(), (generation.clone(), exp));
        self.save(&next)?;
        *records = next;
        Ok(generation)
    }

    pub fn is_current(&self, user_id: &str, generation: &str) -> bool {
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(user_id)
            .is_some_and(|(current, _)| current == generation)
    }

    /// いま有効なトークンの期限
    pub fn expires_at(&self, user_id: &str) -> Option<i64> {
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(user_id)
            .map(|(_, exp)| *exp)
            .filter(|exp| *exp > jwt::now())
    }

    /// 書きかけのファイルを読まないよう、別名で書いてから置き換える
    fn save(&self, records: &Records) -> std::io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&serde_json::to_vec(records)?)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("toro-auth-{name}-{}", random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rotation_replaces_the_generation_and_survives_a_restart() {
        let dir = temp_dir("tokens");
        let store = TokenStore::load(dir.to_str().unwrap());
        let exp = jwt::now() + 100;
        let first = store.rotate("1", exp).unwrap();
        assert!(store.is_current("1", &first));

        let second = store.rotate("1", exp).unwrap();
        assert!(!store.is_current("1", &first));
        assert!(store.is_current("1", &second));
        assert!(!store.is_current("2", &second));

        let reloaded = TokenStore::load(dir.to_str().unwrap());
        assert!(reloaded.is_current("1", &second));
        assert_eq!(reloaded.expires_at("1"), Some(exp));
        assert_eq!(reloaded.expires_at("2"), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn expired_records_are_dropped_when_saving() {
        let dir = temp_dir("expiry");
        let store = TokenStore::load(dir.to_str().unwrap());
        store.rotate("old", jwt::now() - 1).unwrap();
        assert_eq!(store.expires_at("old"), None);
        store.rotate("new", jwt::now() + 100).unwrap();
        let saved = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        assert!(!saved.contains("\"old\""));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_save_changes_nothing() {
        let dir = temp_dir("failure");
        let store = TokenStore::load(dir.to_str().unwrap());
        let current = store.rotate("1", jwt::now() + 100).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(store.rotate("1", jwt::now() + 100).is_err());
        assert!(store.is_current("1", &current));
    }

    #[test]
    fn a_broken_file_means_no_valid_tokens() {
        let dir = temp_dir("broken");
        std::fs::write(dir.join(FILE_NAME), "{not json").unwrap();
        let store = TokenStore::load(dir.to_str().unwrap());
        assert!(!store.is_current("1", "anything"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
