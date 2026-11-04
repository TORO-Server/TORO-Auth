//! OAuth の連携 (グラント) の、最後に使った時刻の記録
//!
//! 連携 1 つにつき 1 件。認可コードをトークンに換えたときに作り、アクセストークンとリフレッシュトークンに
//! `gid` として入れる。**使っている間はログインが続き、一定期間 (`OAUTH_IDLE_DAYS`、既定 30 日) 使わないと無効になる**:
//! - トークンが確認されるたびに (api / mcp / toro-guard の確認の窓口、userinfo も) 最後に使った時刻を更新する
//! - 最後に使ってから期間を過ぎた連携は、アクセストークンもリフレッシュトークンも通らない (再ログインが要る)
//! - リフレッシュのたびに、新しいリフレッシュトークンを返す (トークンの署名の期限も、使っている間は延びる)
//!
//! トークンそのものは覚えない。記録を失った連携は無効になる (安全な側。クライアントは、もう一度連携する)。
//! 最後に使った時刻の保存は、書き込みを減らすため `SAVE_EVERY` ごとにまとめる (落ちたときに失うのは、その分の「使った」だけ)。

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use crate::util::random_hex;

const FILE_NAME: &str = "oauth-grants.json";
/// 最後に使った時刻を、ファイルに書き出す間隔 (秒)
const SAVE_EVERY: i64 = 300;
/// 1 人が持てる連携の数。超えたら、いちばん長く使っていないものから消す (記録の大きさに上限を設ける)
const MAX_GRANTS_PER_USER: usize = 32;

/// 連携の ID → (利用者の ID, 作った時刻, 最後に使った時刻)
type Grants = HashMap<String, (String, i64, i64)>;

struct Inner {
    grants: Grants,
    last_saved: i64,
}

pub struct GrantStore {
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl GrantStore {
    /// 読めない記録は無いものとして始める。すべての連携が無効になるだけで、安全な側に倒れる
    pub fn load(state_dir: &str) -> Self {
        let path = Path::new(state_dir).join(FILE_NAME);
        let grants = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                eprintln!("{}: {e}", path.display());
                HashMap::new()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                eprintln!("{}: {e}", path.display());
                HashMap::new()
            }
        };
        Self {
            path,
            inner: Mutex::new(Inner {
                grants,
                last_saved: 0,
            }),
        }
    }

    /// 新しい連携を作って、その ID を返す。保存できなければ何も作らない
    pub fn create(&self, user_id: &str, idle: i64, now: i64) -> std::io::Result<String> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = inner.grants.clone();
        next.retain(|_, (_, _, last_used)| now - *last_used <= idle);
        drop_oldest_of_user(&mut next, user_id);
        let gid = random_hex(16);
        next.insert(gid.clone(), (user_id.to_string(), now, now));
        self.save(&next)?;
        inner.grants = next;
        inner.last_saved = now;
        Ok(gid)
    }

    /// 連携が有効なら、最後に使った時刻を `now` にして true。
    /// 無い (作った覚えが無い・失った) か、最後に使ってから `idle` 秒を過ぎていたら false (過ぎたものは消す)
    pub fn touch(&self, gid: &str, user_id: &str, idle: i64, now: i64) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((owner, _, last_used)) = inner.grants.get_mut(gid) else {
            return false;
        };
        if owner != user_id {
            return false;
        }
        if now - *last_used > idle {
            inner.grants.remove(gid);
            return false;
        }
        *last_used = (*last_used).max(now);
        if now - inner.last_saved >= SAVE_EVERY {
            inner
                .grants
                .retain(|_, (_, _, last_used)| now - *last_used <= idle);
            match self.save(&inner.grants) {
                Ok(()) => inner.last_saved = now,
                Err(e) => eprintln!("{}: {e}", self.path.display()),
            }
        }
        true
    }

    /// 書きかけのファイルを読まないよう、別名で書いてから置き換える
    fn save(&self, grants: &Grants) -> std::io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&serde_json::to_vec(grants)?)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &self.path)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().grants.len()
    }
}

/// 新しい連携を 1 つ足せるように、その人の古い連携を消す
fn drop_oldest_of_user(grants: &mut Grants, user_id: &str) {
    let mut own: Vec<(String, i64)> = grants
        .iter()
        .filter(|(_, (owner, _, _))| owner == user_id)
        .map(|(gid, (_, _, last_used))| (gid.clone(), *last_used))
        .collect();
    if own.len() < MAX_GRANTS_PER_USER {
        return;
    }
    own.sort_by_key(|(_, last_used)| *last_used);
    for (gid, _) in &own[..=own.len() - MAX_GRANTS_PER_USER] {
        grants.remove(gid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: i64 = 1000;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("toro-auth-{name}-{}", random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn using_a_grant_keeps_it_alive_and_idling_ends_it() {
        let dir = temp_dir("grants");
        let store = GrantStore::load(dir.to_str().unwrap());
        let gid = store.create("1", IDLE, 0).unwrap();

        // 使うたびに延びる: 総時間は IDLE を超えても、間が IDLE 以内なら続く
        for now in [900, 1800, 2700, 3600] {
            assert!(store.touch(&gid, "1", IDLE, now), "at {now}");
        }
        // ちょうど IDLE までは有効、超えたら無効 (そのあとは、使おうとしても戻らない)
        assert!(store.touch(&gid, "1", IDLE, 4600));
        assert!(!store.touch(&gid, "1", IDLE, 5601));
        assert!(!store.touch(&gid, "1", IDLE, 5602));
        assert_eq!(store.len(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_grants_and_other_users_are_refused() {
        let dir = temp_dir("grants-other");
        let store = GrantStore::load(dir.to_str().unwrap());
        let gid = store.create("1", IDLE, 0).unwrap();
        assert!(!store.touch("nope", "1", IDLE, 1));
        assert!(!store.touch(&gid, "2", IDLE, 1), "gid of someone else");
        assert!(store.touch(&gid, "1", IDLE, 1));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn grants_survive_a_restart_and_a_lost_record_means_invalid() {
        let dir = temp_dir("grants-restart");
        let store = GrantStore::load(dir.to_str().unwrap());
        let gid = store.create("1", IDLE, 100).unwrap();
        let reloaded = GrantStore::load(dir.to_str().unwrap());
        assert!(reloaded.touch(&gid, "1", IDLE, 200));

        std::fs::remove_file(dir.join(FILE_NAME)).unwrap();
        let lost = GrantStore::load(dir.to_str().unwrap());
        assert!(!lost.touch(&gid, "1", IDLE, 200));
        std::fs::write(dir.join(FILE_NAME), "{broken").unwrap();
        assert!(!GrantStore::load(dir.to_str().unwrap()).touch(&gid, "1", IDLE, 200));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn last_use_is_saved_in_batches_and_idle_grants_are_dropped_on_save() {
        let dir = temp_dir("grants-batch");
        let store = GrantStore::load(dir.to_str().unwrap());
        let old = store.create("old", IDLE, 0).unwrap();
        let gid = store.create("1", IDLE, 5000).unwrap(); // 作るときに、使われなかった連携を捨てる
        assert!(!store.touch(&old, "old", IDLE, 5000));

        // SAVE_EVERY より前は、ファイルに書かない
        assert!(store.touch(&gid, "1", IDLE, 5100));
        let saved: Grants =
            serde_json::from_slice(&std::fs::read(dir.join(FILE_NAME)).unwrap()).unwrap();
        assert_eq!(saved[&gid].2, 5000);
        // SAVE_EVERY を過ぎたら、まとめて書く
        assert!(store.touch(&gid, "1", IDLE, 5000 + SAVE_EVERY));
        let saved: Grants =
            serde_json::from_slice(&std::fs::read(dir.join(FILE_NAME)).unwrap()).unwrap();
        assert_eq!(saved[&gid].2, 5000 + SAVE_EVERY);
        assert_eq!(saved.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn one_user_cannot_pile_up_grants() {
        let dir = temp_dir("grants-cap");
        let store = GrantStore::load(dir.to_str().unwrap());
        let other = store.create("other", IDLE, 0).unwrap();
        let gids: Vec<String> = (0..MAX_GRANTS_PER_USER as i64 + 1)
            .map(|now| store.create("1", IDLE, now).unwrap())
            .collect();
        assert_eq!(store.len(), MAX_GRANTS_PER_USER + 1);
        // いちばん古いものだけが消え、他の人の連携は巻き込まない
        assert!(!store.touch(&gids[0], "1", IDLE, 100));
        assert!(store.touch(&gids[1], "1", IDLE, 100));
        assert!(store.touch(gids.last().unwrap(), "1", IDLE, 100));
        assert!(store.touch(&other, "other", IDLE, 100));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_save_creates_nothing() {
        let dir = temp_dir("grants-fail");
        let store = GrantStore::load(dir.to_str().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(store.create("1", IDLE, 0).is_err());
        assert_eq!(store.len(), 0);
    }
}
