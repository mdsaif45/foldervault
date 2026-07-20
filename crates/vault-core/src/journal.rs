//! Crash-recovery journal.
//!
//! Lock and unlock both follow "stage -> rename -> delete the other copy".
//! The only dangerous window is between the rename and the delete: a crash
//! there leaves BOTH copies on disk (never zero copies). A journal record is
//! written just before the rename and removed after the delete; `recover()`
//! replays any leftover record to finish (or tidy up) the interrupted step.
//!
//! Record files live in one directory (the app uses
//! `%LOCALAPPDATA%\FolderVault\journal`).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::format::verify_structure;
use crate::{Result, VaultError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpKind {
    Lock,
    Unlock,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub op: OpKind,
    /// The plaintext folder (lock: source being consumed; unlock: destination).
    pub folder: String,
    /// The .fvlt container involved.
    pub container: String,
    /// The staging path (.fvlt.tmp or .__restoring) of the op.
    pub staging: String,
}

pub struct Journal {
    dir: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Lock had fully written the container; removed the leftover source folder.
    FinishedLock(PathBuf),
    /// Lock never completed; removed its staging file (source untouched).
    RolledBackLock(PathBuf),
    /// Unlock had fully restored the folder; removed the leftover container.
    FinishedUnlock(PathBuf),
    /// Unlock never completed; removed its staging folder (container untouched).
    RolledBackUnlock(PathBuf),
}

impl Journal {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self { dir: dir.to_path_buf() })
    }

    /// Persist a record (fsynced) before the commit rename. Returns its path.
    pub fn begin(&self, uuid: &[u8; 16], record: &Record) -> Result<PathBuf> {
        let name: String = uuid.iter().map(|b| format!("{b:02x}")).collect();
        let path = self.dir.join(format!("{name}.jrec"));
        let bytes =
            bincode::serialize(record).map_err(|e| VaultError::Other(format!("journal: {e}")))?;
        let mut f = fs::File::create(&path)?;
        std::io::Write::write_all(&mut f, &bytes)?;
        f.sync_all()?;
        Ok(path)
    }

    pub fn complete(&self, record_path: &Path) {
        let _ = fs::remove_file(record_path);
    }

    /// Replay every leftover record. Call at app/CLI startup, before any
    /// lock/unlock. Destructive steps only run after verifying the container
    /// is structurally complete.
    pub fn recover(&self, hmac_key: &[u8; 32]) -> Result<Vec<RecoveryAction>> {
        let mut actions = Vec::new();
        for item in fs::read_dir(&self.dir)? {
            let path = item?.path();
            if path.extension().map(|e| e != "jrec").unwrap_or(true) {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else { continue };
            let Ok(rec) = bincode::deserialize::<Record>(&bytes) else {
                // unreadable record: drop it, never guess at destructive steps
                let _ = fs::remove_file(&path);
                continue;
            };
            if let Some(a) = replay(&rec, hmac_key) {
                actions.push(a);
            }
            let _ = fs::remove_file(&path);
        }
        Ok(actions)
    }
}

/// Invariant used below: if the STAGING path still exists, the commit rename
/// never ran, so the pre-rename copy is the source of truth and only the
/// staging leftovers may be removed. Deleting the "other copy" is allowed
/// only once staging is gone (rename provably happened) — and for lock, only
/// after the container passes a structural verify.
fn replay(rec: &Record, hmac_key: &[u8; 32]) -> Option<RecoveryAction> {
    let folder = Path::new(&rec.folder);
    let container = Path::new(&rec.container);
    let staging = Path::new(&rec.staging);
    match rec.op {
        OpKind::Lock => {
            if staging.exists() {
                let _ = fs::remove_file(staging);
                return Some(RecoveryAction::RolledBackLock(staging.to_path_buf()));
            }
            if folder.exists()
                && container.exists()
                && verify_structure(container, hmac_key).is_ok()
            {
                // crash between rename and source delete -> finish the delete
                // (recycle so it stays recoverable)
                crate::trash::recycle(folder).ok()?;
                return Some(RecoveryAction::FinishedLock(folder.to_path_buf()));
            }
            None
        }
        OpKind::Unlock => {
            if staging.exists() {
                let _ = fs::remove_dir_all(staging);
                return Some(RecoveryAction::RolledBackUnlock(staging.to_path_buf()));
            }
            if folder.exists() && container.exists() {
                // crash between rename and container delete -> finish
                let _ = crate::trash::set_readonly(container, false);
                crate::trash::recycle(container).ok()?;
                return Some(RecoveryAction::FinishedUnlock(container.to_path_buf()));
            }
            None
        }
    }
}
