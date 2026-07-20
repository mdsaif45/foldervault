//! End-to-end lock/unlock tests over real temp directories.

use std::fs;
use std::path::{Path, PathBuf};

use vault_core::crypto::KdfParams;
use vault_core::format::{
    inspect, lock_folder, unlock_container, verify_structure, Credential, LockOptions,
};
use vault_core::journal::{Journal, OpKind, Record, RecoveryAction};
use vault_core::recovery;
use vault_core::VaultError;

const HMAC_KEY: [u8; 32] = [0xAB; 32];
const NOW: u64 = 1_800_000_000;

fn fast_opts() -> LockOptions {
    LockOptions {
        kdf: Some(KdfParams { m_cost_kib: 1024, t_cost: 1, lanes: 1 }),
        ..Default::default()
    }
}

fn nop(_done: u64, _total: u64) {}

fn lock(src: &Path, pw: &[u8]) -> vault_core::Result<PathBuf> {
    lock_folder(src, pw, &HMAC_KEY, &fast_opts(), None, &mut nop)
}

fn unlock(c: &Path, pw: &[u8], now: u64) -> vault_core::Result<PathBuf> {
    unlock_container(c, Credential::Password(pw), &HMAC_KEY, now, None, &mut nop)
}

/// Build a representative tree: nested dirs, empty file, empty dir,
/// unicode names, and a 3 MiB file (multi-chunk).
fn build_tree(root: &Path) -> PathBuf {
    let src = root.join("Photos");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("a.txt"), b"hello world").unwrap();
    fs::create_dir_all(src.join("sub/inner")).unwrap();
    fs::write(src.join("sub/inner/b.bin"), vec![7u8; 300]).unwrap();
    fs::write(src.join("sub/empty.dat"), b"").unwrap();
    fs::create_dir(src.join("hollow")).unwrap();
    fs::write(src.join("файл-日本語.txt"), "юникод контент".as_bytes()).unwrap();
    let big: Vec<u8> = (0..3 * 1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
    fs::write(src.join("big.bin"), &big).unwrap();
    src
}

fn snapshot(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    collect(root, root, &mut out);
    out.sort();
    out
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Option<Vec<u8>>)>) {
    for item in fs::read_dir(dir).unwrap() {
        let p = item.unwrap().path();
        let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        if p.is_dir() {
            out.push((rel, None));
            collect(root, &p, out);
        } else {
            out.push((rel, Some(fs::read(&p).unwrap())));
        }
    }
}

#[test]
fn lock_unlock_roundtrip_preserves_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let before = snapshot(&src);

    let container = lock(&src, b"correct horse").unwrap();
    assert!(!src.exists(), "source folder must be gone after lock");
    assert_eq!(container, tmp.path().join("Photos.fvlt"));
    assert!(verify_structure(&container, &HMAC_KEY).unwrap() > 3);

    let restored = unlock(&container, b"correct horse", NOW).unwrap();
    assert!(!container.exists(), "container must be gone after unlock");
    assert_eq!(restored, src);
    assert_eq!(snapshot(&restored), before);
}

#[test]
fn wrong_password_counts_down_then_correct_password_resets() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock(&src, b"right").unwrap();

    match unlock(&container, b"wrong1", NOW) {
        Err(VaultError::WrongPassword { attempts_left }) => assert_eq!(attempts_left, 2),
        other => panic!("expected WrongPassword, got {other:?}"),
    }
    assert!(!src.exists(), "failed unlock must not extract anything");
    assert_eq!(inspect(&container, &HMAC_KEY).unwrap().lockout.fail_count, 1);

    // correct password still works and clears the counter
    unlock(&container, b"right", NOW).unwrap();
    assert!(src.exists());
}

#[test]
fn three_failures_lock_out_even_the_correct_password() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock(&src, b"right").unwrap();

    for expected_left in [2u32, 1] {
        match unlock(&container, b"nope", NOW) {
            Err(VaultError::WrongPassword { attempts_left }) => {
                assert_eq!(attempts_left, expected_left)
            }
            other => panic!("expected WrongPassword, got {other:?}"),
        }
    }
    let until = match unlock(&container, b"nope", NOW) {
        Err(VaultError::LockedOut { until_unix }) => until_unix,
        other => panic!("expected LockedOut, got {other:?}"),
    };
    assert_eq!(until, NOW + 24 * 60 * 60);

    // correct password during the window -> still locked out
    assert!(matches!(
        unlock(&container, b"right", NOW + 60),
        Err(VaultError::LockedOut { .. })
    ));
    // clock rollback -> still locked out
    assert!(matches!(
        unlock(&container, b"right", NOW - 999_999),
        Err(VaultError::LockedOut { .. })
    ));
    // window expired -> correct password unlocks
    unlock(&container, b"right", until + 1).unwrap();
    assert!(src.exists());
}

#[test]
fn master_code_unlocks_even_during_lockout() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let before = snapshot(&src);
    let master = recovery::generate();

    let mut opts = fast_opts();
    opts.master_pub = Some(master.public);
    let container =
        lock_folder(&src, b"forgotten", &HMAC_KEY, &opts, None, &mut nop).unwrap();

    // burn all three attempts -> locked out
    for _ in 0..3 {
        let _ = unlock(&container, b"guess", NOW);
    }
    assert!(matches!(
        unlock(&container, b"forgotten", NOW),
        Err(VaultError::LockedOut { .. })
    ));

    // wrong master code -> clean error, container intact
    let bogus = recovery::generate();
    assert!(matches!(
        unlock_container(&container, Credential::MasterCode(&bogus.code), &HMAC_KEY, NOW, None, &mut nop),
        Err(VaultError::Other(_))
    ));
    assert!(container.exists());

    // correct master code -> unlocks DURING the lockout window
    let restored = unlock_container(
        &container, Credential::MasterCode(&master.code), &HMAC_KEY, NOW, None, &mut nop,
    )
    .unwrap();
    assert_eq!(snapshot(&restored), before);
}

#[test]
fn master_code_rejected_when_not_enrolled() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock(&src, b"pw").unwrap();
    let master = recovery::generate();
    match unlock_container(
        &container, Credential::MasterCode(&master.code), &HMAC_KEY, NOW, None, &mut nop,
    ) {
        Err(VaultError::Other(msg)) => assert!(msg.contains("no master key")),
        other => panic!("expected not-enrolled error, got {other:?}"),
    }
}

#[test]
fn payload_tamper_is_detected_and_nothing_is_extracted() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock(&src, b"pw").unwrap();

    // flip one bit deep in the payload (past header + manifest)
    let mut bytes = fs::read(&container).unwrap();
    let at = bytes.len() - 1000;
    bytes[at] ^= 0x01;
    fs::write(&container, &bytes).unwrap();

    assert!(matches!(unlock(&container, b"pw", NOW), Err(VaultError::Tampered)));
    assert!(!src.exists(), "tampered container must not extract");
    assert!(
        !tmp.path().join("Photos.__restoring").exists(),
        "partial extraction must be cleaned up"
    );
}

#[test]
fn foreign_hmac_key_allows_single_attempt_then_locks() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock(&src, b"pw").unwrap();

    // "another machine": different install key -> lockout fields untrusted
    let other_key = [0xCD; 32];
    match unlock_container(&container, Credential::Password(b"wrong"), &other_key, NOW, None, &mut nop) {
        Err(VaultError::LockedOut { .. }) => {}
        other => panic!("foreign container should lock after one failure, got {other:?}"),
    }
    // but the correct password on the foreign machine still works pre-failure:
    // re-lock a fresh copy and unlock with the right password first try
    let src2 = {
        let s = tmp.path().join("Docs");
        fs::create_dir(&s).unwrap();
        fs::write(s.join("x.txt"), b"data").unwrap();
        s
    };
    let c2 = lock(&src2, b"pw").unwrap();
    unlock_container(&c2, Credential::Password(b"pw"), &other_key, NOW, None, &mut nop).unwrap();
    assert!(src2.exists());
}

#[test]
fn lock_refuses_to_overwrite_existing_container() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    fs::write(tmp.path().join("Photos.fvlt"), b"already here").unwrap();
    assert!(matches!(lock(&src, b"pw"), Err(VaultError::Exists(_))));
    assert!(src.exists(), "source must be untouched when lock refuses");
}

#[test]
fn unlock_refuses_when_destination_folder_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock(&src, b"pw").unwrap();
    fs::create_dir(tmp.path().join("Photos")).unwrap();
    assert!(matches!(unlock(&container, b"pw", NOW), Err(VaultError::Exists(_))));
    assert!(container.exists(), "container must survive a refused unlock");
}

#[test]
fn secure_delete_locks_and_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let before = snapshot(&src);
    let mut opts = fast_opts();
    opts.secure_delete = true;
    let container = lock_folder(&src, b"pw", &HMAC_KEY, &opts, None, &mut nop).unwrap();
    assert!(!src.exists());
    let restored = unlock(&container, b"pw", NOW).unwrap();
    assert_eq!(snapshot(&restored), before);
}

// ---------- journal / crash recovery ----------

#[test]
fn journal_finishes_interrupted_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let journal = Journal::open(&tmp.path().join("journal")).unwrap();
    let src = build_tree(tmp.path());
    let container = lock(&src, b"pw").unwrap();

    // simulate "crash between rename and source delete": the container is
    // complete but the source folder is still on disk, record left behind
    fs::create_dir(&src).unwrap();
    fs::write(src.join("leftover.txt"), b"plain").unwrap();
    let rec = Record {
        op: OpKind::Lock,
        folder: src.to_string_lossy().into_owned(),
        container: container.to_string_lossy().into_owned(),
        staging: tmp.path().join("Photos.fvlt.tmp").to_string_lossy().into_owned(),
    };
    journal.begin(&[1u8; 16], &rec).unwrap();

    let actions = journal.recover(&HMAC_KEY).unwrap();
    assert_eq!(actions, vec![RecoveryAction::FinishedLock(src.clone())]);
    assert!(!src.exists(), "recovery must finish deleting the source");
    assert!(container.exists());
    // second run: nothing left to do
    assert!(journal.recover(&HMAC_KEY).unwrap().is_empty());
}

#[test]
fn journal_rolls_back_lock_that_never_renamed() {
    let tmp = tempfile::tempdir().unwrap();
    let journal = Journal::open(&tmp.path().join("journal")).unwrap();
    let src = build_tree(tmp.path());
    let staging = tmp.path().join("Photos.fvlt.tmp");
    fs::write(&staging, b"half-written garbage").unwrap();
    let rec = Record {
        op: OpKind::Lock,
        folder: src.to_string_lossy().into_owned(),
        container: tmp.path().join("Photos.fvlt").to_string_lossy().into_owned(),
        staging: staging.to_string_lossy().into_owned(),
    };
    journal.begin(&[2u8; 16], &rec).unwrap();

    let actions = journal.recover(&HMAC_KEY).unwrap();
    assert_eq!(actions, vec![RecoveryAction::RolledBackLock(staging.clone())]);
    assert!(!staging.exists());
    assert!(src.exists(), "source must be untouched by rollback");
}

#[test]
fn journal_finishes_interrupted_unlock() {
    let tmp = tempfile::tempdir().unwrap();
    let journal = Journal::open(&tmp.path().join("journal")).unwrap();
    let src = build_tree(tmp.path());
    let container = lock(&src, b"pw").unwrap();
    let restored = unlock(&container, b"pw", NOW).unwrap();

    // simulate "crash between rename and container delete": folder restored,
    // container still on disk (recreate a fake one), record left behind
    fs::write(&container, b"stale container").unwrap();
    let rec = Record {
        op: OpKind::Unlock,
        folder: restored.to_string_lossy().into_owned(),
        container: container.to_string_lossy().into_owned(),
        staging: tmp.path().join("Photos.__restoring").to_string_lossy().into_owned(),
    };
    journal.begin(&[3u8; 16], &rec).unwrap();

    let actions = journal.recover(&HMAC_KEY).unwrap();
    assert_eq!(actions, vec![RecoveryAction::FinishedUnlock(container.clone())]);
    assert!(!container.exists(), "recovery must finish deleting the container");
    assert!(restored.exists());
}

#[test]
fn journal_rolls_back_unlock_that_never_renamed() {
    let tmp = tempfile::tempdir().unwrap();
    let journal = Journal::open(&tmp.path().join("journal")).unwrap();
    let src = build_tree(tmp.path());
    let container = lock(&src, b"pw").unwrap();

    // staging fully extracted but rename never happened
    let staging = tmp.path().join("Photos.__restoring");
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("x.txt"), b"extracted plaintext").unwrap();
    let rec = Record {
        op: OpKind::Unlock,
        folder: src.to_string_lossy().into_owned(),
        container: container.to_string_lossy().into_owned(),
        staging: staging.to_string_lossy().into_owned(),
    };
    journal.begin(&[4u8; 16], &rec).unwrap();

    let actions = journal.recover(&HMAC_KEY).unwrap();
    assert_eq!(actions, vec![RecoveryAction::RolledBackUnlock(staging.clone())]);
    assert!(!staging.exists(), "plaintext staging must be removed");
    assert!(container.exists(), "container must remain the source of truth");
    // and the container still unlocks normally afterwards
    unlock(&container, b"pw", NOW).unwrap();
}
