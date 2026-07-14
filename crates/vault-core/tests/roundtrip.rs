//! End-to-end lock/unlock tests over real temp directories.

use std::fs;
use std::path::{Path, PathBuf};

use vault_core::crypto::KdfParams;
use vault_core::format::{inspect, lock_folder, unlock_container, verify_structure, LockOptions};
use vault_core::VaultError;

const HMAC_KEY: [u8; 32] = [0xAB; 32];
const NOW: u64 = 1_800_000_000;

fn fast_opts() -> LockOptions {
    LockOptions { kdf: Some(KdfParams { m_cost_kib: 1024, t_cost: 1, lanes: 1 }) }
}

fn nop(_done: u64, _total: u64) {}

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

    let container = lock_folder(&src, b"correct horse", &HMAC_KEY, &fast_opts(), &mut nop).unwrap();
    assert!(!src.exists(), "source folder must be gone after lock");
    assert_eq!(container, tmp.path().join("Photos.fvlt"));
    assert!(verify_structure(&container, &HMAC_KEY).unwrap() > 3);

    let restored =
        unlock_container(&container, b"correct horse", &HMAC_KEY, NOW, &mut nop).unwrap();
    assert!(!container.exists(), "container must be gone after unlock");
    assert_eq!(restored, src);
    assert_eq!(snapshot(&restored), before);
}

#[test]
fn wrong_password_counts_down_then_correct_password_resets() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock_folder(&src, b"right", &HMAC_KEY, &fast_opts(), &mut nop).unwrap();

    match unlock_container(&container, b"wrong1", &HMAC_KEY, NOW, &mut nop) {
        Err(VaultError::WrongPassword { attempts_left }) => assert_eq!(attempts_left, 2),
        other => panic!("expected WrongPassword, got {other:?}"),
    }
    assert!(!src.exists(), "failed unlock must not extract anything");
    assert_eq!(inspect(&container, &HMAC_KEY).unwrap().lockout.fail_count, 1);

    // correct password still works and clears the counter
    unlock_container(&container, b"right", &HMAC_KEY, NOW, &mut nop).unwrap();
    assert!(src.exists());
}

#[test]
fn three_failures_lock_out_even_the_correct_password() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock_folder(&src, b"right", &HMAC_KEY, &fast_opts(), &mut nop).unwrap();

    for expected_left in [2u32, 1] {
        match unlock_container(&container, b"nope", &HMAC_KEY, NOW, &mut nop) {
            Err(VaultError::WrongPassword { attempts_left }) => {
                assert_eq!(attempts_left, expected_left)
            }
            other => panic!("expected WrongPassword, got {other:?}"),
        }
    }
    let until = match unlock_container(&container, b"nope", &HMAC_KEY, NOW, &mut nop) {
        Err(VaultError::LockedOut { until_unix }) => until_unix,
        other => panic!("expected LockedOut, got {other:?}"),
    };
    assert_eq!(until, NOW + 24 * 60 * 60);

    // correct password during the window -> still locked out
    assert!(matches!(
        unlock_container(&container, b"right", &HMAC_KEY, NOW + 60, &mut nop),
        Err(VaultError::LockedOut { .. })
    ));
    // clock rollback -> still locked out
    assert!(matches!(
        unlock_container(&container, b"right", &HMAC_KEY, NOW - 999_999, &mut nop),
        Err(VaultError::LockedOut { .. })
    ));
    // window expired -> correct password unlocks
    unlock_container(&container, b"right", &HMAC_KEY, until + 1, &mut nop).unwrap();
    assert!(src.exists());
}

#[test]
fn payload_tamper_is_detected_and_nothing_is_extracted() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock_folder(&src, b"pw", &HMAC_KEY, &fast_opts(), &mut nop).unwrap();

    // flip one bit deep in the payload (past header + manifest)
    let mut bytes = fs::read(&container).unwrap();
    let at = bytes.len() - 1000;
    bytes[at] ^= 0x01;
    fs::write(&container, &bytes).unwrap();

    assert!(matches!(
        unlock_container(&container, b"pw", &HMAC_KEY, NOW, &mut nop),
        Err(VaultError::Tampered)
    ));
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
    let container = lock_folder(&src, b"pw", &HMAC_KEY, &fast_opts(), &mut nop).unwrap();

    // "another machine": different install key -> lockout fields untrusted
    let other_key = [0xCD; 32];
    match unlock_container(&container, b"wrong", &other_key, NOW, &mut nop) {
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
    let c2 = lock_folder(&src2, b"pw", &HMAC_KEY, &fast_opts(), &mut nop).unwrap();
    unlock_container(&c2, b"pw", &other_key, NOW, &mut nop).unwrap();
    assert!(src2.exists());
}

#[test]
fn lock_refuses_to_overwrite_existing_container() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    fs::write(tmp.path().join("Photos.fvlt"), b"already here").unwrap();
    assert!(matches!(
        lock_folder(&src, b"pw", &HMAC_KEY, &fast_opts(), &mut nop),
        Err(VaultError::Exists(_))
    ));
    assert!(src.exists(), "source must be untouched when lock refuses");
}

#[test]
fn unlock_refuses_when_destination_folder_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let src = build_tree(tmp.path());
    let container = lock_folder(&src, b"pw", &HMAC_KEY, &fast_opts(), &mut nop).unwrap();
    fs::create_dir(tmp.path().join("Photos")).unwrap();
    assert!(matches!(
        unlock_container(&container, b"pw", &HMAC_KEY, NOW, &mut nop),
        Err(VaultError::Exists(_))
    ));
    assert!(container.exists(), "container must survive a refused unlock");
}
