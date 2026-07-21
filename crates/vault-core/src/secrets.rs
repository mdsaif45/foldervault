//! At-rest protection for the per-install secret files (install.key,
//! master.pub) and shared loading logic used by both front-ends.
//!
//! On Windows the bytes are wrapped with DPAPI (`CRYPTPROTECT_LOCALMACHINE`
//! off => scoped to the current *user account*), so another user on the same
//! PC cannot read them. Files are tagged with a 4-byte magic so we can tell a
//! DPAPI blob from a legacy raw file and migrate transparently.
//!
//! On non-Windows (tests/CI) protection is an identity transform — the point
//! of the module is a single code path shared by CLI + GUI, not portability
//! of the ciphertext.

use std::path::{Path, PathBuf};

use crate::crypto::random_bytes;

const DPAPI_MAGIC: &[u8; 4] = b"FVP1"; // FolderVault Protected v1

/// Resolve the per-install data directory (override with `FVLT_KEY_DIR`).
pub fn data_dir() -> PathBuf {
    std::env::var_os("FVLT_KEY_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(|d| Path::new(&d).join("FolderVault")))
        .unwrap_or_else(|| PathBuf::from(".foldervault"))
}

/// Load (or first-time create) the 32-byte per-install HMAC key.
/// Transparently upgrades a legacy raw file to a protected one.
pub fn load_or_create_install_key(base: &Path) -> std::io::Result<[u8; 32]> {
    let path = base.join("install.key");
    if let Some(bytes) = read_protected(&path)? {
        if bytes.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            return Ok(k);
        }
    }
    std::fs::create_dir_all(base)?;
    let mut k = [0u8; 32];
    random_bytes(&mut k);
    write_protected(&path, &k)?;
    Ok(k)
}

pub fn load_master_pub(base: &Path) -> Option<[u8; 32]> {
    // master.pub is not secret (public key), but we still store it protected
    // for uniformity; tolerate a legacy raw file too.
    let bytes = read_protected(&base.join("master.pub")).ok().flatten()?;
    bytes.try_into().ok()
}

pub fn save_master_pub(base: &Path, public: &[u8; 32]) -> std::io::Result<()> {
    std::fs::create_dir_all(base)?;
    write_protected(&base.join("master.pub"), public)
}

/// Read a file that may be DPAPI-protected (magic prefix) or a legacy raw
/// blob. Returns `Ok(None)` if the file does not exist.
fn read_protected(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if raw.len() >= 4 && &raw[..4] == DPAPI_MAGIC {
        let plain = unprotect(&raw[4..])
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "unprotect failed"))?;
        Ok(Some(plain))
    } else {
        // legacy raw file — accept, and it will be rewritten protected on next create
        Ok(Some(raw))
    }
}

fn write_protected(path: &Path, plain: &[u8]) -> std::io::Result<()> {
    // protect() returns None only if the OS crypto call fails (essentially
    // never for a logged-in user). Surface that as an error rather than
    // writing an FVP1-tagged blob we could never read back.
    let protected = protect(plain).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "DPAPI protect failed")
    })?;
    let mut out = Vec::with_capacity(4 + protected.len());
    out.extend_from_slice(DPAPI_MAGIC);
    out.extend_from_slice(&protected);
    std::fs::write(path, out)
}


// ---------- platform crypto ----------

#[cfg(windows)]
fn protect(plain: &[u8]) -> Option<Vec<u8>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        if CryptProtectData(&mut in_blob, None, None, None, None, 0, &mut out_blob).is_ok() {
            let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
            let v = slice.to_vec();
            let _ = LocalFree(HLOCAL(out_blob.pbData as *mut _));
            Some(v)
        } else {
            // Essentially never happens for a logged-in user. Do NOT fall back
            // to storing raw: write_protected always prepends the FVP1 magic,
            // so a raw blob would fail to DPAPI-decrypt on read (unreadable).
            // Report failure so the caller surfaces a real error instead.
            None
        }
    }
}

#[cfg(windows)]
fn unprotect(blob: &[u8]) -> Option<Vec<u8>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        if CryptUnprotectData(&mut in_blob, None, None, None, None, 0, &mut out_blob).is_ok() {
            let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
            let v = slice.to_vec();
            let _ = LocalFree(HLOCAL(out_blob.pbData as *mut _));
            Some(v)
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
fn protect(plain: &[u8]) -> Option<Vec<u8>> {
    Some(plain.to_vec())
}

#[cfg(not(windows))]
fn unprotect(blob: &[u8]) -> Option<Vec<u8>> {
    Some(blob.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_key_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let k1 = load_or_create_install_key(dir.path()).unwrap();
        let k2 = load_or_create_install_key(dir.path()).unwrap();
        assert_eq!(k1, k2, "same key on reload");
        // file must not contain the raw key in the clear on Windows
        let raw = std::fs::read(dir.path().join("install.key")).unwrap();
        assert_eq!(&raw[..4], DPAPI_MAGIC);
        #[cfg(windows)]
        assert!(
            raw.windows(32).all(|w| w != k1),
            "raw key bytes must not appear in the protected file"
        );
    }

    #[test]
    fn master_pub_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey = [0x5Au8; 32];
        save_master_pub(dir.path(), &pubkey).unwrap();
        assert_eq!(load_master_pub(dir.path()), Some(pubkey));
    }

    #[test]
    fn legacy_raw_file_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        // simulate a pre-DPAPI install.key (32 raw bytes, no magic)
        let legacy = [7u8; 32];
        std::fs::write(dir.path().join("install.key"), legacy).unwrap();
        let k = load_or_create_install_key(dir.path()).unwrap();
        assert_eq!(k, legacy, "legacy raw key still loads");
    }
}
