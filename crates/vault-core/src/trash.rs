//! Recycle-bin deletion + read-only guard for locked containers.
//!
//! Deleting user data (the original folder on lock, the container on unlock)
//! goes to the Recycle Bin so a mistake is recoverable, instead of a permanent
//! delete. Setting the `.fvlt` read-only adds a delete-confirmation prompt in
//! Explorer — friction against accidental deletion, NOT a hard block (see
//! docs/THREAT-MODEL.md: encryption protects secrecy, not availability).

use std::path::Path;

/// Send a file or directory to the Recycle Bin. Falls back to a permanent
/// delete only if the shell operation is unavailable (non-Windows / error),
/// so a lock/unlock never gets stuck with both copies on disk.
pub fn recycle(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        if recycle_win(path) {
            return Ok(());
        }
    }
    // fallback: permanent delete
    if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Mark a file read-only (adds Explorer's delete confirmation).
pub fn set_readonly(path: &Path, readonly: bool) -> std::io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_readonly(readonly);
    std::fs::set_permissions(path, perms)
}

#[cfg(windows)]
fn recycle_win(path: &Path) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::{
        SHFileOperationW, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT,
        SHFILEOPSTRUCTW, FO_DELETE,
    };

    // pFrom must be double-NUL terminated
    let mut from: Vec<u16> = path.as_os_str().encode_wide().collect();
    from.push(0);
    from.push(0);

    let flags = FOF_ALLOWUNDO.0 | FOF_NOCONFIRMATION.0 | FOF_NOERRORUI.0 | FOF_SILENT.0;
    let mut op = SHFILEOPSTRUCTW {
        wFunc: FO_DELETE,
        pFrom: PCWSTR(from.as_ptr()),
        fFlags: flags as u16,
        ..Default::default()
    };
    let rc = unsafe { SHFileOperationW(&mut op) };
    rc == 0 && !op.fAnyOperationsAborted.as_bool()
}

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recycle_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("gone.txt");
        std::fs::write(&f, b"bye").unwrap();
        recycle(&f).unwrap();
        assert!(!f.exists());
    }

    #[test]
    fn recycle_removes_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("a.txt"), b"x").unwrap();
        recycle(&sub).unwrap();
        assert!(!sub.exists());
    }

    #[test]
    fn readonly_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("ro.fvlt");
        std::fs::write(&f, b"data").unwrap();
        set_readonly(&f, true).unwrap();
        assert!(std::fs::metadata(&f).unwrap().permissions().readonly());
        set_readonly(&f, false).unwrap();
        assert!(!std::fs::metadata(&f).unwrap().permissions().readonly());
    }
}
