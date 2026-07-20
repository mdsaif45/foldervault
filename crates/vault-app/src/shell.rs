//! Explorer integration (HKCU registry, no admin) + per-install data files.

use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE,
    REG_SZ,
};
use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// Key/secret handling lives in vault-core::secrets (DPAPI-protected on
// Windows) so the CLI and GUI share one code path. Re-export for convenience.
pub use vault_core::secrets::{
    data_dir, load_master_pub, load_or_create_install_key as install_key, save_master_pub,
};

fn set_value(root: HKEY, subkey: &str, value_name: Option<&str>, data: &str) -> windows::core::Result<()> {
    unsafe {
        let mut key = HKEY::default();
        let subkey_w = wide(subkey);
        RegCreateKeyExW(
            root,
            PCWSTR(subkey_w.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        )
        .ok()?;
        let name_w = value_name.map(wide);
        let data_w = wide(data);
        let bytes =
            std::slice::from_raw_parts(data_w.as_ptr() as *const u8, data_w.len() * 2);
        let res = RegSetValueExW(
            key,
            name_w.as_ref().map(|n| PCWSTR(n.as_ptr())).unwrap_or(PCWSTR::null()),
            0,
            REG_SZ,
            Some(bytes),
        );
        let _ = RegCloseKey(key);
        res.ok()?;
        Ok(())
    }
}

/// Register the .fvlt association (locked-folder icon + double-click open)
/// and the "Lock with FolderVault" verb on folders. HKCU only — no admin.
pub fn register(exe: &Path) -> windows::core::Result<()> {
    let exe = exe.to_string_lossy();
    let open_cmd = format!("\"{exe}\" open \"%1\"");
    let lock_cmd = format!("\"{exe}\" lock \"%1\"");
    let icon_locked = format!("\"{exe}\",-2");
    let icon_app = format!("\"{exe}\",-1");

    set_value(HKEY_CURRENT_USER, r"Software\Classes\.fvlt", None, "FolderVault.Container")?;
    set_value(
        HKEY_CURRENT_USER,
        r"Software\Classes\FolderVault.Container",
        None,
        "Locked folder (FolderVault)",
    )?;
    set_value(
        HKEY_CURRENT_USER,
        r"Software\Classes\FolderVault.Container\DefaultIcon",
        None,
        &icon_locked,
    )?;
    set_value(
        HKEY_CURRENT_USER,
        r"Software\Classes\FolderVault.Container\shell\open\command",
        None,
        &open_cmd,
    )?;
    set_value(
        HKEY_CURRENT_USER,
        r"Software\Classes\Directory\shell\FolderVault.Lock",
        None,
        "Lock with FolderVault",
    )?;
    set_value(
        HKEY_CURRENT_USER,
        r"Software\Classes\Directory\shell\FolderVault.Lock",
        Some("Icon"),
        &icon_app,
    )?;
    set_value(
        HKEY_CURRENT_USER,
        r"Software\Classes\Directory\shell\FolderVault.Lock\command",
        None,
        &lock_cmd,
    )?;
    // record where we registered, so we can detect a moved portable build
    set_value(
        HKEY_CURRENT_USER,
        r"Software\FolderVault",
        Some("RegisteredExe"),
        &exe,
    )?;
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None) };
    Ok(())
}

/// Cheap idempotent registration for every launch: re-registers only when the
/// exe path differs from what's recorded (or nothing is recorded yet). This
/// self-heals a portable build the user moved to a new folder.
pub fn register_if_needed(exe: &Path) {
    let want = exe.to_string_lossy().to_string();
    if read_registered_exe().as_deref() != Some(want.as_str()) {
        let _ = register(exe);
    }
}

fn read_registered_exe() -> Option<String> {
    use windows::Win32::System::Registry::{RegGetValueW, RRF_RT_REG_SZ};
    unsafe {
        let subkey = wide(r"Software\FolderVault");
        let name = wide("RegisteredExe");
        let mut buf = [0u16; 32768];
        let mut size = (buf.len() * 2) as u32;
        let rc = RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut size),
        );
        if rc.is_ok() {
            let n = (size as usize / 2).saturating_sub(1); // drop trailing NUL
            Some(String::from_utf16_lossy(&buf[..n]))
        } else {
            None
        }
    }
}

/// Remove all HKCU integration (used by the installer's uninstaller via
/// `FolderVault.exe unregister`).
pub fn unregister() {
    use windows::Win32::System::Registry::RegDeleteTreeW;
    unsafe {
        for sub in [
            r"Software\Classes\Directory\shell\FolderVault.Lock",
            r"Software\Classes\FolderVault.Container",
            r"Software\Classes\.fvlt",
            r"Software\FolderVault",
        ] {
            let w = wide(sub);
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(w.as_ptr()));
        }
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }
}
