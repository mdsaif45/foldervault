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
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None) };
    Ok(())
}
