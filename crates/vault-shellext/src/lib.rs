//! FolderVault Windows 11 shell command (`IExplorerCommand`).
//!
//! A tiny in-proc COM server Explorer loads to place "Lock with FolderVault"
//! directly in the Win11 context menu (not under "Show more options"). The
//! command does nothing but shell-execute `FolderVault.exe lock "<folder>"`,
//! so all real logic stays in the main exe. Registration is done by the
//! sparse MSIX package (installer/msix), not by this DLL.
//!
//! CLSID: {7F9C2E14-4B3A-4E2D-9C7A-FV0LDER0LOCK}  (see msix/AppxManifest.xml)

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use windows::core::{implement, w, Interface, GUID, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{BOOL, CLASS_E_CLASSNOTAVAILABLE, E_NOINTERFACE, E_POINTER, S_OK};
use windows::Win32::System::Com::{IBindCtx, IClassFactory, IClassFactory_Impl};
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows::Win32::UI::Shell::{
    IEnumExplorerCommand, IExplorerCommand, IExplorerCommand_Impl, IShellItem, IShellItemArray,
    SHStrDupW, ShellExecuteW, ECS_DISABLED, ECS_ENABLED, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

// {7F9C2E14-4B3A-4E2D-9C7A-A1B2C3D4E5F6}
pub const CLSID_FOLDERVAULT_LOCK: GUID =
    GUID::from_u128(0x7F9C2E14_4B3A_4E2D_9C7A_A1B2C3D4E5F6);

static DLL_REFS: AtomicUsize = AtomicUsize::new(0);

fn dll_add_ref() {
    DLL_REFS.fetch_add(1, Ordering::SeqCst);
}
fn dll_release() {
    DLL_REFS.fetch_sub(1, Ordering::SeqCst);
}

/// Absolute path to THIS dll, so we can find FolderVault.exe next to it.
fn module_dir() -> Option<std::path::PathBuf> {
    unsafe {
        let mut hmod = windows::Win32::Foundation::HMODULE::default();
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(module_dir as *const u16),
            &mut hmod,
        )
        .ok()?;
        let mut buf = [0u16; 32768];
        let n = GetModuleFileNameW(hmod, &mut buf);
        if n == 0 {
            return None;
        }
        let path = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n as usize]));
        path.parent().map(|p| p.to_path_buf())
    }
}

/// The exe that does the work. Sits beside the DLL in the install/package dir.
fn foldervault_exe() -> Option<std::path::PathBuf> {
    let exe = module_dir()?.join("FolderVault.exe");
    exe.exists().then_some(exe)
}

#[implement(IExplorerCommand)]
struct LockCommand;

impl IExplorerCommand_Impl for LockCommand_Impl {
    fn GetTitle(&self, _items: Option<&IShellItemArray>) -> windows::core::Result<PWSTR> {
        unsafe { SHStrDupW(w!("Lock with FolderVault")) }
    }

    fn GetIcon(&self, _items: Option<&IShellItemArray>) -> windows::core::Result<PWSTR> {
        // "<exe>,-1" -> the app padlock icon resource
        if let Some(exe) = foldervault_exe() {
            let spec = format!("{},-1", exe.to_string_lossy());
            let wide: Vec<u16> = spec.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { SHStrDupW(PCWSTR(wide.as_ptr())) }
        } else {
            Err(E_POINTER.into())
        }
    }

    fn GetToolTip(&self, _items: Option<&IShellItemArray>) -> windows::core::Result<PWSTR> {
        Err(E_NOINTERFACE.into()) // no tooltip
    }

    fn GetCanonicalName(&self) -> windows::core::Result<GUID> {
        Ok(CLSID_FOLDERVAULT_LOCK)
    }

    fn GetState(&self, items: Option<&IShellItemArray>, _occ: BOOL) -> windows::core::Result<u32> {
        // enabled only for a single filesystem folder selection
        let Some(items) = items else { return Ok(ECS_DISABLED.0 as u32) };
        unsafe {
            if items.GetCount().unwrap_or(0) != 1 {
                return Ok(ECS_DISABLED.0 as u32);
            }
        }
        Ok(ECS_ENABLED.0 as u32)
    }

    fn Invoke(&self, items: Option<&IShellItemArray>, _ctx: Option<&IBindCtx>) -> windows::core::Result<()> {
        let Some(items) = items else { return Ok(()) };
        let Some(exe) = foldervault_exe() else { return Ok(()) };
        unsafe {
            let item: IShellItem = items.GetItemAt(0)?;
            let path = item.GetDisplayName(SIGDN_FILESYSPATH)?;
            let exe_w: Vec<u16> = exe.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
            let verb: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
            // params: lock "<path>"
            let quoted = format!("lock \"{}\"", path.to_string().unwrap_or_default());
            let params: Vec<u16> = quoted.encode_utf16().chain(std::iter::once(0)).collect();
            ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(exe_w.as_ptr()),
                PCWSTR(params.as_ptr()),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );
        }
        Ok(())
    }

    fn GetFlags(&self) -> windows::core::Result<u32> {
        Ok(0) // ECF_DEFAULT
    }

    fn EnumSubCommands(&self) -> windows::core::Result<IEnumExplorerCommand> {
        Err(E_NOINTERFACE.into())
    }
}

// ---------- class factory ----------

#[implement(IClassFactory)]
struct Factory;

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Option<&windows::core::IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> windows::core::Result<()> {
        unsafe {
            *object = std::ptr::null_mut();
        }
        if outer.is_some() {
            return Err(windows::Win32::Foundation::CLASS_E_NOAGGREGATION.into());
        }
        let cmd: IExplorerCommand = LockCommand.into();
        unsafe { cmd.query(&*iid, object).ok() }
    }

    fn LockServer(&self, lock: BOOL) -> windows::core::Result<()> {
        if lock.as_bool() {
            dll_add_ref();
        } else {
            dll_release();
        }
        Ok(())
    }
}

// ---------- DLL exports ----------

#[no_mangle]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    unsafe {
        if ppv.is_null() {
            return E_POINTER;
        }
        *ppv = std::ptr::null_mut();
        if *rclsid != CLSID_FOLDERVAULT_LOCK {
            return CLASS_E_CLASSNOTAVAILABLE;
        }
        let factory: IClassFactory = Factory.into();
        match factory.query(&*riid, ppv) {
            S_OK => S_OK,
            e => e,
        }
    }
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if DLL_REFS.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        windows::Win32::Foundation::S_FALSE
    }
}
