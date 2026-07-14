//! Explorer integration via HKCU registry (no admin, no COM — phase 3).
//!
//! setup() writes:
//!   HKCU\Software\Classes\Directory\shell\FolderVault.Lock
//!       (Default)="Lock with FolderVault", Icon="<exe>,0"
//!       \command (Default)="<exe>" lock "%1"
//!   HKCU\Software\Classes\.fvlt        (Default)="FolderVault.Container"
//!   HKCU\Software\Classes\FolderVault.Container
//!       DefaultIcon="<exe>,1"          ← folder+padlock icon resource
//!       \shell\open\command "<exe>" open "%1"
//! then SHChangeNotify(SHCNE_ASSOCCHANGED) so icons refresh without logoff.
//!
//! Lockout mirror: HKCU\Software\FolderVault\state\<container-uuid>.
//! Win11 top-level menu (sparse MSIX + IExplorerCommand) is phase 4.

// TODO(phase-3): implement.
