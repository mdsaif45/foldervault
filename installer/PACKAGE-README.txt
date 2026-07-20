FolderVault
===========

Lock any folder behind a password. A locked folder becomes a single encrypted
".fvlt" file with a padlock icon; double-click it to unlock.

FIRST RUN
---------
Double-click FolderVault.exe once. It will:
  * register the "Lock with FolderVault" entry in your right-click menu
  * register the .fvlt file type (double-click to unlock)
  * show your MASTER RECOVERY CODE one time -- write it down and keep it safe.

The recovery code is the ONLY way back in if you forget a folder's password.
FolderVault cannot recover it for you.

DAILY USE
---------
  * Lock:   right-click a folder -> "Lock with FolderVault" -> set a password.
  * Unlock: double-click the .fvlt file -> enter the password.
  * 3 wrong passwords locks that folder for 24 hours (the recovery code still
    works during a lockout).

PORTABLE NOTE
-------------
You can move this folder anywhere -- the next time you lock or unlock,
FolderVault notices the new location and re-registers itself automatically.

WINDOWS 11 TOP-LEVEL MENU (self-contained package only)
-------------------------------------------------------
Install the included FolderVault-*.msix to get "Lock with FolderVault" directly
in the Win11 right-click menu (instead of under "Show more options"). Without
it, the entry still works -- it just lives under "Show more options".

COMMAND LINE (fvlt.exe, in the cli package)
-------------------------------------------
  fvlt lock <folder>        fvlt unlock <file>
  fvlt inspect <file>       fvlt verify <file>
  fvlt master-init          generate a recovery code

SECURITY
--------
AES-256-GCM encryption, Argon2id password hashing, X25519 recovery key.
Your per-machine key is protected with Windows DPAPI. See FORMAT.md (cli
package) for the full container format and threat model.

UNINSTALL
---------
Use "Uninstall FolderVault" (installer build) or run "FolderVault.exe
unregister" then delete the files (portable build). Your locked .fvlt files
are NOT touched -- keep FolderVault (or the recovery code) to open them later.
