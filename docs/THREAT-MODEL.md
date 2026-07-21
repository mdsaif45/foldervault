# FolderVault — Threat Model (honest version)

## What FolderVault protects against

| Adversary | Protected? | Why |
|---|---|---|
| Family member / coworker snooping on the machine | ✅ | Contents + filenames encrypted; no password → no data. |
| Someone copying the `.fvlt` file to another PC | ✅ (confidentiality) | AES-256-GCM; offline brute force throttled by Argon2id (64 MiB, ~100 ms/guess). Strong password ⇒ infeasible. |
| Tampering with the container | ✅ detected | Every byte is authenticated (GCM tags + header HMAC). Modified data fails to decrypt rather than extracting garbage. |
| Resetting the 3-attempt counter by editing the file | ⚠️ detected on same machine | HMAC + registry mirror. On a *different* machine the counter doesn't apply — Argon2id is the real barrier. |

## What it does NOT protect against

- **Deletion / ransom**: anyone with file access can delete `Photos.fvlt`.
  Encryption protects secrecy, not availability. Backups are the answer.

  FolderVault adds *friction* layers, not guarantees:
  - the locked `.fvlt` is marked **read-only**, so Explorer shows a
    delete-confirmation prompt (stops a careless single click, not a
    determined delete);
  - deletions FolderVault performs itself (the original folder on lock, the
    container on unlock/delete) go to the **Recycle Bin**, so an accidental
    operation is recoverable;
  - a **"Delete with FolderVault"** right-click verb (and `fvlt delete`) asks
    for the password/recovery code before recycling — sharing unlock's
    3-attempt / 24 h lockout so it isn't an unlimited password oracle.

  None of these truly *prevent* deletion: the file is yours on your disk, so
  you (or malware running as you, or another OS) can always clear the
  read-only bit and use the OS's own Delete / `del` / a live USB. The password
  verb is a **convenience gate on FolderVault's delete path, not enforcement**
  — it does not remove or intercept Windows' built-in Delete.

  Enforcement options investigated (and why none ship yet):
  - **File-level deny-delete ACL — tried, DOES NOT WORK reliably.** We
    prototyped an explicit `DELETE`-deny ACE on the container for the user's
    SID. It blocks deletion only in directories that don't grant the user
    `FILE_DELETE_CHILD` on the parent (e.g. a fresh root folder). In the very
    places people keep folders — `%USERPROFILE%\Documents`, `Desktop`, temp —
    the parent grants the owner delete-child, which satisfies the delete
    regardless of the file's own DACL, so the ACE is silently ineffective.
    Confirmed by measurement (Documents: not blocked; `D:\` fresh dir:
    blocked). We will not ship a "protection" that quietly does nothing where
    it matters most. (Denying `FILE_DELETE_CHILD` on the *parent* would block
    deleting every file in that folder and needs `SeSecurityPrivilege` — not
    acceptable.)
  - **out of scope — kernel minifilter driver**: the only mechanism that
    truly blocks deletion everywhere (even admin/Shift+Del), but needs a
    signed driver + admin install and contradicts the lightweight, low-risk
    goal. This is the only real path to hard delete-prevention if it ever
    becomes a requirement.

  The only real protection against losing data remains a backup / second
  encrypted copy somewhere the attacker can't reach.
- **Malware running as you while the folder is unlocked**: once extracted,
  files are plaintext on disk.
- **Forgotten password + lost master key**: unrecoverable by design. No backdoor.
  (The master key is X25519: only the *public* half lives on disk — it can seal
  data keys but never open them. The recovery code is shown once and never
  stored; someone stealing the machine cannot use master recovery.)
- **Forensic recovery of pre-lock plaintext**: deleting originals doesn't wipe
  disk sectors (SSDs make secure wipe unreliable anyway). `--secure-delete`
  does a best-effort overwrite; the honest fix is locking data early in its life.

## Why the 24-hour lockout is a deterrent, not cryptography

The lockout state travels with the file and is mirrored in the registry, both
HMAC-keyed to this install. That stops the casual attacker at the same keyboard.
An attacker who images the file and scripts guesses elsewhere is limited only by
Argon2id cost — which is why the UI enforces a minimum password strength and the
first-run flow pushes the user to store the master recovery key somewhere safe.

## Non-goals (rejected approaches)

- ACL-deny / hidden+system attributes / `CLSID` folder tricks (classic
  "folder locker" apps): trivially bypassed by a live USB, safe mode, or
  another OS reading the disk. We refuse to ship security theater.
- Kernel filter driver for on-the-fly transparent encryption: real product
  (that's EFS/BitLocker territory), but a driver contradicts "lightweight,
  tiny, low-risk". Out of scope.
