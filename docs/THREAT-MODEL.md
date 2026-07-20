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

  FolderVault adds two *friction* layers, not guarantees:
  - the locked `.fvlt` is marked **read-only**, so Explorer shows a
    delete-confirmation prompt (stops a careless single click, not a
    determined delete);
  - deletions FolderVault performs itself (the original folder on lock, the
    container on unlock) go to the **Recycle Bin**, so an accidental
    lock/unlock is recoverable.

  Neither can truly *prevent* deletion: the file is yours on your disk, so
  you (or malware running as you, or another OS) can always clear the
  read-only bit and delete it. A "password required to delete" feature is on
  the roadmap, but be clear-eyed that it can only ever be another
  confirmation prompt from *our* app — the shell's own Delete, `del` from a
  prompt, or a live USB bypass it entirely. The only real protection against
  losing data is a backup / second encrypted copy somewhere the attacker
  can't reach.
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
