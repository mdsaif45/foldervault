# Releasing FolderVault

One command builds all four GitHub-release artifacts:

```powershell
pwsh installer\build-release.ps1          # unsigned
pwsh installer\build-release.ps1 -Sign    # signed with a throwaway dev cert
pwsh installer\build-release.ps1 -Sign -CertPath prod.pfx -CertPass ****   # prod
```

Output lands in `dist/`:

| Artifact | What it is | Who it's for |
|---|---|---|
| `FolderVault-<ver>-installer.exe` | Inno Setup, per-user, no admin. Runs first-run setup, adds an uninstaller. | Most users. |
| `FolderVault-<ver>-portable.zip` | `FolderVault.exe` + `vault_shellext.dll` + README. Run from anywhere; self-registers and self-heals if moved. | No-install / USB-stick use. |
| `FolderVault-<ver>-selfcontained.zip` | Portable **plus** the sparse `.msix` for the Windows 11 top-level right-click menu. | Users who want the entry outside "Show more options". |
| `fvlt-<ver>-cli.zip` | `fvlt.exe` + `FORMAT.md`. Scriptable lock/unlock/inspect/verify. | Automation / power users. |

**All four produce the same behavior after first run** — each self-registers the
`Lock with FolderVault` menu and the `.fvlt` association the first time it runs
(installer via its postinstall step; portable/self-contained on first launch or
double-click; the MSIX additionally hoists the entry to the Win11 top level).

## Prerequisites for building

- Rust (stable, `x86_64-pc-windows-msvc`) + MSVC C++ toolset — see the top-level
  README. `makeappx.exe` + `signtool.exe` come with the Windows 10/11 SDK.
- Inno Setup for `installer.exe`: `winget install JRSoftware.InnoSetup`
  (build script auto-detects it in `%LOCALAPPDATA%\Programs` or Program Files).
  Without it the other three artifacts still build.

## Signing status

No production certificate yet (project has no external users). `-Sign` with no
`-CertPath` generates a throwaway `CN=FolderVault Dev` cert so the MSIX is
locally installable (install the cert into *Trusted People* first). Unsigned
builds will trip SmartScreen — expected until a real cert is purchased.

## Cutting a GitHub release

```powershell
pwsh installer\build-release.ps1
# bump version in Cargo.toml first if needed
git tag v<ver> ; git push origin v<ver>
gh release create v<ver> dist\* --title "FolderVault <ver>" --notes-file docs/RELEASE-NOTES.md
```
