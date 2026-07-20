# Assets

Two ICOs are embedded into `FolderVault.exe` as resources by `build.rs`
(via the `winres` crate). Both are generated procedurally with GDI+ by
`installer/make-icons.ps1` — re-run it to regenerate after tweaking colors.

- **`app.ico`** (resource id 1) — standalone gold padlock. Used by the
  taskbar, the "Lock with FolderVault" context-menu entry, and the dialog
  window. Referenced from the registry as `"<exe>",-1`.
- **`locked-folder.ico`** (resource id 2) — Win11-style yellow folder with a
  dark padlock in the lower-right. This is what every locked `.fvlt` file
  shows in Explorer. Referenced from the registry as `"<exe>",-2`.

Each ICO holds 16/20/24/32/48/64/256 px frames (256 as PNG-compressed) so the
icon stays crisp from Details view up to extra-large icons.
