# Assets

`foldervault.ico` (to be created in phase 3) needs two images embedded as exe
icon resources via `winres`:

- **index 0** — app icon (padlock), used by the context-menu entry and taskbar.
- **index 1** — *folder with padlock overlay*, matching the Windows 11 folder
  style (front-facing yellow folder + bottom-right gold padlock). This is what
  every locked `.fvlt` file shows in Explorer.

Sizes required in the .ico: 16, 20, 24, 32, 40, 48, 64, 256 (256 as PNG-compressed).
Draw at 256 and 16/24/32 separately — a downscaled 256 turns to mush at 16 px.
