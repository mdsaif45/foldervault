//! Win32 UI: borderless dark rounded window hosting the lock / unlock / setup
//! dialogs. No frameworks — GDI drawing + two EDIT controls + owner-draw
//! buttons, DWM rounded corners and Mica when available.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWA_SYSTEMBACKDROP_TYPE, DWMWA_USE_IMMERSIVE_DARK_MODE,
    DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DWM_SYSTEMBACKDROP_TYPE,
};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreatePen, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint,
    FillRect, GetMonitorInfoW, InvalidateRect, MonitorFromPoint, RoundRect, SelectObject,
    SetBkColor, SetBkMode, SetTextColor, HBRUSH, HDC, HFONT, MONITORINFO,
    MONITOR_DEFAULTTONEAREST, PAINTSTRUCT, PS_SOLID, TRANSPARENT,
    DT_END_ELLIPSIS, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, FW_NORMAL, FW_SEMIBOLD,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::DRAWITEMSTRUCT;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_UPDATEDIR, SHCNF_PATHW};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
    GetCursorPos, GetMessageW, GetWindowLongPtrW, GetWindowTextW, IsDialogMessageW, KillTimer,
    LoadCursorW, PostMessageW, PostQuitMessage, RegisterClassExW, SendMessageW, SetTimer,
    SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow, TranslateMessage, BS_OWNERDRAW,
    CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, ES_AUTOHSCROLL, ES_MULTILINE, ES_PASSWORD,
    ES_READONLY, GWLP_USERDATA, HMENU, HWND_TOP, IDC_ARROW, MSG, SWP_NOSIZE,
    SWP_NOZORDER, SW_HIDE, SW_SHOW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_COMMAND, WM_CREATE,
    WM_CTLCOLOREDIT, WM_DESTROY, WM_DRAWITEM, WM_LBUTTONDOWN, WM_NCHITTEST, WM_PAINT,
    WM_SETFONT, WM_TIMER, WNDCLASSEXW, WS_CHILD, WS_POPUP, WS_TABSTOP, WS_VISIBLE,
};

use vault_core::format::{lock_folder, unlock_container, Credential, LockOptions};
use vault_core::journal::Journal;
use vault_core::lockout::MAX_ATTEMPTS;
use vault_core::VaultError;

use crate::shell::{data_dir, wide};

// ---------- theme ----------

const fn rgb(r: u32, g: u32, b: u32) -> COLORREF {
    COLORREF(r | (g << 8) | (b << 16))
}
const BG: COLORREF = rgb(0x1E, 0x1E, 0x24);
const FIELD: COLORREF = rgb(0x16, 0x16, 0x1C);
const BORDER: COLORREF = rgb(0x3A, 0x3A, 0x44);
const TEXT: COLORREF = rgb(0xEC, 0xEC, 0xF0);
const MUTED: COLORREF = rgb(0x8B, 0x8B, 0x96);
const ACCENT: COLORREF = rgb(0xE1, 0xB9, 0x4A);
const ON_ACCENT: COLORREF = rgb(0x2B, 0x24, 0x10);
const DANGER: COLORREF = rgb(0xE2, 0x4B, 0x4A);
const WARN: COLORREF = rgb(0xD8, 0x9A, 0x3E);
const OK_GREEN: COLORREF = rgb(0x6F, 0xC4, 0x7E);

const ID_EDIT: isize = 100;
const ID_EDIT2: isize = 101;
const ID_PRIMARY: isize = 1; // IDOK so Enter triggers it via WM_GETDEFID
const ID_CLOSE: isize = 2; // IDCANCEL so Esc closes
const ID_LINK: isize = 102;

const WM_APP_PROGRESS: u32 = WM_APP + 1;
const WM_APP_DONE: u32 = WM_APP + 2;
const WM_GETDEFID: u32 = 0x0400; // DM_GETDEFID
const EM_SETCUEBANNER: u32 = 0x1501;
const TIMER_SHAKE: usize = 1;
const TIMER_COUNTDOWN: usize = 2;

// ---------- dialog model ----------

pub enum Mode {
    /// Password + confirm -> encrypt folder.
    Lock { src: PathBuf },
    /// Password (or recovery code) -> decrypt container.
    Unlock { container: PathBuf },
    /// Show the one-time recovery code.
    Setup { code: String },
}

enum Phase {
    Input,
    Busy,
    LockedOut { until_unix: u64 },
}

struct App {
    mode: Mode,
    phase: Phase,
    hwnd: HWND,
    edit: HWND,
    edit2: HWND, // confirm (lock) — hidden otherwise
    dpi: f32,
    title: String,
    subtitle: String,
    status: String,
    status_color: COLORREF,
    fail_count: u32,
    master_mode: bool, // unlock: entering recovery code instead of password
    master_available: bool,
    progress_pct: u32,
    shake_step: i32,
    origin: (i32, i32),
    result: Arc<Mutex<Option<Result<PathBuf, VaultError>>>>,
    hmac_key: [u8; 32],
    master_pub: Option<[u8; 32]>,
    fonts: Fonts,
    field_brush: HBRUSH,
    succeeded: bool,
}

struct Fonts {
    title: HFONT,
    body: HFONT,
    small: HFONT,
    code: HFONT,
    glyph: HFONT,
}

fn s(app: &App, v: i32) -> i32 {
    (v as f32 * app.dpi) as i32
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------- public entry ----------

/// Runs one dialog to completion. Returns true when the operation succeeded.
pub fn run_dialog(mode: Mode, hmac_key: [u8; 32], master_pub: Option<[u8; 32]>) -> bool {
    unsafe {
        let instance = GetModuleHandleW(None).unwrap_or_default();
        let class = w!("FolderVaultDlg");
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: CreateSolidBrush(BG),
            lpszClassName: class,
            ..Default::default()
        };
        RegisterClassExW(&wc); // idempotent per-process

        let (title, subtitle) = match &mode {
            Mode::Lock { src } => (
                src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                "Lock this folder".to_string(),
            ),
            Mode::Unlock { container } => (
                container
                    .file_stem()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                "Locked folder".to_string(),
            ),
            Mode::Setup { .. } => (
                "FolderVault".to_string(),
                "Save your recovery code".to_string(),
            ),
        };

        let app = Box::new(App {
            title,
            subtitle,
            phase: Phase::Input,
            hwnd: HWND::default(),
            edit: HWND::default(),
            edit2: HWND::default(),
            dpi: 1.0,
            status: String::new(),
            status_color: MUTED,
            fail_count: 0,
            master_mode: false,
            master_available: master_pub.is_some() || matches!(mode, Mode::Unlock { .. }),
            progress_pct: 0,
            shake_step: 0,
            origin: (0, 0),
            result: Arc::new(Mutex::new(None)),
            hmac_key,
            master_pub,
            fonts: Fonts {
                title: HFONT::default(),
                body: HFONT::default(),
                small: HFONT::default(),
                code: HFONT::default(),
                glyph: HFONT::default(),
            },
            field_brush: HBRUSH::default(),
            succeeded: false,
            mode,
        });
        let app_ptr = Box::into_raw(app);

        let (w_du, h_du) = match &(*app_ptr).mode {
            Mode::Lock { .. } => (384, 248),
            Mode::Unlock { .. } => (384, 214),
            Mode::Setup { .. } => (440, 264),
        };
        // position near the cursor's monitor center
        let mut pt = Default::default();
        let _ = GetCursorPos(&mut pt);
        let mon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
        let mut mi = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        let _ = GetMonitorInfoW(mon, &mut mi);
        let mw = mi.rcWork.right - mi.rcWork.left;
        let mh = mi.rcWork.bottom - mi.rcWork.top;

        let hwnd = match CreateWindowExW(
            WINDOW_EX_STYLE(0x00000008 | 0x08000000), // TOPMOST off; actually: plain
            class,
            w!("FolderVault"),
            WS_POPUP,
            mi.rcWork.left + (mw - w_du) / 2,
            mi.rcWork.top + (mh - h_du) / 2,
            w_du,
            h_du,
            None,
            None,
            instance,
            Some(app_ptr as *const _),
        ) {
            Ok(h) => h,
            Err(_) => {
                drop(Box::from_raw(app_ptr));
                return false;
            }
        };

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetFocus((*app_ptr).edit);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).into() {
            if IsDialogMessageW(hwnd, &msg).as_bool() {
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let succeeded = (*app_ptr).succeeded;
        drop(Box::from_raw(app_ptr));
        succeeded
    }
}

// ---------- window proc ----------

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_CREATE {
        let cs = &*(lparam.0 as *const CREATESTRUCTW);
        let app = cs.lpCreateParams as *mut App;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, app as isize);
        (*app).hwnd = hwnd;
        on_create(&mut *app);
        return LRESULT(0);
    }
    let app = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App;
    if app.is_null() {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    let app = &mut *app;
    match msg {
        WM_PAINT => {
            on_paint(app);
            LRESULT(0)
        }
        WM_CTLCOLOREDIT => {
            let hdc = HDC(wparam.0 as *mut _);
            SetTextColor(hdc, TEXT);
            SetBkColor(hdc, FIELD);
            if app.field_brush.is_invalid() {
                app.field_brush = CreateSolidBrush(FIELD);
            }
            LRESULT(app.field_brush.0 as isize)
        }
        WM_DRAWITEM => {
            on_drawitem(app, &*(lparam.0 as *const DRAWITEMSTRUCT));
            LRESULT(1)
        }
        WM_GETDEFID => LRESULT(((0x534B_u32 as isize) << 16) | ID_PRIMARY), // DC_HASDEFID<<16|id
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as isize;
            match id {
                ID_PRIMARY => on_primary(app),
                ID_CLOSE => {
                    let _ = DestroyWindow(hwnd);
                }
                ID_LINK => on_toggle_master(app),
                _ => {}
            }
            LRESULT(0)
        }
        WM_NCHITTEST => {
            // whole background drags the window (client area minus controls)
            let hit = DefWindowProcW(hwnd, msg, wparam, lparam);
            if hit.0 == 1 {
                return LRESULT(2); // HTCLIENT -> HTCAPTION
            }
            hit
        }
        WM_LBUTTONDOWN => LRESULT(0),
        WM_TIMER => {
            on_timer(app, wparam.0);
            LRESULT(0)
        }
        WM_APP_PROGRESS => {
            app.progress_pct = wparam.0 as u32;
            let _ = InvalidateRect(hwnd, None, true);
            LRESULT(0)
        }
        WM_APP_DONE => {
            on_done(app);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

// ---------- creation & layout ----------

unsafe fn on_create(app: &mut App) {
    let hwnd = app.hwnd;
    app.dpi = GetDpiForWindow(hwnd) as f32 / 96.0;

    // dark titlebar-less rounded window with Mica when the OS supports it
    let dark: i32 = 1;
    let _ = DwmSetWindowAttribute(
        hwnd,
        DWMWA_USE_IMMERSIVE_DARK_MODE,
        &dark as *const _ as *const _,
        4,
    );
    let corner = DWMWCP_ROUND;
    let _ = DwmSetWindowAttribute(
        hwnd,
        DWMWA_WINDOW_CORNER_PREFERENCE,
        &corner as *const _ as *const _,
        4,
    );
    let backdrop = DWM_SYSTEMBACKDROP_TYPE(2); // DWMSBT_MAINWINDOW (Mica)
    let _ = DwmSetWindowAttribute(
        hwnd,
        DWMWA_SYSTEMBACKDROP_TYPE,
        &backdrop as *const _ as *const _,
        4,
    );

    let mk_font = |pt: i32, weight: i32, face: PCWSTR| -> HFONT {
        CreateFontW(
            -((pt as f32 * app.dpi * 96.0 / 72.0) as i32),
            0, 0, 0,
            weight,
            0, 0, 0,
            1, // DEFAULT_CHARSET
            0, // OUT_DEFAULT_PRECIS
            0, // CLIP_DEFAULT_PRECIS
            5, // CLEARTYPE_QUALITY
            0, // DEFAULT_PITCH | FF_DONTCARE
            face,
        )
    };
    app.fonts.title = mk_font(13, FW_SEMIBOLD.0 as i32, w!("Segoe UI"));
    app.fonts.body = mk_font(10, FW_NORMAL.0 as i32, w!("Segoe UI"));
    app.fonts.small = mk_font(9, FW_NORMAL.0 as i32, w!("Segoe UI"));
    app.fonts.code = mk_font(11, FW_NORMAL.0 as i32, w!("Consolas"));
    app.fonts.glyph = mk_font(14, FW_NORMAL.0 as i32, w!("Segoe MDL2 Assets"));

    let instance = GetModuleHandleW(None).unwrap_or_default();
    let mut rc = RECT::default();
    let _ = GetClientRect(hwnd, &mut rc);
    let cw = rc.right;
    let dpi = app.dpi;
    let sc = move |v: i32| (v as f32 * dpi) as i32;

    let mk_edit = move |y: i32, h: i32, style: u32, id: isize| -> HWND {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("EDIT"),
            PCWSTR::null(),
            WINDOW_STYLE(style) | WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            sc(24) + sc(12),
            y + (h - sc(20)) / 2,
            cw - sc(48) - sc(24),
            sc(20),
            hwnd,
            HMENU(id as *mut _),
            instance,
            None,
        )
        .unwrap_or_default()
    };
    let mk_button = move |x: i32, y: i32, w_: i32, h: i32, id: isize| -> HWND {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("BUTTON"),
            PCWSTR::null(),
            WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            x, y, w_, h,
            hwnd,
            HMENU(id as *mut _),
            instance,
            None,
        )
        .unwrap_or_default()
    };

    match &app.mode {
        Mode::Lock { .. } => {
            app.edit = mk_edit(sc(74), sc(34), (ES_PASSWORD | ES_AUTOHSCROLL) as u32, ID_EDIT);
            app.edit2 = mk_edit(sc(116), sc(34), (ES_PASSWORD | ES_AUTOHSCROLL) as u32, ID_EDIT2);
            set_cue(app.edit, "Password");
            set_cue(app.edit2, "Confirm password");
            mk_button(cw - sc(24 + 96), sc(248 - 24 - 34), sc(96), sc(34), ID_PRIMARY);
        }
        Mode::Unlock { .. } => {
            app.edit = mk_edit(sc(74), sc(34), (ES_PASSWORD | ES_AUTOHSCROLL) as u32, ID_EDIT);
            set_cue(app.edit, "Password");
            mk_button(cw - sc(24 + 96), sc(214 - 24 - 34), sc(96), sc(34), ID_PRIMARY);
            // "Use recovery code" link
            mk_button(sc(24), sc(214 - 24 - 30), sc(150), sc(26), ID_LINK);
            // read container stats for the subtitle + lockout state
            if let Mode::Unlock { container } = &app.mode {
                if let Ok(h) = vault_core::format::inspect(container, &app.hmac_key) {
                    let mb = h.payload_len as f64 / (1024.0 * 1024.0);
                    app.subtitle = format!("Locked folder · {mb:.1} MB");
                    app.fail_count = if h.hmac_ok { h.lockout.fail_count } else { MAX_ATTEMPTS - 1 };
                    app.master_available = vault_core::recovery::is_enrolled(&h.wrapped_dk_mk);
                    let now = now_unix();
                    if h.lockout.locked_until > now {
                        enter_lockout(app, h.lockout.locked_until);
                    } else if app.fail_count > 0 {
                        let left = MAX_ATTEMPTS - app.fail_count;
                        app.status = format!("{left} attempt{} remaining",
                            if left == 1 { "" } else { "s" });
                        app.status_color = WARN;
                    }
                }
            }
        }
        Mode::Setup { code } => {
            let code_w = code.clone();
            app.edit = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("EDIT"),
                PCWSTR(wide(&code_w).as_ptr()),
                WINDOW_STYLE((ES_MULTILINE | ES_READONLY) as u32) | WS_CHILD | WS_VISIBLE,
                sc(24) + sc(12),
                sc(84),
                sc(440 - 48 - 24),
                sc(56),
                hwnd,
                HMENU(ID_EDIT as *mut _),
                instance,
                None,
            )
            .unwrap_or_default();
            SendMessageW(app.edit, WM_SETFONT, WPARAM(app.fonts.code.0 as usize), LPARAM(1));
            mk_button(cw - sc(24 + 130), sc(264 - 24 - 34), sc(130), sc(34), ID_PRIMARY);
            mk_button(sc(24), sc(264 - 24 - 34), sc(90), sc(34), ID_LINK); // Copy
            app.status = "Anyone with this code can unlock your folders. Store it safely — \
                          it is shown only once.".into();
            app.status_color = MUTED;
        }
    }
    for e in [app.edit, app.edit2] {
        if !e.is_invalid() {
            SendMessageW(e, WM_SETFONT, WPARAM(app.fonts.body.0 as usize), LPARAM(1));
        }
    }
    // close ✕
    mk_button(cw - sc(40), sc(14), sc(26), sc(26), ID_CLOSE);
}

fn set_cue(edit: HWND, text: &str) {
    let t = wide(text);
    unsafe {
        SendMessageW(edit, EM_SETCUEBANNER, WPARAM(1), LPARAM(t.as_ptr() as isize));
    }
}

// ---------- painting ----------

unsafe fn draw_text(hdc: HDC, font: HFONT, color: COLORREF, rc: &mut RECT, text: &str, fmt: u32) {
    if text.is_empty() {
        return;
    }
    let old = SelectObject(hdc, font);
    SetTextColor(hdc, color);
    let mut t: Vec<u16> = text.encode_utf16().collect();
    DrawTextW(hdc, &mut t, rc, windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT(fmt));
    SelectObject(hdc, old);
}

unsafe fn on_paint(app: &mut App) {
    let mut ps = PAINTSTRUCT::default();
    let hdc = BeginPaint(app.hwnd, &mut ps);
    SetBkMode(hdc, TRANSPARENT);
    let mut rc = RECT::default();
    let _ = GetClientRect(app.hwnd, &mut rc);
    let cw = rc.right;
    let ch = rc.bottom;

    // header: padlock glyph + title + subtitle
    let mut r = RECT { left: s(app, 24), top: s(app, 20), right: s(app, 52), bottom: s(app, 52) };
    draw_text(hdc, app.fonts.glyph, ACCENT, &mut r, "\u{E72E}", DT_SINGLELINE.0 | DT_VCENTER.0 | DT_NOPREFIX.0);
    let mut r = RECT { left: s(app, 58), top: s(app, 16), right: cw - s(app, 48), bottom: s(app, 38) };
    draw_text(hdc, app.fonts.title, TEXT, &mut r, &app.title, DT_SINGLELINE.0 | DT_END_ELLIPSIS.0 | DT_NOPREFIX.0);
    let mut r = RECT { left: s(app, 58), top: s(app, 38), right: cw - s(app, 48), bottom: s(app, 56) };
    draw_text(hdc, app.fonts.small, MUTED, &mut r, &app.subtitle, DT_SINGLELINE.0 | DT_NOPREFIX.0);

    match app.phase {
        Phase::Busy => {
            // progress track + fill
            let y = ch / 2 + s(app, 8);
            let track = RECT { left: s(app, 24), top: y, right: cw - s(app, 24), bottom: y + s(app, 6) };
            let b = CreateSolidBrush(FIELD);
            FillRect(hdc, &track, b);
            let _ = DeleteObject(b);
            let w_full = track.right - track.left;
            let fill = RECT {
                left: track.left,
                top: track.top,
                right: track.left + (w_full * app.progress_pct.min(100) as i32) / 100,
                bottom: track.bottom,
            };
            let b = CreateSolidBrush(ACCENT);
            FillRect(hdc, &fill, b);
            let _ = DeleteObject(b);
            let mut r = RECT { left: s(app, 24), top: y + s(app, 12), right: cw - s(app, 24), bottom: y + s(app, 32) };
            let verb = match app.mode {
                Mode::Lock { .. } => "Encrypting",
                _ => "Decrypting",
            };
            draw_text(hdc, app.fonts.small, MUTED, &mut r,
                &format!("{verb}… {}%", app.progress_pct), DT_SINGLELINE.0 | DT_NOPREFIX.0);
        }
        _ => {
            // field borders behind the edit controls
            for (edit, y, h) in [(app.edit, 74, 34), (app.edit2, 116, 34)] {
                if edit.is_invalid() || matches!(app.mode, Mode::Setup { .. }) {
                    continue;
                }
                if !is_visible(edit) {
                    continue;
                }
                draw_field_border(app, hdc, s(app, 24), s(app, y), cw - s(app, 48), s(app, h));
            }
            if let Mode::Setup { .. } = app.mode {
                draw_field_border(app, hdc, s(app, 24), s(app, 76), cw - s(app, 48), s(app, 72));
            }
            // attempt dots (unlock only)
            if let Mode::Unlock { .. } = app.mode {
                let dots_y = s(app, 120);
                for i in 0..MAX_ATTEMPTS as i32 {
                    let x = s(app, 26) + i * s(app, 14);
                    let color = if (i as u32) < app.fail_count { DANGER } else { BORDER };
                    let b = CreateSolidBrush(color);
                    let pen = CreatePen(PS_SOLID, 1, color);
                    let ob = SelectObject(hdc, b);
                    let op = SelectObject(hdc, pen);
                    let d = s(app, 7);
                    let _ = windows::Win32::Graphics::Gdi::Ellipse(hdc, x, dots_y, x + d, dots_y + d);
                    SelectObject(hdc, ob);
                    SelectObject(hdc, op);
                    let _ = DeleteObject(b);
                    let _ = DeleteObject(pen);
                }
                let mut r = RECT { left: s(app, 26 + 3 * 14 + 6), top: dots_y - s(app, 4), right: cw - s(app, 24), bottom: dots_y + s(app, 14) };
                draw_text(hdc, app.fonts.small, app.status_color, &mut r, &app.status, DT_SINGLELINE.0 | DT_NOPREFIX.0);
            } else {
                // status line (lock/setup)
                let top = match app.mode {
                    Mode::Lock { .. } => s(app, 158),
                    _ => s(app, 156),
                };
                let mut r = RECT { left: s(app, 24), top, right: cw - s(app, 24), bottom: top + s(app, 46) };
                draw_text(hdc, app.fonts.small, app.status_color, &mut r, &app.status,
                    DT_NOPREFIX.0 | windows::Win32::Graphics::Gdi::DT_WORDBREAK.0);
            }
        }
    }
    let _ = EndPaint(app.hwnd, &ps);
}

unsafe fn draw_field_border(app: &App, hdc: HDC, x: i32, y: i32, w_: i32, h: i32) {
    let pen = CreatePen(PS_SOLID, 1, BORDER);
    let brush = CreateSolidBrush(FIELD);
    let op = SelectObject(hdc, pen);
    let ob = SelectObject(hdc, brush);
    let r = s(app, 8);
    let _ = RoundRect(hdc, x, y, x + w_, y + h, r, r);
    SelectObject(hdc, op);
    SelectObject(hdc, ob);
    let _ = DeleteObject(pen);
    let _ = DeleteObject(brush);
}

unsafe fn is_visible(hwnd: HWND) -> bool {
    windows::Win32::UI::WindowsAndMessaging::IsWindowVisible(hwnd).as_bool()
}

unsafe fn on_drawitem(app: &mut App, dis: &DRAWITEMSTRUCT) {
    let hdc = dis.hDC;
    SetBkMode(hdc, TRANSPARENT);
    let mut rc = dis.rcItem;
    let id = dis.CtlID as isize;
    let pressed = dis.itemState.0 & 0x0001 != 0; // ODS_SELECTED
    match id {
        ID_PRIMARY => {
            let bg = if pressed { rgb(0xC9, 0xA2, 0x38) } else { ACCENT };
            let pen = CreatePen(PS_SOLID, 1, bg);
            let brush = CreateSolidBrush(bg);
            let op = SelectObject(hdc, pen);
            let ob = SelectObject(hdc, brush);
            let r = s(app, 8);
            let _ = RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, r, r);
            SelectObject(hdc, op);
            SelectObject(hdc, ob);
            let _ = DeleteObject(pen);
            let _ = DeleteObject(brush);
            let label = match app.mode {
                Mode::Lock { .. } => "Lock",
                Mode::Unlock { .. } => "Unlock",
                Mode::Setup { .. } => "I saved it",
            };
            draw_text(hdc, app.fonts.body, ON_ACCENT, &mut rc, label,
                DT_SINGLELINE.0 | DT_VCENTER.0 | 0x0001 /*DT_CENTER*/ | DT_NOPREFIX.0);
        }
        ID_CLOSE => {
            let color = if pressed { TEXT } else { MUTED };
            draw_text(hdc, app.fonts.body, color, &mut rc, "\u{2715}",
                DT_SINGLELINE.0 | DT_VCENTER.0 | 0x0001 | DT_NOPREFIX.0);
        }
        ID_LINK => {
            let label = match app.mode {
                Mode::Setup { .. } => "Copy",
                _ if app.master_mode => "Use password",
                _ => "Use recovery code",
            };
            let color = if pressed { TEXT } else { MUTED };
            if let Mode::Setup { .. } = app.mode {
                draw_field_border(app, hdc, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top);
            }
            draw_text(hdc, app.fonts.small, color, &mut rc, label,
                DT_SINGLELINE.0 | DT_VCENTER.0 | 0x0001 | DT_NOPREFIX.0);
        }
        _ => {}
    }
}

// ---------- actions ----------

unsafe fn get_text(edit: HWND) -> String {
    let mut buf = [0u16; 512];
    let n = GetWindowTextW(edit, &mut buf);
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

unsafe fn on_toggle_master(app: &mut App) {
    match app.mode {
        Mode::Setup { ref code } => {
            // Copy button
            copy_to_clipboard(app.hwnd, code);
            app.status = "Copied. Paste it somewhere safe now.".into();
            app.status_color = OK_GREEN;
            let _ = InvalidateRect(app.hwnd, None, true);
        }
        Mode::Unlock { .. } => {
            if !app.master_available && !app.master_mode {
                app.status = "No recovery code was set up for this folder".into();
                app.status_color = WARN;
                let _ = InvalidateRect(app.hwnd, None, true);
                return;
            }
            app.master_mode = !app.master_mode;
            let style = GetWindowLongPtrW(app.edit, windows::Win32::UI::WindowsAndMessaging::GWL_STYLE);
            let pw_bit = ES_PASSWORD as isize;
            let new_style = if app.master_mode { style & !pw_bit } else { style | pw_bit };
            SetWindowLongPtrW(app.edit, windows::Win32::UI::WindowsAndMessaging::GWL_STYLE, new_style);
            SendMessageW(app.edit, 0x00CC /*EM_SETPASSWORDCHAR*/,
                WPARAM(if app.master_mode { 0 } else { 0x25CF }), LPARAM(0));
            set_cue(app.edit, if app.master_mode { "XXXX-XXXX-XXXX-…" } else { "Password" });
            let _ = SetWindowTextW(app.edit, w!(""));
            let _ = SetFocus(app.edit);
            let _ = InvalidateRect(app.hwnd, None, true);
        }
        _ => {}
    }
}

unsafe fn on_primary(app: &mut App) {
    if !matches!(app.phase, Phase::Input) {
        return;
    }
    match &app.mode {
        Mode::Setup { .. } => {
            app.succeeded = true;
            let _ = DestroyWindow(app.hwnd);
        }
        Mode::Lock { src } => {
            let pw = get_text(app.edit);
            let confirm = get_text(app.edit2);
            if pw.is_empty() {
                set_status(app, "Enter a password", WARN);
                return;
            }
            if pw.len() < 6 {
                set_status(app, "Use at least 6 characters", WARN);
                return;
            }
            if pw != confirm {
                set_status(app, "Passwords do not match", DANGER);
                shake(app);
                return;
            }
            let src = src.clone();
            start_busy(app);
            spawn_worker(app, move |hmac_key, master_pub, progress| {
                let opts = LockOptions { master_pub, ..Default::default() };
                let journal = Journal::open(&data_dir().join("journal")).ok();
                lock_folder(&src, pw.as_bytes(), &hmac_key, &opts, journal.as_ref(), progress)
            });
        }
        Mode::Unlock { container } => {
            let secret = get_text(app.edit);
            if secret.is_empty() {
                set_status(app, if app.master_mode { "Enter your recovery code" } else { "Enter the password" }, WARN);
                return;
            }
            let container = container.clone();
            let master = app.master_mode;
            start_busy(app);
            spawn_worker(app, move |hmac_key, _mp, progress| {
                let journal = Journal::open(&data_dir().join("journal")).ok();
                let cred = if master {
                    Credential::MasterCode(&secret)
                } else {
                    Credential::Password(secret.as_bytes())
                };
                unlock_container(&container, cred, &hmac_key, now_unix(), journal.as_ref(), progress)
            });
        }
    }
}

unsafe fn set_status(app: &mut App, text: &str, color: COLORREF) {
    app.status = text.into();
    app.status_color = color;
    let _ = InvalidateRect(app.hwnd, None, true);
}

unsafe fn start_busy(app: &mut App) {
    app.phase = Phase::Busy;
    app.progress_pct = 0;
    for e in [app.edit, app.edit2] {
        if !e.is_invalid() {
            let _ = ShowWindow(e, SW_HIDE);
        }
    }
    let _ = InvalidateRect(app.hwnd, None, true);
}

fn spawn_worker<F>(app: &mut App, job: F)
where
    F: FnOnce(
            [u8; 32],
            Option<[u8; 32]>,
            &mut dyn FnMut(u64, u64),
        ) -> Result<PathBuf, VaultError>
        + Send
        + 'static,
{
    let hwnd_raw = app.hwnd.0 as isize;
    let hmac_key = app.hmac_key;
    let master_pub = app.master_pub;
    let slot = app.result.clone();
    std::thread::spawn(move || {
        let hwnd = HWND(hwnd_raw as *mut _);
        let mut last = 0u64;
        let mut progress = |done: u64, total: u64| {
            if total == 0 {
                return;
            }
            let pct = done * 100 / total;
            if pct != last {
                last = pct;
                unsafe {
                    let _ = PostMessageW(hwnd, WM_APP_PROGRESS, WPARAM(pct as usize), LPARAM(0));
                }
            }
        };
        let result = job(hmac_key, master_pub, &mut progress);
        *slot.lock().unwrap() = Some(result);
        unsafe {
            let _ = PostMessageW(hwnd, WM_APP_DONE, WPARAM(0), LPARAM(0));
        }
    });
}

unsafe fn on_done(app: &mut App) {
    let result = app.result.lock().unwrap().take();
    let Some(result) = result else { return };
    match result {
        Ok(path) => {
            app.succeeded = true;
            // poke Explorer so the icon/folder appears immediately
            if let Some(parent) = path.parent() {
                let pw = wide(&parent.to_string_lossy());
                SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW, Some(pw.as_ptr() as *const _), None);
            }
            let _ = DestroyWindow(app.hwnd);
        }
        Err(e) => {
            app.phase = Phase::Input;
            for e2 in [app.edit, app.edit2] {
                if !e2.is_invalid() {
                    let _ = ShowWindow(e2, SW_SHOW);
                }
            }
            let _ = SetWindowTextW(app.edit, w!(""));
            if !app.edit2.is_invalid() {
                let _ = SetWindowTextW(app.edit2, w!(""));
            }
            let _ = SetFocus(app.edit);
            match e {
                VaultError::WrongPassword { attempts_left } => {
                    app.fail_count = MAX_ATTEMPTS - attempts_left;
                    set_status(app, &format!("Wrong password — {attempts_left} attempt{} remaining",
                        if attempts_left == 1 { "" } else { "s" }), DANGER);
                    shake(app);
                }
                VaultError::LockedOut { until_unix } => {
                    enter_lockout(app, until_unix);
                    shake(app);
                }
                VaultError::Exists(p) => {
                    set_status(app, &format!("Already exists: {}", p.display()), WARN);
                }
                VaultError::Tampered => {
                    set_status(app, "This file is corrupt or has been tampered with", DANGER);
                }
                VaultError::Other(msg) => set_status(app, &msg, DANGER),
                other => set_status(app, &format!("{other}"), DANGER),
            }
        }
    }
}

unsafe fn enter_lockout(app: &mut App, until_unix: u64) {
    app.phase = Phase::LockedOut { until_unix };
    app.fail_count = MAX_ATTEMPTS;
    if !app.master_mode {
        let _ = EnableWindow(app.edit, false);
    }
    SetTimer(app.hwnd, TIMER_COUNTDOWN, 1000, None);
    update_countdown(app);
}

unsafe fn update_countdown(app: &mut App) {
    let Phase::LockedOut { until_unix } = app.phase else { return };
    let now = now_unix();
    if now >= until_unix {
        app.phase = Phase::Input;
        app.fail_count = 0;
        let _ = KillTimer(app.hwnd, TIMER_COUNTDOWN);
        let _ = EnableWindow(app.edit, true);
        set_status(app, "You can try again now", MUTED);
        return;
    }
    let left = until_unix - now;
    let (h, m, sec) = (left / 3600, (left % 3600) / 60, left % 60);
    app.status = format!("Locked — try again in {h:02}:{m:02}:{sec:02}");
    app.status_color = DANGER;
    let _ = InvalidateRect(app.hwnd, None, true);
}

unsafe fn shake(app: &mut App) {
    let mut rc = RECT::default();
    let _ = windows::Win32::UI::WindowsAndMessaging::GetWindowRect(app.hwnd, &mut rc);
    app.origin = (rc.left, rc.top);
    app.shake_step = 8;
    SetTimer(app.hwnd, TIMER_SHAKE, 20, None);
}

unsafe fn on_timer(app: &mut App, id: usize) {
    match id {
        TIMER_SHAKE => {
            if app.shake_step <= 0 {
                let _ = KillTimer(app.hwnd, TIMER_SHAKE);
                let _ = SetWindowPos(app.hwnd, HWND_TOP, app.origin.0, app.origin.1, 0, 0,
                    SWP_NOSIZE | SWP_NOZORDER);
                return;
            }
            let dx = if app.shake_step % 2 == 0 { 6 } else { -6 };
            let _ = SetWindowPos(app.hwnd, HWND_TOP, app.origin.0 + dx, app.origin.1, 0, 0,
                SWP_NOSIZE | SWP_NOZORDER);
            app.shake_step -= 1;
        }
        TIMER_COUNTDOWN => update_countdown(app),
        _ => {}
    }
}

unsafe fn copy_to_clipboard(hwnd: HWND, text: &str) {
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    let data = wide(text);
    if OpenClipboard(hwnd).is_ok() {
        let _ = EmptyClipboard();
        if let Ok(h) = GlobalAlloc(GMEM_MOVEABLE, data.len() * 2) {
            let ptr = GlobalLock(h);
            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u16, data.len());
                let _ = GlobalUnlock(h);
                let _ = SetClipboardData(13 /*CF_UNICODETEXT*/,
                    windows::Win32::Foundation::HANDLE(h.0));
            }
        }
        let _ = CloseClipboard();
    }
}
