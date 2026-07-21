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
    DT_END_ELLIPSIS, DT_LEFT, DT_NOPREFIX, DT_RIGHT, DT_SINGLELINE, DT_VCENTER, FW_NORMAL,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::DRAWITEMSTRUCT;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetActiveWindow, SetFocus};
use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_UPDATEDIR, SHCNF_PATHW};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
    GetCursorPos, GetMessageW, GetWindowLongPtrW, GetWindowTextW, IsDialogMessageW, KillTimer,
    LoadCursorW, PostMessageW, PostQuitMessage, RegisterClassExW, SendMessageW, SetTimer,
    SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow, TranslateMessage, BS_OWNERDRAW,
    CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, ES_AUTOHSCROLL, ES_MULTILINE, ES_PASSWORD,
    ES_READONLY, GWLP_USERDATA, HMENU, HWND_TOP, IDC_ARROW, MSG, SWP_NOSIZE,
    SWP_NOZORDER, SW_HIDE, SW_SHOW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_COMMAND, WM_CREATE,
    SetForegroundWindow,
    WM_CTLCOLOREDIT, WM_DESTROY, WM_DRAWITEM, WM_LBUTTONDOWN, WM_NCHITTEST, WM_PAINT,
    WM_SETFOCUS, WM_SETFONT, WM_TIMER, WNDCLASSEXW, WS_CHILD, WS_CLIPCHILDREN, WS_EX_APPWINDOW,
    WS_EX_CONTROLPARENT, WS_EX_TOPMOST, WS_POPUP, WS_TABSTOP, WS_VISIBLE,
};

use vault_core::format::{
    lock_folder, unlock_container, verify_and_delete, Credential, LockOptions,
};
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
const BADGE_BG: COLORREF = rgb(0x2C, 0x2C, 0x36);
const DANGER: COLORREF = rgb(0xE2, 0x4B, 0x4A);
const WARN: COLORREF = rgb(0xD8, 0x9A, 0x3E);
const OK_GREEN: COLORREF = rgb(0x6F, 0xC4, 0x7E);

const ID_EDIT: isize = 100;
const ID_EDIT2: isize = 101;
const ID_PRIMARY: isize = 1; // IDOK so Enter triggers it via WM_GETDEFID
const ID_CLOSE: isize = 2; // IDCANCEL so Esc closes
const ID_LINK: isize = 102;
const ID_EYE: isize = 103; // reveal-password toggle inside the field

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
    /// Password (or recovery code) -> recycle the container (no extraction).
    Delete { container: PathBuf },
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
    reveal: bool, // password shown in clear (eye toggle)
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
    button: HFONT, // primary-button label (medium weight)
    link: HFONT,   // underlined small for text links
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
            Mode::Delete { container } => (
                container
                    .file_stem()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                "Delete this locked folder".to_string(),
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
            master_available: master_pub.is_some()
                || matches!(mode, Mode::Unlock { .. } | Mode::Delete { .. }),
            progress_pct: 0,
            reveal: false,
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
                button: HFONT::default(),
                link: HFONT::default(),
            },
            field_brush: HBRUSH::default(),
            succeeded: false,
            mode,
        });
        let app_ptr = Box::into_raw(app);

        let (w_du, h_du) = match &(*app_ptr).mode {
            Mode::Lock { .. } => (420, 252),
            Mode::Unlock { .. } | Mode::Delete { .. } => (420, 214),
            Mode::Setup { .. } => (460, 268),
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

        // WS_EX_CONTROLPARENT: lets IsDialogMessageW / Tab recurse into the
        // child EDIT controls. WS_EX_APPWINDOW: show a taskbar button so the
        // window can be foreground-activated. WS_EX_TOPMOST: keep the dialog
        // above other windows (it's a modal prompt).
        let hwnd = match CreateWindowExW(
            WS_EX_CONTROLPARENT | WS_EX_APPWINDOW | WS_EX_TOPMOST,
            class,
            w!("FolderVault"),
            WS_POPUP | WS_VISIBLE | WS_CLIPCHILDREN,
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
        let _ = SetForegroundWindow(hwnd);
        let _ = SetActiveWindow(hwnd);
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
                ID_EYE => on_toggle_reveal(app),
                _ => {}
            }
            LRESULT(0)
        }
        WM_SETFOCUS => {
            // focus the (enabled) input when the window itself gets focus
            if !matches!(app.phase, Phase::Busy) {
                let target = app.edit;
                if !target.is_invalid() {
                    let _ = SetFocus(target);
                }
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

    let dpi_f = app.dpi;
    let mk_font_u = move |pt: i32, weight: i32, underline: u32, face: PCWSTR| -> HFONT {
        CreateFontW(
            -((pt as f32 * dpi_f * 96.0 / 72.0) as i32),
            0, 0, 0,
            weight,
            0,          // italic
            underline,  // underline
            0,          // strikeout
            1, // DEFAULT_CHARSET
            0, // OUT_DEFAULT_PRECIS
            0, // CLIP_DEFAULT_PRECIS
            5, // CLEARTYPE_QUALITY
            0, // DEFAULT_PITCH | FF_DONTCARE
            face,
        )
    };
    let mk_font = |pt: i32, weight: i32, face: PCWSTR| mk_font_u(pt, weight, 0, face);
    // Win11's Segoe UI Variable reads closest to the mockup's Anthropic Sans;
    // CreateFontW falls back to Segoe UI automatically on Win10 where absent.
    let ui_disp = w!("Segoe UI Variable Display");
    let ui_text = w!("Segoe UI Variable Text");
    const FW_MEDIUM: i32 = 500;
    app.fonts.title = mk_font(13, FW_MEDIUM, ui_disp);
    app.fonts.body = mk_font(10, FW_NORMAL.0 as i32, ui_text);
    app.fonts.small = mk_font(9, FW_NORMAL.0 as i32, ui_text);
    app.fonts.code = mk_font(11, FW_NORMAL.0 as i32, w!("Consolas"));
    app.fonts.glyph = mk_font(15, FW_NORMAL.0 as i32, w!("Segoe MDL2 Assets"));
    app.fonts.button = mk_font(10, FW_MEDIUM, ui_text);
    app.fonts.link = mk_font_u(9, FW_NORMAL.0 as i32, 1, ui_text);

    let instance = GetModuleHandleW(None).unwrap_or_default();
    let mut rc = RECT::default();
    let _ = GetClientRect(hwnd, &mut rc);
    let cw = rc.right;
    let dpi = app.dpi;
    let sc = move |v: i32| (v as f32 * dpi) as i32;

    // All fields reserve the same right gutter so their edges (and the rounded
    // borders drawn behind them) line up, whether or not an eye toggle sits in
    // the gutter. Text starts sc(14) in from the field's left edge. The gutter
    // is wide enough that the eye button sits entirely to the RIGHT of the EDIT
    // control (otherwise the focused EDIT paints over the eye's left half).
    let mk_edit = move |y: i32, h: i32, style: u32, id: isize| -> HWND {
        let right_pad = sc(52);
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("EDIT"),
            PCWSTR::null(),
            WINDOW_STYLE(style) | WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            sc(24) + sc(14),
            y + (h - sc(20)) / 2,
            cw - sc(24) - sc(14) - right_pad,
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
            app.edit = mk_edit(sc(78), sc(38), (ES_PASSWORD | ES_AUTOHSCROLL) as u32, ID_EDIT);
            app.edit2 = mk_edit(sc(122), sc(38), (ES_PASSWORD | ES_AUTOHSCROLL) as u32, ID_EDIT2);
            set_cue(app.edit, "Password");
            set_cue(app.edit2, "Confirm password");
            // eye toggle in the gutter, fully right of the EDIT (ends at cw-52)
            mk_button(cw - sc(24) - sc(26), sc(78) + sc(7), sc(24), sc(24), ID_EYE);
            mk_button(cw - sc(24 + 104), sc(252 - 22 - 36), sc(104), sc(36), ID_PRIMARY);
        }
        // Unlock and Delete share the same single-field layout
        Mode::Unlock { .. } | Mode::Delete { .. } => {
            let is_delete = matches!(app.mode, Mode::Delete { .. });
            app.edit = mk_edit(sc(78), sc(38), (ES_PASSWORD | ES_AUTOHSCROLL) as u32, ID_EDIT);
            set_cue(app.edit, "Password");
            // eye toggle in the gutter, fully right of the EDIT
            mk_button(cw - sc(24) - sc(26), sc(78) + sc(7), sc(24), sc(24), ID_EYE);
            mk_button(cw - sc(24 + 104), sc(214 - 22 - 36), sc(104), sc(36), ID_PRIMARY);
            // "Use recovery code" underlined text link (left-aligned, drawn as link)
            mk_button(sc(24), sc(214 - 22 - 32), sc(160), sc(28), ID_LINK);
            // read container stats for the subtitle + lockout state
            let container = match &app.mode {
                Mode::Unlock { container } | Mode::Delete { container } => Some(container.clone()),
                _ => None,
            };
            if let Some(container) = container {
                if let Ok(h) = vault_core::format::inspect(&container, &app.hmac_key) {
                    let mb = h.payload_len as f64 / (1024.0 * 1024.0);
                    let lead = if is_delete { "Delete locked folder" } else { "Locked folder" };
                    app.subtitle = format!("{lead} · {mb:.1} MB");
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
                sc(24) + sc(14),
                sc(86),
                cw - sc(48) - sc(28),
                sc(56),
                hwnd,
                HMENU(ID_EDIT as *mut _),
                instance,
                None,
            )
            .unwrap_or_default();
            SendMessageW(app.edit, WM_SETFONT, WPARAM(app.fonts.code.0 as usize), LPARAM(1));
            mk_button(cw - sc(24 + 120), sc(268 - 22 - 36), sc(120), sc(36), ID_PRIMARY);
            mk_button(sc(24), sc(268 - 22 - 36), sc(92), sc(36), ID_LINK); // Copy
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

    // header: rounded lock badge + padlock glyph + title + subtitle
    let badge = RECT {
        left: s(app, 22),
        top: s(app, 20),
        right: s(app, 22) + s(app, 38),
        bottom: s(app, 20) + s(app, 38),
    };
    let bpen = CreatePen(PS_SOLID, 1, BADGE_BG);
    let bbrush = CreateSolidBrush(BADGE_BG);
    let op = SelectObject(hdc, bpen);
    let ob = SelectObject(hdc, bbrush);
    let br = s(app, 9);
    let _ = RoundRect(hdc, badge.left, badge.top, badge.right, badge.bottom, br, br);
    SelectObject(hdc, op);
    SelectObject(hdc, ob);
    let _ = DeleteObject(bpen);
    let _ = DeleteObject(bbrush);
    let mut r = badge;
    draw_text(hdc, app.fonts.glyph, ACCENT, &mut r, "\u{E72E}",
        DT_SINGLELINE.0 | DT_VCENTER.0 | 0x0001 /*DT_CENTER*/ | DT_NOPREFIX.0);

    let text_left = s(app, 22) + s(app, 38) + s(app, 12);
    let mut r = RECT { left: text_left, top: s(app, 21), right: cw - s(app, 46), bottom: s(app, 42) };
    draw_text(hdc, app.fonts.title, TEXT, &mut r, &app.title, DT_SINGLELINE.0 | DT_END_ELLIPSIS.0 | DT_NOPREFIX.0);
    let mut r = RECT { left: text_left, top: s(app, 43), right: cw - s(app, 46), bottom: s(app, 60) };
    draw_text(hdc, app.fonts.small, MUTED, &mut r, &app.subtitle, DT_SINGLELINE.0 | DT_END_ELLIPSIS.0 | DT_NOPREFIX.0);

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
                Mode::Delete { .. } => "Deleting",
                _ => "Decrypting",
            };
            // delete has no byte progress; show a plain working label
            let label = if matches!(app.mode, Mode::Delete { .. }) {
                format!("{verb}…")
            } else {
                format!("{verb}… {}%", app.progress_pct)
            };
            draw_text(hdc, app.fonts.small, MUTED, &mut r,
                &label, DT_SINGLELINE.0 | DT_NOPREFIX.0);
        }
        _ => {
            // field borders behind the edit controls (fields at y=78, y=122, h=38)
            for (edit, y, h) in [(app.edit, 78, 38), (app.edit2, 122, 38)] {
                if edit.is_invalid() || matches!(app.mode, Mode::Setup { .. }) {
                    continue;
                }
                if !is_visible(edit) {
                    continue;
                }
                draw_field_border(app, hdc, s(app, 24), s(app, y), cw - s(app, 48), s(app, h));
            }
            if let Mode::Setup { .. } = app.mode {
                draw_field_border(app, hdc, s(app, 24), s(app, 80), cw - s(app, 48), s(app, 68));
            }
            // attempt dots + label on ONE row (unlock/delete), below the field
            if matches!(app.mode, Mode::Unlock { .. } | Mode::Delete { .. }) {
                let dots_y = s(app, 126);
                let d = s(app, 7);
                for i in 0..MAX_ATTEMPTS as i32 {
                    let x = s(app, 24) + i * s(app, 13);
                    let color = if (i as u32) < app.fail_count { DANGER } else { BORDER };
                    let b = CreateSolidBrush(color);
                    let pen = CreatePen(PS_SOLID, 1, color);
                    let ob = SelectObject(hdc, b);
                    let op = SelectObject(hdc, pen);
                    let _ = windows::Win32::Graphics::Gdi::Ellipse(hdc, x, dots_y, x + d, dots_y + d);
                    SelectObject(hdc, ob);
                    SelectObject(hdc, op);
                    let _ = DeleteObject(b);
                    let _ = DeleteObject(pen);
                }
                // label right-aligned on the same baseline as the dots
                let mut r = RECT { left: s(app, 100), top: dots_y - s(app, 5), right: cw - s(app, 24), bottom: dots_y + s(app, 14) };
                draw_text(hdc, app.fonts.small, app.status_color, &mut r, &app.status,
                    DT_SINGLELINE.0 | DT_VCENTER.0 | DT_RIGHT.0 | DT_NOPREFIX.0);
            } else {
                // status line (lock/setup)
                let top = match app.mode {
                    Mode::Lock { .. } => s(app, 166),
                    _ => s(app, 156),
                };
                let mut r = RECT { left: s(app, 24), top, right: cw - s(app, 24), bottom: top + s(app, 44) };
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

/// Crisp eye icon rendered like an SVG path: an almond drawn from two Bézier
/// lids + a round pupil, supersampled 4x and StretchBlt-ed down with HALFTONE
/// so the curves are anti-aliased (GDI alone aliases badly at 16px). `open`=
/// false adds the slash (hidden state).
unsafe fn draw_eye(hdc: HDC, rc: &RECT, color: COLORREF, open: bool) {
    use windows::Win32::Graphics::Gdi::{
        CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, GetStockObject, LineTo, MoveToEx,
        PolyBezier, SetStretchBltMode, StretchBlt, HALFTONE, HOLLOW_BRUSH, SRCCOPY,
    };
    use windows::Win32::Foundation::POINT;
    let bw = rc.right - rc.left;
    let bh = rc.bottom - rc.top;
    if bw <= 0 || bh <= 0 {
        return;
    }
    const SS: i32 = 4; // supersample factor
    let (bwx, bhx) = (bw * SS, bh * SS);

    let mem = CreateCompatibleDC(hdc);
    let bmp = CreateCompatibleBitmap(hdc, bwx, bhx);
    let old_bmp = SelectObject(mem, bmp);
    // fill the offscreen with the field colour so downscale blends into it
    let bg = CreateSolidBrush(FIELD);
    let full = RECT { left: 0, top: 0, right: bwx, bottom: bhx };
    FillRect(mem, &full, bg);
    let _ = DeleteObject(bg);

    let cx = bwx / 2;
    let cy = bhx / 2;
    let w = (bw * SS * 36 / 100).max(SS); // half-width ~0.36 of box
    let h = (bh * SS * 22 / 100).max(SS); // half-height ~0.22 of box
    let pen = CreatePen(PS_SOLID, (SS as f32 * 1.3) as i32, color);
    let hollow = HBRUSH(GetStockObject(HOLLOW_BRUSH).0);
    let op = SelectObject(mem, pen);
    let ob = SelectObject(mem, hollow);

    // upper lid: bezier from left corner up-and-over to right corner
    let up = [
        POINT { x: cx - w, y: cy },
        POINT { x: cx - w / 2, y: cy - h * 2 },
        POINT { x: cx + w / 2, y: cy - h * 2 },
        POINT { x: cx + w, y: cy },
    ];
    let _ = PolyBezier(mem, &up);
    // lower lid: mirror
    let dn = [
        POINT { x: cx - w, y: cy },
        POINT { x: cx - w / 2, y: cy + h * 2 },
        POINT { x: cx + w / 2, y: cy + h * 2 },
        POINT { x: cx + w, y: cy },
    ];
    let _ = PolyBezier(mem, &dn);

    // pupil (filled)
    SelectObject(mem, ob);
    let pr = (bh * SS * 11 / 100).max(SS);
    let pbrush = CreateSolidBrush(color);
    let ob2 = SelectObject(mem, pbrush);
    let _ = windows::Win32::Graphics::Gdi::Ellipse(mem, cx - pr, cy - pr, cx + pr, cy + pr);
    SelectObject(mem, ob2);
    let _ = DeleteObject(pbrush);

    if !open {
        let _ = MoveToEx(mem, cx - w, cy + h + SS, None);
        let _ = LineTo(mem, cx + w, cy - h - SS);
    }

    SelectObject(mem, op);
    let _ = DeleteObject(pen);

    // downscale into the target with smoothing
    SetStretchBltMode(hdc, HALFTONE);
    let _ = StretchBlt(hdc, rc.left, rc.top, bw, bh, mem, 0, 0, bwx, bhx, SRCCOPY);

    SelectObject(mem, old_bmp);
    let _ = DeleteObject(bmp);
    let _ = DeleteDC(mem);
}

unsafe fn on_drawitem(app: &mut App, dis: &DRAWITEMSTRUCT) {
    let hdc = dis.hDC;
    SetBkMode(hdc, TRANSPARENT);
    let mut rc = dis.rcItem;
    let id = dis.CtlID as isize;
    let pressed = dis.itemState.0 & 0x0001 != 0; // ODS_SELECTED
    match id {
        ID_PRIMARY => {
            // clear the item to the window bg first so the rounded corners
            // don't leave dark triangles from the default button face
            let clr = CreateSolidBrush(BG);
            FillRect(hdc, &rc, clr);
            let _ = DeleteObject(clr);
            // Delete is a destructive action -> red button + white label;
            // everything else uses the gold accent.
            let is_delete = matches!(app.mode, Mode::Delete { .. });
            let bg = if is_delete {
                if pressed { rgb(0xB0, 0x3A, 0x39) } else { DANGER }
            } else if pressed {
                rgb(0xC9, 0xA2, 0x38)
            } else {
                ACCENT
            };
            let fg = if is_delete { rgb(0xFF, 0xFF, 0xFF) } else { ON_ACCENT };
            let pen = CreatePen(PS_SOLID, 1, bg);
            let brush = CreateSolidBrush(bg);
            let op = SelectObject(hdc, pen);
            let ob = SelectObject(hdc, brush);
            let r = s(app, 10);
            let _ = RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, r, r);
            SelectObject(hdc, op);
            SelectObject(hdc, ob);
            let _ = DeleteObject(pen);
            let _ = DeleteObject(brush);
            let label = match app.mode {
                Mode::Lock { .. } => "Lock",
                Mode::Unlock { .. } => "Unlock",
                Mode::Delete { .. } => "Delete",
                Mode::Setup { .. } => "I saved it",
            };
            draw_text(hdc, app.fonts.button, fg, &mut rc, label,
                DT_SINGLELINE.0 | DT_VCENTER.0 | 0x0001 /*DT_CENTER*/ | DT_NOPREFIX.0);
        }
        ID_CLOSE => {
            let bg = CreateSolidBrush(BG);
            FillRect(hdc, &rc, bg);
            let _ = DeleteObject(bg);
            let color = if pressed { TEXT } else { MUTED };
            draw_text(hdc, app.fonts.body, color, &mut rc, "\u{2715}",
                DT_SINGLELINE.0 | DT_VCENTER.0 | 0x0001 | DT_NOPREFIX.0);
        }
        ID_EYE => {
            // sits inside the field: paint the field colour behind the icon
            let bg = CreateSolidBrush(FIELD);
            FillRect(hdc, &rc, bg);
            let _ = DeleteObject(bg);
            let color = if pressed || app.reveal { ACCENT } else { MUTED };
            draw_eye(hdc, &rc, color, app.reveal);
        }
        ID_LINK => {
            if let Mode::Setup { .. } = app.mode {
                // Setup's "Copy" stays a bordered button
                let label = "Copy";
                let color = if pressed { TEXT } else { MUTED };
                draw_field_border(app, hdc, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top);
                draw_text(hdc, app.fonts.small, color, &mut rc, label,
                    DT_SINGLELINE.0 | DT_VCENTER.0 | 0x0001 | DT_NOPREFIX.0);
            } else {
                // Unlock's link: underlined text, left-aligned, no border.
                // Paint the whole item background with the window color first
                // so no default button face / focus box shows through.
                let bg = CreateSolidBrush(BG);
                FillRect(hdc, &rc, bg);
                let _ = DeleteObject(bg);
                let label = if app.master_mode { "Use password" } else { "Use recovery code" };
                let color = if pressed { ACCENT } else { MUTED };
                draw_text(hdc, app.fonts.link, color, &mut rc, label,
                    DT_SINGLELINE.0 | DT_VCENTER.0 | DT_LEFT.0 | DT_NOPREFIX.0);
            }
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

unsafe fn on_toggle_reveal(app: &mut App) {
    // no-op in master-code mode (the field is already plaintext)
    if app.master_mode {
        return;
    }
    app.reveal = !app.reveal;
    // EM_SETPASSWORDCHAR: 0 = show text, 0x25CF = bullet
    SendMessageW(
        app.edit,
        0x00CC,
        WPARAM(if app.reveal { 0 } else { 0x25CF }),
        LPARAM(0),
    );
    let _ = InvalidateRect(app.edit, None, true);
    let _ = SetFocus(app.edit);
    let _ = InvalidateRect(app.hwnd, None, false); // repaint the eye glyph
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
        Mode::Unlock { .. } | Mode::Delete { .. } => {
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
                let opts = LockOptions {
                    master_pub,
                    // send the original folder to the Recycle Bin (recoverable)
                    // and mark the .fvlt read-only so Explorer confirms deletes
                    recycle_original: true,
                    readonly_container: true,
                    ..Default::default()
                };
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
        Mode::Delete { container } => {
            let secret = get_text(app.edit);
            if secret.is_empty() {
                set_status(app, if app.master_mode { "Enter your recovery code" } else { "Enter the password" }, WARN);
                return;
            }
            let container = container.clone();
            let master = app.master_mode;
            start_busy(app);
            spawn_worker(app, move |hmac_key, _mp, _progress| {
                let cred = if master {
                    Credential::MasterCode(&secret)
                } else {
                    Credential::Password(secret.as_bytes())
                };
                // return the container path on success so on_done refreshes
                // Explorer for its parent, same as unlock.
                verify_and_delete(&container, cred, &hmac_key, now_unix()).map(|()| container.clone())
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
