//! 通知領域（トレイ）のアイコン。デスクトップだけ。
//!
//! ノードが動いているあいだは、窓を閉じても隠すだけにして、ここから開き直すか終わる。終わるときは、ノードに
//! 今のブロックを書き終えてもらってから終わる（`RunEvent::Exit`）。通知領域がない環境（GNOME で拡張がない
//! ときなど）では置けないので、窓を閉じたら終わる。

use tauri::Manager;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

/// 通知領域にアイコンを置けたか
pub struct Available(pub bool);

pub fn build(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "開く", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "終了（ノードも止める）", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let mut builder = TrayIconBuilder::new()
        .tooltip("heika")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// 隠した窓を出して、前に持ってくる
fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.webview_windows().values().next() {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}
