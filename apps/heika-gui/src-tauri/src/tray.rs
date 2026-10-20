//! 通知領域（トレイ）のアイコン。デスクトップだけ。
//!
//! ノードが動いているあいだは、窓を閉じても隠すだけにして、ここから開き直すか終わる。終わるときは、ノードに
//! 今のブロックを書き終えてもらってから終わる（`RunEvent::Exit`）。Linux で appindicator のライブラリがなければ
//! 置かずに、窓を閉じたら終わる。ライブラリはあっても通知領域を出すものがない（GNOME で拡張がないときなど）と、
//! 置けたことになって見えないので、アプリをもう一度起動すれば窓が出るようにしてある（single-instance）。

use tauri::Manager;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

/// 通知領域にアイコンを置けたか
pub struct Available(pub bool);

pub fn build(app: &tauri::App) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    if !appindicator_loads() {
        return Err("appindicator のライブラリがありません".to_owned());
    }
    build_icon(app).map_err(|error| error.to_string())
}

fn build_icon(app: &tauri::App) -> tauri::Result<()> {
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

/// tray-icon（libappindicator-sys）が読みにいくライブラリのどれかが読めるか。どれも読めないと panic する
#[cfg(target_os = "linux")]
fn appindicator_loads() -> bool {
    [
        "libayatana-appindicator3.so.1",
        "libappindicator3.so.1",
        "libayatana-appindicator3.so",
        "libappindicator3.so",
    ]
    .iter()
    // SAFETY: 読み込むだけで、中の関数は呼ばない。読み込んだものは、tray-icon も同じように読み込む
    .any(|name| unsafe { libloading::Library::new(name) }.is_ok())
}

/// 隠した窓を出して、前に持ってくる
pub fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.webview_windows().values().next() {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}
