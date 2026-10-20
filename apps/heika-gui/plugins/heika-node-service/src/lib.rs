//! heika-gui のノードを、Android で裏でも動かし続けるためのフォアグラウンドサービス。
//!
//! ノードそのものはアプリのプロセスの中のスレッド（Rust）で動く。このプラグインは、そのあいだプロセスが
//! 止められないように、フォアグラウンドサービス（種類は specialUse）を始めて、通知に様子を出すだけ。
//! Android 15 から、dataSync の種類は1日に6時間までしか動けないので使わない。
//!
//! Android のほかでは何もしない。

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager, Runtime};

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("heika-node-service")
        .setup(|app, _api| {
            #[cfg(target_os = "android")]
            let handle = _api.register_android_plugin(
                "io.github.hinablogchannel.heika.node",
                "NodeServicePlugin",
            )?;
            #[cfg(not(target_os = "android"))]
            let handle = std::marker::PhantomData;
            app.manage(NodeService::<R>(handle));
            Ok(())
        })
        .build()
}

/// 通知に出す文
#[cfg(target_os = "android")]
#[derive(serde::Serialize)]
struct Notice<'a> {
    text: &'a str,
}

/// サービスを始めて、通知を変えて、止める
#[cfg(target_os = "android")]
pub struct NodeService<R: Runtime>(tauri::plugin::PluginHandle<R>);
#[cfg(not(target_os = "android"))]
pub struct NodeService<R: Runtime>(std::marker::PhantomData<fn() -> R>);

impl<R: Runtime> NodeService<R> {
    /// サービスを始める（通知を出す許可も、まだなら聞く）。始めていれば、通知を `text` にする
    pub fn start(&self, text: &str) -> Result<(), String> {
        self.run("start", text)
    }

    /// 通知を `text` にする
    pub fn update(&self, text: &str) -> Result<(), String> {
        self.run("update", text)
    }

    /// サービスを止めて、通知を消す
    pub fn stop(&self) -> Result<(), String> {
        self.run("stop", "")
    }

    #[cfg(target_os = "android")]
    fn run(&self, command: &str, text: &str) -> Result<(), String> {
        self.0
            .run_mobile_plugin::<serde_json::Value>(command, Notice { text })
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    #[cfg(not(target_os = "android"))]
    fn run(&self, _command: &str, _text: &str) -> Result<(), String> {
        Ok(())
    }
}

/// [`NodeService`] を、アプリから引けるようにする
pub trait NodeServiceExt<R: Runtime> {
    fn node_service(&self) -> &NodeService<R>;
}

impl<R: Runtime, T: Manager<R>> NodeServiceExt<R> for T {
    fn node_service(&self) -> &NodeService<R> {
        self.state::<NodeService<R>>().inner()
    }
}
