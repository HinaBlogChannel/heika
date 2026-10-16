//! Linux で、クリップボードに持ち主がいないときに貼り付けると落ちるのを避ける。
//!
//! WebKitGTK 2.54.0 は、クリップボードに持ち主がいない（何もコピーしていないか、コピーしたアプリが閉じた）ときに
//! 貼り付けると、貼り付けの処理の中で落ちる。中身が空の文字列でも、持ち主がいれば落ちない。
//! なので、持ち主がいなくなったら、heika が空の文字列で持ち主になる。ほかのアプリがコピーすれば、そちらが持ち主に戻る。

use gtk::gdk;
use gtk::prelude::*;

/// 起動したときと、クリップボードの持ち主が変わるたびに確かめる。GTK のスレッドで呼ぶ
pub fn keep_owned() {
    for selection in [gdk::SELECTION_CLIPBOARD, gdk::SELECTION_PRIMARY] {
        let clipboard = gtk::Clipboard::get(&selection);
        claim_if_ownerless(&clipboard);
        // gtk-rs には owner-change の型つきの接続がないので、名前でつなぐ
        clipboard.connect_local("owner-change", false, |values| {
            if let Ok(clipboard) = values[0].get::<gtk::Clipboard>() {
                claim_if_ownerless(&clipboard);
            }
            None
        });
    }
}

fn claim_if_ownerless(clipboard: &gtk::Clipboard) {
    // 持ち主がいなければ、どの形で渡せるかの一覧（TARGETS）が空で返ってくる
    clipboard.request_contents(&gdk::Atom::intern("TARGETS"), |clipboard, data| {
        if data.targets().is_none_or(|targets| targets.is_empty()) {
            clipboard.set_text("");
        }
    });
}
