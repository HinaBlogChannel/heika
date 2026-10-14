//! アドレスを探す Web Worker。画面から先頭の文字を受け取ったら、止められるまで探し続ける。
//!
//! WASM を読み終える前に届いたメッセージは受け取れないので、準備ができたら `"ready"` を送り、画面はそれを待ってから先頭の文字を送る。
//!
//! 画面には、区切りごとに試した数（数値）を送り、見つかったら `["found", アドレス, 秘密鍵]`、
//! 失敗したら `["error", 理由]` を送って終わる。

use js_sys::Array;
use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};
use web_vanitygen::search;

/// 試した数を画面に送る間隔。小さすぎると送るほうに時間をとられる
const BATCH: u32 = 500;

fn main() {
    let scope: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let poster = scope.clone();
    let onmessage = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
        let Some(prefix) = event.data().as_string() else {
            return;
        };
        // 止めるときは画面が Worker ごと terminate するので、ここでは抜けない
        loop {
            let message = match search(&prefix, BATCH) {
                Ok(None) => {
                    let _ = poster.post_message(&JsValue::from(BATCH));
                    continue;
                }
                Ok(Some(found)) => Array::of3(
                    &"found".into(),
                    &found.address.into(),
                    &found.private_key.into(),
                ),
                Err(error) => Array::of2(&"error".into(), &error.into()),
            };
            let _ = poster.post_message(&message);
            return;
        }
    });
    scope.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();
    let _ = scope.post_message(&"ready".into());
}
