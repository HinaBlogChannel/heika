// Worker の読み込み。trunk の data-loader-shim は古い呼び方で初期化して警告が出るので、自分で書く
importScripts("./worker.js");
wasm_bindgen({ module_or_path: "./worker_bg.wasm" });
