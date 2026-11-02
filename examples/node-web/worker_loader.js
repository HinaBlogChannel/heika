// Worker の読み込み。trunk の data-loader-shim は古い呼び方で初期化して警告が出るので、自分で書く。
// 画面が付けた版の印（?v=…）を引き継いで、キャッシュに残った前の版の Worker を読まないようにする
importScripts("./worker.js" + self.location.search);
wasm_bindgen({ module_or_path: "./worker_bg.wasm" + self.location.search });
