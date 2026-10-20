// リリースの Windows では、コンソールの窓を出さない
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // ノードとして起動し直されたときは、画面を出さずにノードだけ動かす
    if heika_gui_lib::node::run_child_if_asked() {
        return;
    }
    heika_gui_lib::run();
}
