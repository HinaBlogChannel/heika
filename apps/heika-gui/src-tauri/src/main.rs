// リリースの Windows では、コンソールの窓を出さない
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    heika_gui_lib::run();
}
