//! 外の世界のうち、聞けばその場で答えられるもの。今は時計だけ。テストでは好きな時刻を返すものを差し込む

use std::time::SystemTime;

pub trait Env {
    /// 今の時刻（UTC）。ピアに合わせてずらさない
    fn now(&self) -> SystemTime;
}

/// OS の時計を使う [`Env`]
pub struct SystemEnv;

impl Env for SystemEnv {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
