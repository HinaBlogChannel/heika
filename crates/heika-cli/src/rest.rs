//! REST に問い合わせる。heika-rest の、取ってくる関数を受け取る非同期の関数を、このスレッドで動かす。

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

/// REST の1回の問い合わせを待つ時間
const TIMEOUT: Duration = Duration::from_secs(10);
/// 根が合わなかったときに、取り直すまでにおく間。REST の DB がノードに追いつくのを待つ
pub const RETRY_PAUSE: Duration = Duration::from_secs(3);

/// 問い合わせる REST
pub struct Rest {
    origin: String,
    agent: ureq::Agent,
}

impl Rest {
    /// `url`（例: https://symbol.example:3001）の REST。HTTPS では、OS のルート証明書で相手を確かめる
    pub fn new(url: &str) -> Self {
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .root_certs(RootCerts::PlatformVerifier)
            .build();
        Self {
            origin: url.trim_end_matches('/').to_owned(),
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(TIMEOUT))
                .tls_config(tls)
                .build()
                .into(),
        }
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// `path` を取る。404 なら None
    pub fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        match self
            .agent
            .get(&format!("{}{path}", self.origin))
            .call()
            .and_then(|mut response| response.body_mut().read_to_vec())
        {
            Ok(body) => Ok(Some(body)),
            Err(ureq::Error::StatusCode(404)) => Ok(None),
            Err(error) => Err(format!("REST の {path} を取れませんでした: {error}")),
        }
    }

    /// `path` に JSON の `body` を PUT する
    pub fn put(&self, path: &str, body: &str) -> Result<(), String> {
        self.agent
            .put(&format!("{}{path}", self.origin))
            .header("Content-Type", "application/json")
            .send(body)
            .map(drop)
            .map_err(|error| format!("REST の {path} に送れませんでした: {error}"))
    }
}

/// future を、このスレッドで終わるまで動かす。待たされたら、起こされるまで眠る
pub fn block_on<T>(future: impl Future<Output = T>) -> T {
    struct Unpark(Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::park(),
        }
    }
}
