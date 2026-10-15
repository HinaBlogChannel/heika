//! ウォレットのための計算。合意形成には関わらない、鍵を作ったり覚えやすくしたり、ノードに鍵を渡したりするもの。

pub mod age;
pub mod bip39;
pub mod cipher;
pub mod harvest_request;
pub mod keystore;
pub mod keystore_file;
pub mod message;
pub mod slip10;

#[cfg(test)]
mod testing {
    /// 決まったバイト列を返すだけの乱数。テストでニーモニックや使い捨ての鍵を固定するのに使う。
    pub struct Replay<'a>(pub &'a [u8]);

    impl rand_core::TryRng for Replay<'_> {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unimplemented!("only fill_bytes is used")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unimplemented!("only fill_bytes is used")
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let (head, rest) = self.0.split_at(dst.len());
            dst.copy_from_slice(head);
            self.0 = rest;
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for Replay<'_> {}
}
