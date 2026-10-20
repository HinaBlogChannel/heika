//! ネームスペースのエイリアスで、アドレスとモザイクを解決する。

use super::*;

impl Executor {
    /// モザイクの ID を解決する。ネームスペースだったら、ステートメントに残す（catapult の observer の `Resolvers`）。
    /// ネームスペースがないか、モザイクの別名でなければ、そのままの値を使う（catapult の `BuildResolver` は、どの
    /// 解決もできなければ、解決する前の値をそのまま返す。テストネットの高さ 2,672,377）
    pub(super) fn resolve_mosaic(&mut self, id: u64) -> Result<u64, ExecError> {
        if id >> 63 == 0 {
            return Ok(id);
        }
        let resolved = match self.alias_of(id) {
            Ok(Alias::Mosaic(mosaic_id)) => mosaic_id,
            _ => id,
        };
        self.statement.add_mosaic_resolution(id, resolved);
        Ok(resolved)
    }

    /// アドレスを解決する。ネームスペースだったら、ステートメントに残す。解決できなければ、モザイクと同じに
    /// そのままの値を使う
    pub(super) fn resolve_address(
        &mut self,
        address: &UnresolvedAddress,
    ) -> Result<[u8; 24], ExecError> {
        let Some(id) = address.namespace_id() else {
            return Ok(address.0);
        };
        let resolved = match self.alias_of(id.0) {
            Ok(Alias::Address(resolved)) => resolved,
            _ => address.0,
        };
        self.statement.add_address_resolution(address, resolved);
        Ok(resolved)
    }

    pub(super) fn alias_of(&self, namespace_id: u64) -> Result<Alias, ExecError> {
        let path = self
            .namespace_paths
            .get(&namespace_id)
            .ok_or_else(|| invalid(format!("ネームスペース {namespace_id:016X} がありません")))?;
        let root = &self.namespaces[&path[0]];
        Ok(if path.len() == 1 {
            root.alias
        } else {
            root.children[&path[1..]]
        })
    }

    pub(super) fn set_alias(&mut self, namespace_id: u64, alias: Alias) -> Result<(), ExecError> {
        let path = self
            .namespace_paths
            .get(&namespace_id)
            .ok_or_else(|| invalid(format!("ネームスペース {namespace_id:016X} がありません")))?
            .clone();
        self.touch(SubCache::Namespace, &path[0].to_le_bytes());
        let root = self
            .namespaces
            .get_mut(&path[0])
            .expect("path points to a root");
        if path.len() == 1 {
            root.alias = alias;
        } else {
            *root
                .children
                .get_mut(&path[1..])
                .expect("path points to a child") = alias;
        }
        Ok(())
    }
}
