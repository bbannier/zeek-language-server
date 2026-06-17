pub mod ast;
pub mod complete;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod rst;
pub mod zeek;

type InternedStr = ustr::Ustr;
type Str = smol_str::SmolStr;

use std::path::PathBuf;
use std::sync::Arc;
use tower_lsp_server::ls_types::Uri;

#[salsa::input]
#[derive(Debug)]
pub(crate) struct SourceFile {
    pub(crate) uri: Arc<Uri>,
    pub(crate) text: Str,
}

#[salsa::input(singleton)]
pub(crate) struct ConfigRevision {
    pub(crate) revision: u64,
}

#[salsa::db]
pub(crate) trait Db: salsa::Database {
    fn source_file(&self, uri: &Arc<Uri>) -> Option<SourceFile>;
    fn files(&self) -> Arc<[Arc<Uri>]>;
    fn prefixes(&self) -> Vec<PathBuf>;
}
