use std::sync::Arc;
use tower_lsp::lsp_types::Url;

pub mod ast;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod zeek;

#[salsa::query_group(FilesStorage)]
pub trait Files: salsa::Database {
    #[salsa::input]
    fn source(&self, uri: Arc<Url>) -> Arc<String>;
}
