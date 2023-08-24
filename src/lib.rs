use std::{collections::BTreeSet, sync::Arc};
use tower_lsp::lsp_types::{ClientCapabilities, Url};

pub mod ast;
pub mod complete;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod zeek;

#[allow(clippy::trait_duplication_in_bounds)]
#[salsa::query_group(FilesStorage)]
pub trait Files: salsa::Database {
    #[salsa::input]
    fn source(&self, uri: Arc<Url>) -> Arc<String>;

    #[salsa::input]
    fn files(&self) -> Arc<BTreeSet<Arc<Url>>>;
}

#[allow(clippy::trait_duplication_in_bounds)]
#[salsa::query_group(ClientStorage)]
pub trait Client: salsa::Database {
    #[salsa::input]
    fn capabilities(&self) -> Arc<ClientCapabilities>;

    #[salsa::input]
    fn client_options(&self) -> Arc<lsp::Options>;
}
