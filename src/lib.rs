use std::{collections::BTreeMap, fmt::Debug, sync::Arc};
use tower_lsp::lsp_types::{ClientCapabilities, Url};

pub mod ast;
pub mod complete;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod zeek;

#[salsa::query_group(FileStorage)]
pub trait File: salsa::Database {
    #[salsa::input]
    fn source(&self) -> Arc<String>;
}

#[derive(Default)]
#[salsa::database(FileStorage)]
pub struct FileDatabase {
    storage: salsa::Storage<Self>,
}
impl salsa::Database for FileDatabase {}

impl salsa::ParallelDatabase for FileDatabase {
    fn snapshot(&self) -> salsa::Snapshot<Self> {
        todo!()
    }
}

impl Debug for FileDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileDatabase").finish()
    }
}

unsafe impl Sync for FileDatabase {}

#[allow(clippy::trait_duplication_in_bounds)]
#[salsa::query_group(FilesStorage)]
pub trait Files: salsa::Database {
    #[salsa::input]
    fn files(&self) -> Arc<BTreeMap<Arc<Url>, Arc<FileDatabase>>>;
}

#[allow(clippy::trait_duplication_in_bounds)]
#[salsa::query_group(ClientStorage)]
pub trait Client: salsa::Database {
    #[salsa::input]
    fn capabilities(&self) -> Arc<ClientCapabilities>;

    #[salsa::input]
    fn client_options(&self) -> Arc<lsp::Options>;
}
