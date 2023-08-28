use std::{collections::BTreeSet, sync::Arc};
use tower_lsp::lsp_types::{ClientCapabilities, Url};
use tracing::instrument;

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
    fn unsafe_source(&self, uri: Arc<Url>) -> Arc<String>;

    #[salsa::input]
    fn files(&self) -> Arc<BTreeSet<Arc<Url>>>;

    /// Gets the source code for a file if it is known.
    fn source(&self, uri: Arc<Url>) -> Option<Arc<String>>;
}

#[instrument(skip(db))]
pub fn source(db: &dyn Files, uri: Arc<Url>) -> Option<Arc<String>> {
    // Check if we know the file. This reduces chances of us trying to get sources for a not
    // yet added uri.
    //
    // TODO(bbannier): Ideally this would really be modelled in a more compact way, e.g., by us
    // getting sources from the files database.
    if !db.files().contains(&uri) {
        return None;
    }

    Some(db.unsafe_source(uri))
}

#[allow(clippy::trait_duplication_in_bounds)]
#[salsa::query_group(ClientStorage)]
pub trait Client: salsa::Database {
    #[salsa::input]
    fn capabilities(&self) -> Arc<ClientCapabilities>;

    #[salsa::input]
    fn client_options(&self) -> Arc<lsp::Options>;
}
