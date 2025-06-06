use std::sync::Arc;
use tower_lsp_server::lsp_types::{ClientCapabilities, Uri};
use tracing::instrument;

pub mod ast;
pub mod complete;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod rst;
pub mod zeek;

#[allow(clippy::trait_duplication_in_bounds)]
#[salsa::query_group(FilesStorage)]
pub trait Files: salsa::Database {
    #[salsa::input]
    fn unsafe_source(&self, uri: Arc<Uri>) -> Str;

    #[salsa::input]
    fn files(&self) -> Arc<[Arc<Uri>]>;

    /// Gets the source code for a file if it is known.
    fn source(&self, uri: Arc<Uri>) -> Option<Str>;
}

#[instrument(skip(db))]
pub fn source(db: &dyn Files, uri: Arc<Uri>) -> Option<Str> {
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
    fn initialization_options(&self) -> Arc<lsp::InitializationOptions>;
}

type Str = smol_str::SmolStr;
