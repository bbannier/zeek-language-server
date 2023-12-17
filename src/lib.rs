#![deny(clippy::unwrap_used)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::ignored_unit_patterns)] // Creates a lot of false positives.

use rustc_hash::FxHashSet;
use std::sync::Arc;
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
    fn unsafe_source(&self, uri: Arc<Url>) -> Str;

    #[salsa::input]
    fn files(&self) -> Arc<FxHashSet<Arc<Url>>>;

    /// Gets the source code for a file if it is known.
    fn source(&self, uri: Arc<Url>) -> Option<Str>;
}

#[instrument(skip(db))]
pub fn source(db: &dyn Files, uri: Arc<Url>) -> Option<Str> {
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

type Str = Arc<str>;
