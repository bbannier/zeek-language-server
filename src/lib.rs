use std::{path::PathBuf, sync::Arc};
use tower_lsp_server::ls_types::{ClientCapabilities, Uri};
use tracing::instrument;

pub mod ast;
pub mod complete;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod rst;
pub mod zeek;

#[salsa::input]
pub struct SourceInput {
    #[returns(clone)]
    pub text: Str,
}

#[salsa::input]
pub struct FileList {
    #[returns(clone)]
    pub files: Arc<[Arc<Uri>]>,
}

#[salsa::input]
pub struct ClientState {
    #[returns(clone)]
    pub capabilities: Arc<ClientCapabilities>,
    #[returns(clone)]
    pub initialization_options: Arc<lsp::InitializationOptions>,
}

#[salsa::input]
pub struct WorkspaceState {
    #[returns(clone)]
    pub workspace_folders: Arc<[Uri]>,
    #[returns(clone)]
    pub prefixes: Arc<[PathBuf]>,
}

#[salsa::interned(unsafe(no_lifetime), unsafe(non_salsa_values), revisions = usize::MAX)]
pub struct InternedUri {
    #[returns(clone)]
    pub uri: Arc<Uri>,
}

/// Convenience method: intern or look up an [`Arc<Uri>`] in the database.
pub fn uri_db(db: &dyn Db, uri: Arc<Uri>) -> InternedUri {
    InternedUri::new(db, uri)
}

#[salsa::db]
pub trait Db: salsa::Database {
    fn source_input(&self, uri: &Arc<Uri>) -> Option<SourceInput>;
    fn file_list(&self) -> FileList;
    fn client_state(&self) -> ClientState;
    fn workspace_state(&self) -> WorkspaceState;
}

#[salsa::tracked(returns(clone))]
#[instrument(skip_all)]
pub fn source(db: &dyn Db, uri: InternedUri) -> Option<Str> {
    db.source_input(&uri.uri(db)).map(|s| s.text(db))
}

type InternedStr = ustr::Ustr;
type Str = smol_str::SmolStr;
