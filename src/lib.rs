use std::{path::PathBuf, sync::Arc};
use tower_lsp_server::ls_types::{ClientCapabilities, Uri};
use tracing::instrument;

pub mod ast;
pub mod complete;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod rst;
#[cfg(test)]
pub(crate) mod test_util;
pub mod zeek;

#[salsa::input]
pub struct SourceInput {
    #[returns(clone)]
    pub text: Str,
}

#[salsa::input]
pub struct FileList {
    #[returns(clone)]
    pub files: Arc<[InternedUri]>,
}

#[salsa::input]
pub struct ClientState {
    #[returns(clone)]
    pub capabilities: Arc<ClientCapabilities>,
    #[returns(copy)]
    pub initialization_options: lsp::InitializationOptions,
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

impl std::fmt::Debug for InternedUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use salsa::plumbing::AsId as _;
        write!(f, "InternedUri({:?})", self.as_id())
    }
}

impl PartialOrd for InternedUri {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InternedUri {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use salsa::plumbing::AsId as _;
        self.as_id().index().cmp(&other.as_id().index())
    }
}

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
