use {
    std::{hash::Hash, ops::Deref, sync::Arc},
    tower_lsp::lsp_types::VersionedTextDocumentIdentifier,
};

pub mod lsp;
pub mod parse;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ID(Arc<VersionedTextDocumentIdentifier>);

impl From<VersionedTextDocumentIdentifier> for ID {
    fn from(id: VersionedTextDocumentIdentifier) -> Self {
        Self(Arc::new(id))
    }
}

impl Deref for ID {
    type Target = Arc<VersionedTextDocumentIdentifier>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for ID {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.uri.hash(state);
        self.0.version.hash(state);
    }
}
