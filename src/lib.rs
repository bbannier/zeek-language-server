use {
    eyre::Result,
    std::{fmt, hash::Hash, ops::Deref, sync::Arc},
    tower_lsp::lsp_types,
};

pub mod lsp;
pub mod parse;
pub mod query;
pub mod zeek;

#[derive(Clone, PartialEq, Eq)]
pub struct FileId(Arc<lsp_types::VersionedTextDocumentIdentifier>);

impl From<lsp_types::VersionedTextDocumentIdentifier> for FileId {
    fn from(id: lsp_types::VersionedTextDocumentIdentifier) -> Self {
        Self(Arc::new(id))
    }
}

impl fmt::Debug for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileId")
            .field("uri", &format!("{}", &self.0.uri))
            .field("version", &self.0.version)
            .finish()
    }
}

impl Deref for FileId {
    type Target = Arc<lsp_types::VersionedTextDocumentIdentifier>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for FileId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.uri.hash(state);
        self.0.version.hash(state);
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct File {
    id: FileId,
    source: String,
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File").field("id", &self.id).finish()
    }
}

fn to_offset(x: usize) -> Result<u32> {
    u32::try_from(x).map_err(Into::into)
}

fn to_position(p: tree_sitter::Point) -> Result<lsp_types::Position> {
    Ok(lsp_types::Position::new(
        to_offset(p.row)?,
        to_offset(p.column)?,
    ))
}

pub(crate) fn to_range(r: tree_sitter::Range) -> Result<lsp_types::Range> {
    Ok(lsp_types::Range::new(
        to_position(r.start_point)?,
        to_position(r.end_point)?,
    ))
}
