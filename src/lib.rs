use {
    eyre::Result,
    std::{fmt, hash::Hash},
    tower_lsp::lsp_types,
};

pub mod lsp;
pub mod parse;
pub mod query;
pub mod zeek;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct File {
    /// URI of the file.
    uri: lsp_types::Url,

    /// Source of the file.
    source: String,
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File").finish()
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
