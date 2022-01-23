use eyre::Result;
use std::sync::Arc;
use tower_lsp::lsp_types::{self, Url};

pub mod lsp;
pub mod parse;
pub mod query;
pub mod zeek;

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

#[salsa::query_group(FilesStorage)]
pub trait Files: salsa::Database {
    #[salsa::input]
    fn source(&self, uri: Arc<Url>) -> Arc<String>;
}
