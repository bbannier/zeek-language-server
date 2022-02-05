use eyre::Result;
use lspower::lsp::{Position, Range, Url};
use std::sync::Arc;

pub mod ast;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod zeek;

fn to_offset(x: usize) -> Result<u32> {
    u32::try_from(x).map_err(Into::into)
}

fn to_position(p: tree_sitter::Point) -> Result<Position> {
    Ok(Position::new(to_offset(p.row)?, to_offset(p.column)?))
}

pub(crate) fn to_range(r: tree_sitter::Range) -> Result<Range> {
    Ok(Range::new(
        to_position(r.start_point)?,
        to_position(r.end_point)?,
    ))
}

#[salsa::query_group(FilesStorage)]
pub trait Files: salsa::Database {
    #[salsa::input]
    fn source(&self, uri: Arc<Url>) -> Arc<String>;
}
