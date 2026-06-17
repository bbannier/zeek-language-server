pub mod ast;
pub mod complete;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod rst;
pub mod zeek;

type InternedStr = ustr::Ustr;
type Str = smol_str::SmolStr;
