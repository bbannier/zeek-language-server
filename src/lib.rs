use std::sync::Arc;
use tower_lsp_server::ls_types::{ClientCapabilities, Uri};

pub mod ast;
pub mod complete;
pub mod lsp;
pub mod parse;
pub mod query;
pub mod rst;
pub mod zeek;

type InternedStr = ustr::Ustr;
type Str = smol_str::SmolStr;

pub(crate) trait Db {
    fn source(&self, uri: Arc<Uri>) -> Option<Str>;
    fn files(&self) -> Arc<[Arc<Uri>]>;
    fn prefixes(&self) -> Arc<[std::path::PathBuf]>;
    fn capabilities(&self) -> Arc<ClientCapabilities>;
    fn initialization_options(&self) -> Arc<lsp::InitializationOptions>;

    fn parse(&self, file: Arc<Uri>) -> Option<Arc<parse::Tree>>;
    fn decls(&self, uri: Arc<Uri>) -> Arc<[query::Decl]>;
    fn loads(&self, uri: Arc<Uri>) -> Arc<[InternedStr]>;
    fn function_calls(&self, uri: Arc<Uri>) -> Arc<[query::FunctionCall]>;
    fn untyped_var_decls(&self, uri: Arc<Uri>) -> Arc<[query::Decl]>;
    fn ids(&self, uri: Arc<Uri>) -> Arc<[query::NodeLocation]>;
    fn loaded_files(&self, url: Arc<Uri>) -> Arc<[Arc<Uri>]>;
    fn loaded_files_recursive(&self, url: Arc<Uri>) -> Arc<[Arc<Uri>]>;
    fn explicit_decls_recursive(&self, url: Arc<Uri>) -> Arc<[query::Decl]>;
    fn implicit_loads(&self) -> Arc<[Arc<Uri>]>;
    fn implicit_decls(&self) -> Arc<[query::Decl]>;
    fn possible_loads(&self, uri: Arc<Uri>) -> Arc<[InternedStr]>;
    fn resolve(&self, node: query::NodeLocation) -> Option<Arc<query::Decl>>;
    fn typ(&self, decl: Arc<query::Decl>) -> Option<Arc<query::Decl>>;
    fn resolve_id(&self, id: InternedStr, scope: query::NodeLocation) -> Option<Arc<query::Decl>>;
    fn resolve_type(
        &self,
        typ: query::Type,
        scope: Option<query::NodeLocation>,
    ) -> Option<Arc<query::Decl>>;
}
