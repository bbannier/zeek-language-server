use crate::lsp::Database;
use std::sync::Arc;
use tower_lsp_server::ls_types::Uri;
use tracing::instrument;
use tree_sitter::Parser;
use tree_sitter_zeek::language_zeek;

#[derive(Clone, Debug)]
pub struct Tree(tree_sitter::Tree);

impl Tree {
    #[must_use]
    pub fn root_node(&self) -> crate::query::Node<'_> {
        self.0.root_node().into()
    }
}

impl PartialEq for Tree {
    fn eq(&self, other: &Self) -> bool {
        self.0.root_node().id() == other.0.root_node().id()
    }
}

impl From<tree_sitter::Tree> for Tree {
    fn from(value: tree_sitter::Tree) -> Self {
        Self(value)
    }
}

impl Eq for Tree {}

#[instrument(skip(db))]
pub(crate) fn parse(db: &Database, file: Arc<Uri>) -> Option<Arc<Tree>> {
    let mut parser = Parser::new();
    parser
        .set_language(&language_zeek())
        .expect("cannot set parser language");

    let source = db.source(file)?;
    parser
        .parse(source.as_bytes(), None)
        .map(Tree)
        .map(Arc::new)
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use {
        crate::{lsp::TestDatabase, parse::parse},
        insta::assert_debug_snapshot,
        std::sync::Arc,
        tower_lsp_server::ls_types::Uri,
    };

    const SOURCE: &str = "event zeek_init() {}";

    #[test]
    fn can_parse() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/foo/bar.zeek").unwrap());

        db.add_file((*uri).clone(), SOURCE);

        let tree = parse(&db.0, uri);
        let sexp = tree.map(|t| t.root_node().to_sexp());
        assert_debug_snapshot!(sexp);
    }
}
