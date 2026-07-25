use crate::{Db, InternedUri, query::Node};
use std::sync::Arc;
use tracing::instrument;
use tree_sitter::Parser;
use tree_sitter_zeek::language_zeek;

#[derive(Clone, Debug)]
pub struct Tree(tree_sitter::Tree);

impl Tree {
    #[must_use]
    pub fn root_node(&self) -> Node<'_> {
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

#[salsa::tracked(returns(clone))]
#[instrument(skip_all)]
pub fn parse(db: &dyn Db, file: InternedUri) -> Option<Arc<Tree>> {
    let mut parser = Parser::new();
    parser
        .set_language(&language_zeek())
        .expect("cannot set parser language");

    let source = crate::source(db, file)?;
    parser
        .parse(source.as_bytes(), None)
        .map(Tree)
        .map(Arc::new)
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use {
        crate::lsp::TestDatabase, crate::test_util::assert_debug_snapshot, std::sync::Arc,
        tower_lsp_server::ls_types::Uri,
    };

    const SOURCE: &str = "event zeek_init() {}";

    #[test]
    fn can_parse() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/foo/bar.zeek").unwrap());

        db.add_file((*uri).clone(), SOURCE);

        let uri_db = crate::uri_db(&db.0, uri);
        let tree = crate::parse::parse(&db.0, uri_db);
        let sexp = tree.map(|t| t.root_node().to_sexp());
        assert_debug_snapshot!(sexp);
    }
}
