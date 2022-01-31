use crate::Files;
use lspower::lsp::{Position, Url};
use std::{ops::Deref, sync::Arc};
use tracing::instrument;
use tree_sitter::{Language, Parser, Point};

extern "C" {
    pub(crate) fn tree_sitter_zeek() -> Language;
}

#[derive(Clone, Debug)]
pub struct Tree(pub tree_sitter::Tree);

impl Tree {
    #[must_use]
    pub fn named_descendant_for_position(&self, position: &Position) -> Option<tree_sitter::Node> {
        let start = Point::new(position.line as usize, position.character as usize);

        self.0
            .root_node()
            .named_descendant_for_point_range(start, start)
    }

    #[must_use]
    pub fn descendant_for_position(&self, position: &Position) -> Option<tree_sitter::Node> {
        let start = Point::new(position.line as usize, position.character as usize);

        self.0.root_node().descendant_for_point_range(start, start)
    }
}

impl PartialEq for Tree {
    fn eq(&self, other: &Self) -> bool {
        self.0.root_node().id() == other.0.root_node().id()
    }
}

impl Eq for Tree {}

impl Deref for Tree {
    type Target = tree_sitter::Tree;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[salsa::query_group(ParseStorage)]
pub trait Parse: Files {
    #[must_use]
    fn parse(&self, file: Arc<Url>) -> Option<Arc<Tree>>;
}

#[instrument(skip(db))]
fn parse(db: &dyn Parse, file: Arc<Url>) -> Option<Arc<Tree>> {
    let language = unsafe { tree_sitter_zeek() };
    let mut parser = Parser::new();
    parser
        .set_language(language)
        .expect("cannot set parser language");

    let source = db.source(file);
    parser.parse(source.as_str(), None).map(Tree).map(Arc::new)
}

#[cfg(test)]
mod test {
    use lspower::lsp::Url;

    use {
        crate::{lsp::Database, parse::Parse, Files},
        eyre::Result,
        insta::assert_debug_snapshot,
        std::sync::Arc,
    };

    const SOURCE: &'static str = "event zeek_init() {}";

    #[test]
    fn can_parse() -> Result<()> {
        let mut db = Database::default();
        let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());

        db.set_source(uri.clone(), Arc::new(SOURCE.to_string()));

        let tree = db.parse(uri);
        let sexp = tree.map(|t| t.root_node().to_sexp());
        assert_debug_snapshot!(sexp);

        Ok(())
    }
}
