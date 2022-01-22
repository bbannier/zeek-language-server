use {
    crate::File,
    std::{hash::Hash, ops::Deref, sync::Arc},
    tower_lsp::lsp_types::Position,
    tracing::instrument,
    tree_sitter::{Language, Parser, Point},
};

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

impl Hash for Tree {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.root_node().id().hash(state);
    }
}

impl Deref for Tree {
    type Target = tree_sitter::Tree;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[salsa::query_group(ParseStorage)]
pub trait Parse: salsa::Database {
    #[must_use]
    fn parse(&self, file: Arc<File>) -> Option<Arc<Tree>>;
}

#[instrument(skip(_db))]
fn parse(_db: &dyn Parse, file: Arc<File>) -> Option<Arc<Tree>> {
    let language = unsafe { tree_sitter_zeek() };
    let mut parser = Parser::new();
    parser
        .set_language(language)
        .expect("cannot set parser language");

    parser.parse(&file.source, None).map(Tree).map(Arc::new)
}

#[cfg(test)]
mod test {
    use {
        crate::File,
        crate::{lsp::Database, parse::Parse},
        eyre::Result,
        insta::assert_debug_snapshot,
        std::sync::Arc,
    };

    const SOURCE: &'static str = "event zeek_init() {}";

    #[test]
    fn can_parse() -> Result<()> {
        let tree = Database::default().parse(Arc::new(File {
            source: SOURCE.to_owned(),
        }));

        let sexp = tree.map(|t| t.root_node().to_sexp());
        assert_debug_snapshot!(sexp);

        Ok(())
    }
}
