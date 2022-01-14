use {
    crate::ID,
    std::{ops::Deref, sync::Arc},
    tower_lsp::lsp_types::Position,
    tracing::instrument,
    tree_sitter::{Language, Parser, Point},
};

extern "C" {
    fn tree_sitter_zeek() -> Language;
}

fn parse_(source: impl AsRef<[u8]>, old_tree: Option<&Tree>) -> Option<Tree> {
    let language = unsafe { tree_sitter_zeek() };
    let mut parser = Parser::new();
    parser.set_language(language).ok();

    parser.parse(source, old_tree.map(|t| &t.0)).map(Tree)
}

#[derive(Clone, Debug)]
pub struct Tree(pub tree_sitter::Tree);

impl Tree {
    // FIXME(bbannier): do not leak `Node` type here.
    #[must_use]
    pub fn named_descendant_for_position(&self, position: &Position) -> Option<tree_sitter::Node> {
        let start = Point::new(position.line as usize, position.character as usize);

        self.0
            .root_node()
            .named_descendant_for_point_range(start, start)
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
pub trait Parse: salsa::Database {
    #[salsa::input]
    fn source(&self, id: ID) -> Arc<String>;

    #[must_use]
    fn parse(&self, id: ID) -> Arc<Option<Tree>>;
}

#[instrument(skip(db))]
fn parse(db: &dyn Parse, id: ID) -> Arc<Option<Tree>> {
    let source = db.source(id);
    Arc::new(parse_(source.as_str(), None))
}

pub fn query_to<T>(
    node: tree_sitter::Node,
    source: &str,
    query: &str,
    f: impl Fn(&tree_sitter::QueryCapture) -> Option<T>,
) -> Vec<T> {
    let query = match tree_sitter::Query::new(unsafe { tree_sitter_zeek() }, query).ok() {
        Some(q) => q,
        None => return Vec::new(),
    };

    tree_sitter::QueryCursor::new()
        .captures(&query, node, source.as_bytes())
        .flat_map(|(c, _)| c.captures)
        .filter_map(f)
        .collect()
}

#[cfg(test)]
mod test {
    use {
        super::{parse_, Parse, ID},
        crate::lsp::Database,
        eyre::{eyre, Result},
        insta::assert_debug_snapshot,
        std::sync::Arc,
        tower_lsp::lsp_types::{Url, VersionedTextDocumentIdentifier},
    };

    const SOURCE: &'static str = "event zeek_init() {}";

    #[test]
    fn can_parse_() -> Result<()> {
        let tree = parse_(&SOURCE, None).ok_or_else(|| eyre!("parser returned no tree"))?;
        assert_debug_snapshot!(&tree.root_node().to_sexp());

        Ok(())
    }

    #[test]
    fn can_parse() -> Result<()> {
        let uri = Url::from_file_path("/foo/bar.zeek").unwrap();
        let id: ID = VersionedTextDocumentIdentifier::new(uri, 0).into();

        let mut db = Database::default();
        db.set_source(id.clone(), Arc::new(SOURCE.to_owned()));

        let tree = db.parse(id.clone());
        let tree = tree
            .as_ref()
            .as_ref()
            .ok_or_else(|| eyre!("parser returned no tree"))?;
        assert_debug_snapshot!(&tree.root_node().to_sexp());

        Ok(())
    }
}
