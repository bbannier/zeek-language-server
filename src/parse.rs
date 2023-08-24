use crate::{query::Node, File, Files};
use std::{ops::Deref, sync::Arc};
use tower_lsp::lsp_types::Url;
use tracing::instrument;
use tree_sitter::Parser;
use tree_sitter_zeek::language_zeek;

#[derive(Clone, Debug)]
pub struct Tree(tree_sitter::Tree);

impl Tree {
    #[must_use]
    pub fn root_node(&self) -> Node {
        self.0.root_node().into()
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
    let mut parser = Parser::new();
    parser
        .set_language(language_zeek())
        .expect("cannot set parser language");

    let source = db.files().get(&file).map(|f| f.source())?;
    parser.parse(source.as_str(), None).map(Tree).map(Arc::new)
}

#[cfg(test)]
mod test {
    use tower_lsp::lsp_types::Url;

    use crate::Files;

    use {
        crate::{lsp::Database, parse::Parse, File, FileDatabase},
        insta::assert_debug_snapshot,
        std::sync::Arc,
    };

    const SOURCE: &str = "event zeek_init() {}";

    #[test]
    fn can_parse() {
        let mut db = Database::default();
        let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());

        let mut files = db.files();
        let files = Arc::make_mut(&mut files);
        let mut file = FileDatabase::default();
        file.set_source(Arc::new(SOURCE.to_string()));
        files.insert(uri.clone(), Arc::new(file));
        db.set_files(Arc::new(files.clone()));

        let tree = db.parse(uri);
        let sexp = tree.map(|t| t.root_node().to_sexp());
        assert_debug_snapshot!(sexp);
    }
}
