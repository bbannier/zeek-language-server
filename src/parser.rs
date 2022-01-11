use tree_sitter::{Language, Parser, Tree};

extern "C" {
    fn tree_sitter_zeek() -> Language;
}

pub fn parse(source: impl AsRef<[u8]>, old_tree: Option<&Tree>) -> Option<Tree> {
    let language = unsafe { tree_sitter_zeek() };
    let mut parser = Parser::new();
    parser.set_language(language).ok();

    parser.parse(source, old_tree)
}

#[cfg(test)]
mod test {
    use {
        super::parse,
        eyre::{eyre, Result},
        insta::assert_debug_snapshot,
    };

    #[test]
    fn can_parse() -> Result<()> {
        let source = "event zeek_init() {}";
        let tree = parse(&source, None).ok_or_else(|| eyre!("parser returned no tree"))?;
        assert_debug_snapshot!(&tree.root_node().to_sexp());
        Ok(())
    }
}
