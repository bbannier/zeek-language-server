use log::error;
use tower_lsp::lsp_types::{Range, Url};
use tree_sitter::Node;

use crate::{parse::tree_sitter_zeek, to_range};

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum DeclKind {
    Global,
    Option,
    Const,
    Redef,
    RedefEnum,
    RedefRecord,
    Type,
    Func,
    Hook,
    Event,
}

#[derive(Debug)]
pub struct Decl {
    pub id: String,
    pub kind: DeclKind,
    pub is_export: bool,
    pub range: Range,
    pub selection_range: Range,
}

#[derive(Debug)]
pub struct Module<'a> {
    pub id: Option<&'a str>,
    pub decls: Vec<Decl>,
}

#[must_use]
pub fn default_module_name(uri: &Url) -> Option<&str> {
    uri
        // Assume that text documents refer to file paths.
        .path_segments()
        // The last path component would be the file name.
        .and_then(Iterator::last)
        // Assume that implicit module names only exist for files name like `mod.zeek`, and
        // e.g., multiple `.` are not allowed.
        .and_then(|s| s.split('.').next())
    // If we still cannot extract a name at least provide _something_.
}

fn in_export(mut node: Node) -> bool {
    loop {
        node = match node.parent() {
            Some(p) => p,
            None => return false,
        };

        if node.kind() == "export" {
            return true;
        }
    }
}

fn module_id<'a>(node: Node, source: &'a str) -> Vec<&'a str> {
    let query = tree_sitter::Query::new(unsafe { tree_sitter_zeek() }, "(module (id)*@module_id)")
        .expect("could not construct module query");

    let c_module_id = query
        .capture_index_for_name("module_id")
        .expect("module_id should be captured");

    tree_sitter::QueryCursor::new()
        .matches(&query, node, source.as_bytes())
        .filter_map(|c| {
            c.nodes_for_capture_index(c_module_id)
                .next()
                .and_then(|n| n.utf8_text(source.as_bytes()).ok())
        })
        .collect()
}

#[must_use]
pub fn module<'a>(node: Node, source: &'a str) -> Module<'a> {
    let id = module_id(node, source).get(0).copied();
    let decls = decls(node, source);

    Module { id, decls }
}

#[must_use]
pub fn decls(node: Node, source: &str) -> Vec<Decl> {
    let query = match tree_sitter::Query::new(unsafe { tree_sitter_zeek() }, "(_ (_ (id)@id)@decl)")
    {
        Ok(q) => q,
        Err(e) => {
            error!("could not construct query: {}", e);
            return Vec::new();
        }
    };

    let c_id = query
        .capture_index_for_name("id")
        .expect("id should be captured");

    let c_decl = query
        .capture_index_for_name("decl")
        .expect("decl should be captured");

    tree_sitter::QueryCursor::new()
        .matches(&query, node, source.as_bytes())
        .filter_map(|c| {
            let decl = c
                .nodes_for_capture_index(c_decl)
                .next()
                .expect("decl should be present");

            let kind = match decl.kind() {
                "const_decl" => DeclKind::Const,
                "global_decl" => DeclKind::Global,
                "redef_enum_decl" => DeclKind::RedefEnum,
                "redef_record_decl" => DeclKind::RedefRecord,
                "option_decl" => DeclKind::Option,
                "type_decl" => DeclKind::Type,
                "event_decl" => DeclKind::Event,
                "func_decl" => DeclKind::Func,
                _ => {
                    return None;
                }
            };

            let id = c.nodes_for_capture_index(c_id).next()?;

            let range = to_range(decl.range()).ok()?;
            let selection_range = to_range(id.range()).ok()?;

            let id = id.utf8_text(source.as_bytes()).ok()?.into();

            Some(Decl {
                id,
                kind,
                is_export: in_export(decl),
                range,
                selection_range,
            })
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::{decls, module, module_id};
    use crate::{parse::parse_, query::in_export};
    use insta::assert_debug_snapshot;

    const SOURCE: &str = "module test;

              export {
                  const x = 1 &redef;
                  global y = 1;
              }

              type Y: record {
                  y: vector of count &optional;
              };

              event zeek_init() { 1; }";

    #[test]
    fn test_module() {
        let tree = parse_(SOURCE, None).expect("cannot parse");

        assert_debug_snapshot!(module(tree.root_node(), SOURCE));
    }

    #[test]
    fn test_decls() {
        let tree = parse_(SOURCE, None).expect("cannot parse");

        let decls = decls(tree.root_node(), SOURCE);

        assert_eq!(4, decls.len());
        assert_debug_snapshot!(decls);
    }

    #[test]
    fn test_in_export() {
        let tree = parse_(SOURCE, None).expect("cannot parse");
        assert!(!in_export(tree.root_node()));

        let const_node = tree
            .root_node()
            .named_child(1)
            .and_then(|c| c.named_child(0))
            .unwrap();
        assert_eq!(const_node.kind(), "const_decl");
        assert!(in_export(const_node));

        let zeek_init_node = tree
            .root_node()
            .named_child(tree.root_node().named_child_count() - 1)
            .unwrap();
        assert_eq!(zeek_init_node.kind(), "event_decl");
        assert!(!in_export(zeek_init_node));
    }

    #[test]
    fn test_module_id() {
        let module_id = |source| module_id(parse_(source, None).unwrap().root_node(), source);

        assert!(module_id("").is_empty());
        assert!(module_id("event zeek_init() {}").is_empty());
        assert!(module_id("export {}").is_empty());
        assert_eq!(module_id("module test;"), vec!["test"]);

        // Multiple occurrences of `module` currently disallowed by grammar.
        // assert_eq!(
        //     module_name("module test1; module test2;"),
        //     vec!["test1", "test2"]
        // );
    }
}
