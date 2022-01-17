use log::error;
use tower_lsp::lsp_types::{Range, Url};
use tracing::instrument;
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
    Variable,
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
pub struct Module {
    /// ID of this module.
    pub id: Option<String>,

    /// Declarations in this module.
    pub decls: Vec<Decl>,

    /// Other modules explicitly loaded by this module.
    pub loads: Vec<String>,
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

#[instrument]
#[must_use]
pub fn module(node: Node, source: &str) -> Module {
    let id = module_id(node, source).get(0).copied().map(String::from);
    let decls = decls(node, source);
    let loads = loads(node, source).into_iter().map(String::from).collect();

    Module { id, decls, loads }
}

#[instrument]
#[must_use]
pub fn decls(node: Node, source: &str) -> Vec<Decl> {
    let query = match tree_sitter::Query::new(
        unsafe { tree_sitter_zeek() },
        "(_ (_ ([\"global\" \"local\"]?)@scope (id)@id)@decl)@outer_node",
    ) {
        Ok(q) => q,
        Err(e) => {
            error!("could not construct query: {}", e);
            return Vec::new();
        }
    };

    let c_scope = query
        .capture_index_for_name("scope")
        .expect("scope should be captured");

    let c_id = query
        .capture_index_for_name("id")
        .expect("id should be captured");

    let c_decl = query
        .capture_index_for_name("decl")
        .expect("decl should be captured");

    let c_outer_node = query
        .capture_index_for_name("outer_node")
        .expect("outer node should be captured");

    tree_sitter::QueryCursor::new()
        .matches(&query, node, source.as_bytes())
        .filter_map(|c| {
            let decl = c
                .nodes_for_capture_index(c_decl)
                .next()
                .expect("decl should be present");

            // Skip children not directly below the node or in an `export` below the node.
            // TODO(bbannier): this would probably be better handled directly in the query.
            let outer_node = c
                .nodes_for_capture_index(c_outer_node)
                .next()
                .expect("outer node should be present");
            if outer_node != node
                && (outer_node.kind() != "export" && outer_node.parent() != Some(node))
            {
                return None;
            }

            let kind = match decl.kind() {
                "const_decl" => DeclKind::Const,
                "var_decl" => {
                    let scope = c
                        .nodes_for_capture_index(c_scope)
                        .next()
                        .expect("scope should be present");

                    match scope.kind() {
                        "global" => DeclKind::Global,
                        "local" => DeclKind::Variable,
                        _ => {
                            error!("unhandled variable scope: {}", scope.kind());
                            return None;
                        }
                    }
                }
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

#[instrument]
pub fn loads<'a>(node: Node, source: &'a str) -> Vec<&'a str> {
    let query =
        match tree_sitter::Query::new(unsafe { tree_sitter_zeek() }, "(\"@load\") (file)@file") {
            Ok(q) => q,
            Err(e) => {
                error!("could not construct query: {}", e);
                return Vec::new();
            }
        };

    let c_file = query
        .capture_index_for_name("file")
        .expect("file should be captured");

    tree_sitter::QueryCursor::new()
        .matches(&query, node, source.as_bytes())
        .filter_map(|c| c.nodes_for_capture_index(c_file).next())
        .filter_map(|f| f.utf8_text(&source.as_bytes()).ok())
        .collect()
}

#[cfg(test)]
mod test {
    use super::{decls, loads, module, module_id};
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

              event zeek_init() { local x=1; \n
                  # Comment.
              }";

    #[test]
    fn test_loads() {
        let loads = |source| {
            loads(
                parse_(source, None).expect("cannot parse").root_node(),
                source,
            )
        };

        assert_eq!(loads(""), Vec::<&str>::new());

        assert_eq!(
            loads("@load ./main; @load base/misc/version;"),
            vec!["./main", "base/misc/version"]
        );
    }

    #[test]
    fn test_module() {
        let tree = parse_(SOURCE, None).expect("cannot parse");

        assert_debug_snapshot!(module(tree.root_node(), SOURCE));
    }

    #[test]
    fn test_decls() {
        let tree = parse_(SOURCE, None).expect("cannot parse");

        // Test decls reachable from the root node. This is used e.g., to figure out what decls are
        // available in a module. This should not contain e.g., function-scope decls.
        let root_decls = decls(tree.root_node(), SOURCE);
        assert_eq!(4, root_decls.len());
        assert_debug_snapshot!(root_decls);

        // Test decls with scope. While they should not be visible from outside the scope (tested
        // above), they should be visible inside the scope.
        let func_body = tree
            .root_node()
            .child(5)
            .expect("cannot get event_decl")
            .child(3)
            .expect("cannot get func_body");
        assert_eq!(func_body.kind(), "func_body");
        let func_decls = decls(func_body, SOURCE);
        assert_eq!(func_decls.len(), 1);
        assert_debug_snapshot!(func_decls);
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