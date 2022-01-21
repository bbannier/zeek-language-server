use std::sync::Arc;

use log::error;
use tower_lsp::lsp_types::Range;
use tracing::instrument;
use tree_sitter::Node;

use crate::{
    parse::{tree_sitter_zeek, Parse, Tree},
    to_range, zeek, File,
};

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Decl {
    pub id: String,
    pub kind: DeclKind,
    pub is_export: bool,
    pub range: Range,
    pub selection_range: Range,
    pub documentation: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModuleId {
    String(String),
    Global,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Module {
    /// ID of this module.
    pub id: ModuleId,

    /// Declarations in this module.
    pub decls: Vec<Decl>,

    /// Other modules explicitly loaded by this module.
    pub loads: Vec<String>,

    /// Source range of this module.
    pub range: Range,
}

fn in_export(mut node: Node) -> bool {
    loop {
        node = match node.parent() {
            Some(p) => p,
            None => return false,
        };

        if node.kind() == "export_decl" {
            return true;
        }
    }
}

// FIXME(bbannier): this function makes no sense. A decl's module is determined by the previous
// module_decl (or GLOBAL). A file can have multiple modules.
fn module_id(node: Node, source: &str) -> ModuleId {
    let query = tree_sitter::Query::new(
        unsafe { tree_sitter_zeek() },
        "(module_decl (id)*@module_id)",
    )
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
        .last()
        .map_or(ModuleId::Global, |id| ModuleId::String(id.to_string()))
}

#[instrument(skip(source))]
#[must_use]
fn module_(tree: &Tree, source: &str) -> Module {
    let node = tree.root_node();

    let id = module_id(node, source);
    let decls = decls(node, source);
    let loads = loads(node, source).into_iter().map(String::from).collect();
    let range = to_range(node.range()).expect("invalid range");

    Module {
        id,
        decls,
        loads,
        range,
    }
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
            let decl = c.nodes_for_capture_index(c_decl).next()?;

            // Skip children not directly below the node or in an `export` below the node.
            // TODO(bbannier): this would probably be better handled directly in the query.
            let outer_node = c
                .nodes_for_capture_index(c_outer_node)
                .next()
                .expect("outer node should be present");
            if outer_node != node
                && (outer_node.kind() != "export_decl" && outer_node.parent() != Some(node))
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

            // TODO(bbannier): This just extracts the first line of the decl as documentation. We
            // should implement something richer, e.g., also extract (zeekygen) comments close by.
            let documentation =
                format!("```zeek\n{}\n```", decl.utf8_text(source.as_bytes()).ok()?);

            Some(Decl {
                id,
                kind,
                is_export: in_export(decl),
                range,
                selection_range,
                documentation,
            })
        })
        .collect()
}

#[instrument]
pub fn decl_at(id: &str, mut node: Node, source: &str) -> Option<Decl> {
    loop {
        if let Some(decl) = decls(node, source).into_iter().find(|d| d.id == id) {
            return Some(decl);
        }

        node = match node.parent() {
            Some(p) => p,
            None => break,
        };
    }

    None
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

    let implicit_module = if let Some(m) = zeek::init_script_filename().strip_suffix(".zeek") {
        m
    } else {
        zeek::init_script_filename()
    };

    std::iter::once(implicit_module)
        .chain(
            tree_sitter::QueryCursor::new()
                .matches(&query, node, source.as_bytes())
                .filter_map(|c| c.nodes_for_capture_index(c_file).next())
                .filter_map(|f| f.utf8_text(source.as_bytes()).ok()),
        )
        .collect()
}

#[salsa::query_group(QueryStorage)]
pub trait Query: Parse {
    #[must_use]
    fn module(&self, file: Arc<File>) -> Option<Arc<Module>>;
}

#[instrument(skip(db))]
fn module(db: &dyn Query, file: Arc<File>) -> Option<Arc<Module>> {
    let source = file.source.clone();
    let tree = db.parse(file)?;
    Some(Arc::new(module_(&tree, &source)))
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::{decls, loads, module_, module_id};
    use crate::{
        lsp::Database,
        parse::{Parse, Tree},
        query::{in_export, ModuleId},
        File,
    };
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

    fn parse(source: &str) -> Option<Arc<Tree>> {
        Database::default().parse(Arc::new(File {
            source: source.to_string(),
            load: "./test".into(),
        }))
    }

    #[test]
    fn test_loads() {
        let loads = |source: &'static str| {
            loads(parse(&source).expect("cannot parse").root_node(), &source)
        };

        assert_eq!(loads(""), vec!["base/init-default"]);

        assert_eq!(
            loads("@load ./main; @load base/misc/version;"),
            vec!["base/init-default", "./main", "base/misc/version"]
        );
    }

    #[test]
    fn test_module() {
        let tree = parse(SOURCE).expect("cannot parse");

        assert_debug_snapshot!(module_(&tree, SOURCE));
    }

    #[test]
    fn test_decls() {
        let tree = parse(SOURCE).expect("cannot parse");

        // Test decls reachable from the root node. This is used e.g., to figure out what decls are
        // available in a module. This should not contain e.g., function-scope decls.
        let root_decls = decls(tree.root_node(), SOURCE);
        assert_eq!(4, root_decls.len());
        assert_debug_snapshot!(root_decls);

        // Test decls with scope. While they should not be visible from outside the scope (tested
        // above), they should be visible inside the scope.
        let func_body = tree
            .root_node()
            .child(tree.root_node().child_count() - 1)
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
        let tree = parse(SOURCE).expect("cannot parse");
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
        let module_id = |source| module_id(parse(source).unwrap().root_node(), source);

        assert_eq!(module_id(""), ModuleId::Global);
        assert_eq!(module_id("event zeek_init() {}"), ModuleId::Global);
        assert_eq!(module_id("export {}"), ModuleId::Global);
        assert_eq!(
            module_id("# Comment.\n@load foo\nmodule test;"),
            ModuleId::String("test".to_string())
        );

        // For multiple module decls Zeek seems to use the last one.
        assert_eq!(
            module_id("module test1; module test2;"),
            ModuleId::String("test2".to_string())
        );
    }
}
