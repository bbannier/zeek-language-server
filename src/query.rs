use std::{collections::HashSet, fmt, hash::Hash, sync::Arc};

use log::error;
use tower_lsp::lsp_types::{Range, Url};
use tracing::instrument;
use tree_sitter::Node;

use crate::{
    parse::{tree_sitter_zeek, Parse},
    to_range,
};

#[derive(Debug, PartialEq, Copy, Clone, Eq, Hash)]
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
    pub module: ModuleId,
    pub id: String,
    pub kind: DeclKind,
    pub is_export: bool,
    pub range: Range,
    pub selection_range: Range,
    pub documentation: String,
    pub uri: Arc<Url>,
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Decl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.module.hash(state);
        self.id.hash(state);
        self.kind.hash(state);
        self.is_export.hash(state);
        self.is_export.hash(state);

        self.range.start.line.hash(state);
        self.range.start.character.hash(state);

        self.range.end.line.hash(state);
        self.range.end.character.hash(state);

        self.documentation.hash(state);
        self.uri.hash(state);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ModuleId {
    String(String),
    Global,
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ModuleId::Global => "GLOBAL",
                ModuleId::String(s) => s.as_str(),
            }
        )
    }
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

#[instrument]
#[must_use]
pub fn decls_(node: Node, uri: Arc<Url>, source: &str) -> HashSet<Decl> {
    let query = match tree_sitter::Query::new(
        unsafe { tree_sitter_zeek() },
        "(_ (_ ([\"global\" \"local\"]?)@scope (id)@id)@decl)@outer_node",
    ) {
        Ok(q) => q,
        Err(e) => {
            error!("could not construct query: {}", e);
            return HashSet::new();
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

            // Figure out the module this decl is for.
            let module = {
                let mut module_id = None;

                let mut node = decl;
                while let Some(n) = node.parent() {
                    if n.kind() == "source_file" {
                        // Found a source file. Now find the most recent
                        // module decl when looking backwards from `node`.
                        while let Some(m) = node.prev_named_sibling() {
                            if m.kind() == "module_decl" {
                                module_id = Some(ModuleId::String(
                                    m.named_child(0)?.utf8_text(source.as_bytes()).ok()?.into(),
                                ));
                                break;
                            }

                            // Go to sibling before.
                            node = m;
                        }
                    }

                    // Go one level higher.
                    node = n;
                }

                module_id.unwrap_or(ModuleId::Global)
            };

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
                module,
                id,
                kind,
                is_export: in_export(decl),
                range,
                selection_range,
                documentation,
                uri: uri.clone(),
            })
        })
        .collect()
}

#[instrument]
pub fn decl_at(id: &str, mut node: Node, uri: Arc<Url>, source: &str) -> Option<Decl> {
    loop {
        if let Some(decl) = decls_(node, uri.clone(), source)
            .into_iter()
            .find(|d| d.id == id)
        {
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
fn loads_raw<'a>(node: Node, source: &'a str) -> Vec<&'a str> {
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
        .filter_map(|f| f.utf8_text(source.as_bytes()).ok())
        .collect()
}

#[salsa::query_group(QueryStorage)]
pub trait Query: Parse {
    #[must_use]
    fn decls(&self, uri: Arc<Url>) -> Arc<HashSet<Decl>>;

    #[must_use]
    fn loads(&self, uri: Arc<Url>) -> Arc<Vec<String>>;
}

#[instrument(skip(db))]
fn decls(db: &dyn Query, uri: Arc<Url>) -> Arc<HashSet<Decl>> {
    let source = db.source(uri.clone());
    let tree = match db.parse(uri.clone()) {
        Some(t) => t,
        None => return Arc::new(HashSet::new()),
    };

    Arc::new(decls_(tree.root_node(), uri, &source))
}

#[instrument(skip(db))]
fn loads(db: &dyn Query, uri: Arc<Url>) -> Arc<Vec<String>> {
    let tree = match db.parse(uri.clone()) {
        Some(t) => t,
        None => return Arc::new(Vec::new()),
    };
    let source = db.source(uri);

    Arc::new(
        loads_raw(tree.root_node(), &source)
            .iter()
            .map(ToString::to_string)
            .collect(),
    )
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::{decls_, loads_raw};
    use crate::{lsp::Database, parse::Parse, query::in_export, Files};
    use insta::assert_debug_snapshot;
    use tower_lsp::lsp_types::Url;
    use tree_sitter::Node;

    const SOURCE: &str = "module test;

              export {
                  const x = 1 &redef;
                  global y = 1;
              }

              type Y: record {
                  y: vector of count &optional;
              };

              module bar;
              event zeek_init() { local x=1; \n
                  # Comment.
              }";

    #[test]
    fn test_loads() {
        let parse = |source: &str| {
            let mut db = Database::default();
            let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());

            db.set_source(uri.clone(), Arc::new(source.to_string()));
            db.parse(uri)
        };

        let loads = |source: &'static str| {
            loads_raw(parse(&source).expect("cannot parse").root_node(), &source)
        };

        assert_eq!(loads(""), Vec::<&str>::new());

        assert_eq!(
            loads("@load ./main\n @load base/misc/version"),
            vec!["./main", "base/misc/version"]
        );
    }

    #[test]
    fn test_decls_() {
        let mut db = Database::default();
        let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());
        db.set_source(uri.clone(), Arc::new(SOURCE.to_string()));

        let tree = db.parse(uri.clone()).expect("cannot parse");

        let decls_ = |n: Node| {
            let mut xs = decls_(n, uri.clone(), SOURCE)
                .into_iter()
                .collect::<Vec<_>>();
            xs.sort_by(|a, b| a.range.start.cmp(&b.range.start));
            xs
        };

        // Test decls reachable from the root node. This is used e.g., to figure out what decls are
        // available in a module. This should not contain e.g., function-scope decls.
        let root_decls = decls_(tree.root_node());
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
        let func_decls = decls_(func_body);
        assert_eq!(func_decls.len(), 1);
        assert_debug_snapshot!(func_decls);
    }

    #[test]
    fn test_in_export() {
        let mut db = Database::default();
        let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());
        db.set_source(uri.clone(), Arc::new(SOURCE.to_string()));
        let tree = db.parse(uri.clone()).unwrap();

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
}
