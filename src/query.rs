use itertools::Itertools;
use lspower::lsp::{Position, Range, Url};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    hash::Hash,
    str::Utf8Error,
    sync::Arc,
};
use tracing::{error, instrument};

use crate::parse::{tree_sitter_zeek, Parse};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum DeclKind {
    Global,
    Option,
    Const,
    Redef,
    RedefEnum,
    RedefRecord,
    Type(Vec<Decl>),
    FuncDef,
    FuncDecl,
    Hook,
    Event,
    Variable,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Type(pub String);

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct TypeField {
    pub id: String,
    pub typ: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Decl {
    pub module: ModuleId,
    pub id: String,
    pub fqid: String,
    pub kind: DeclKind,
    pub is_export: Option<bool>,
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
    None,
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ModuleId::Global => "GLOBAL",
                ModuleId::String(s) => s.as_str(),
                ModuleId::None => "NONE",
            }
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Node<'a>(tree_sitter::Node<'a>);

impl<'a> Node<'a> {
    #[must_use]
    pub fn kind(&self) -> &'a str {
        self.0.kind()
    }

    #[must_use]
    pub fn range(&self) -> Range {
        let r = self.0.range();

        #[allow(clippy::cast_possible_truncation)]
        let position =
            |p: tree_sitter::Point| -> Position { Position::new(p.row as u32, p.column as u32) };

        Range::new(position(r.start_point), position(r.end_point))
    }

    #[must_use]
    pub fn to_sexp(&self) -> String {
        self.0.to_sexp()
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn utf8_text<'b>(&self, source: &'b [u8]) -> Result<&'b str, Utf8Error> {
        self.0.utf8_text(source)
    }

    pub fn parent(&self) -> Option<Self> {
        self.0.parent().map(Into::into)
    }

    #[must_use]
    pub fn named_child(&self, kind: &str) -> Option<Self> {
        self.named_children(kind).into_iter().next()
    }

    #[must_use]
    pub fn named_child_not(&self, not_kind: &str) -> Option<Self> {
        self.named_children_not(not_kind).into_iter().next()
    }

    #[must_use]
    pub fn named_children(&self, kind: &str) -> Vec<Self> {
        let mut cur = self.0.walk();
        self.0
            .named_children(&mut cur)
            .filter(|n| n.kind() == kind)
            .map(Into::into)
            .collect()
    }

    #[must_use]
    pub fn named_children_not(&self, not_kind: &str) -> Vec<Self> {
        let mut cur = self.0.walk();
        self.0
            .named_children(&mut cur)
            .filter(|n| n.kind() != not_kind)
            .map(Into::into)
            .collect()
    }

    #[must_use]
    pub fn next_sibling(&self) -> Option<Self> {
        let mut n = self.0;
        while let Some(p) = n.next_named_sibling() {
            if p.kind() != "nl" {
                return Some(p.into());
            }

            n = p;
        }
        None
    }

    #[must_use]
    pub fn prev_sibling(&self) -> Option<Self> {
        let mut n = self.0;
        while let Some(p) = n.prev_named_sibling() {
            if p.kind() != "nl" {
                return Some(p.into());
            }

            n = p;
        }
        None
    }

    #[must_use]
    pub fn named_descendant_for_point_range(&self, range: Range) -> Option<Self> {
        let start =
            tree_sitter::Point::new(range.start.line as usize, range.start.character as usize);
        let end = tree_sitter::Point::new(range.end.line as usize, range.end.character as usize);

        // TODO(bbannier): this can still return a `nl` node :/
        self.0
            .named_descendant_for_point_range(start, end)
            .map(Into::into)
    }

    #[must_use]
    pub fn descendant_for_position(&self, position: Position) -> Option<Self> {
        let start = tree_sitter::Point::new(position.line as usize, position.character as usize);

        // TODO(bbannier): this can still return a `nl` node :/

        self.0
            .descendant_for_point_range(start, start)
            .map(Into::into)
    }

    #[must_use]
    pub fn named_descendant_for_position(&self, position: Position) -> Option<Self> {
        let range = Range::new(position, position);
        self.named_descendant_for_point_range(range)
    }
}

impl<'a> From<tree_sitter::Node<'a>> for Node<'a> {
    fn from(n: tree_sitter::Node<'a>) -> Self {
        Self(n)
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
pub fn decls_(node: Node, uri: Arc<Url>, source: &[u8]) -> HashSet<Decl> {
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
        .matches(&query, node.0, source)
        .filter_map(|c| {
            let decl = c.nodes_for_capture_index(c_decl).next()?;
            let decl: Node = decl.into();

            // Skip children not directly below the node or in an `export` below the node.
            // TODO(bbannier): this would probably be better handled directly in the query.
            let outer_node = c
                .nodes_for_capture_index(c_outer_node)
                .next()
                .expect("outer node should be present");
            if outer_node != node.0
                && (outer_node.kind() != "export_decl" && outer_node.parent() != Some(node.0))
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
                        while let Some(m) = node.prev_sibling() {
                            if m.kind() == "module_decl" {
                                module_id = Some(ModuleId::String(
                                    m.named_children_not("nl")
                                        .into_iter()
                                        .next()?
                                        .utf8_text(source)
                                        .ok()?
                                        .into(),
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

            let id: Node = c.nodes_for_capture_index(c_id).next()?.into();

            let range = decl.range();
            let selection_range = id.range();

            let id = id.utf8_text(source).ok()?.to_string();

            let documentation = if let Some(docs) = zeekygen_comments(decl, source) {
                format!(
                    "{docs}\n```zeek\n{source}\n```",
                    source = decl.utf8_text(source).ok()?
                )
            } else {
                format!(
                    "```zeek\n{source}\n```",
                    source = decl.utf8_text(source).ok()?
                )
            };

            let fqid = match &module {
                ModuleId::Global | ModuleId::None => id.clone(),
                ModuleId::String(m) => format!("{}::{}", &m, &id),
            };

            let kind = match decl.kind() {
                "const_decl" => DeclKind::Const,
                "var_decl" => {
                    let scope = c
                        .nodes_for_capture_index(c_scope)
                        .next()
                        .expect("scope should be present");

                    // Forward declarations of functions like `global foo: function(): count` are
                    // parsed as `var_decl` like this:
                    //
                    // (var_decl
                    //   (id)
                    //   (type "function" (func_params (type))))
                    //
                    // Correct for that here.
                    if decl
                        .named_child("type")
                        .and_then(|typ| typ.named_child("function"))
                        .is_some()
                    {
                        DeclKind::FuncDef
                    } else {
                        // Just a plain & clean variable declaration.
                        match scope.kind() {
                            "global" => DeclKind::Global,
                            "local" => DeclKind::Variable,
                            _ => {
                                error!("unhandled variable scope: {}", scope.kind());
                                return None;
                            }
                        }
                    }
                }
                "redef_enum_decl" => DeclKind::RedefEnum,
                "redef_record_decl" => DeclKind::RedefRecord,
                "option_decl" => DeclKind::Option,
                "type_decl" => {
                    let typ = decl.named_child("type")?;

                    let fields = typ
                        .named_children_not("nl")
                        .into_iter()
                        .filter_map(|c| {
                            if c.kind() == "type_spec" {
                                let id_ = c.named_child("id")?;
                                let id = id_.utf8_text(source).ok()?;

                                let documentation = if let Some(docs) = zeekygen_comments(c, source)
                                {
                                    format!(
                                        "{docs}\n```zeek\n# In {fqid}\n{source}\n```",
                                        source = c.utf8_text(source).ok()?
                                    )
                                } else {
                                    format!(
                                        "```zeek\n# In {fqid}\n{source}\n```",
                                        source = c.utf8_text(source).ok()?
                                    )
                                };

                                Some(Decl {
                                    id: id.to_string(),
                                    fqid: format!("{fqid}::{id}"),
                                    kind: DeclKind::Variable,
                                    range: id_.range(),
                                    selection_range: id_.range(),
                                    documentation,
                                    uri: uri.clone(),

                                    module: ModuleId::None,
                                    is_export: None,
                                })
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();

                    DeclKind::Type(fields)
                }
                "event_decl" => DeclKind::Event,
                "func_decl" => DeclKind::FuncDecl,
                _ => {
                    return None;
                }
            };

            Some(Decl {
                module,
                id,
                fqid,
                kind,
                is_export: Some(in_export(decl)),
                range,
                selection_range,
                documentation,
                uri: uri.clone(),
            })
        })
        .collect()
}

#[instrument]
pub fn decl_at(id: &str, mut node: Node, uri: Arc<Url>, source: &[u8]) -> Option<Decl> {
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
        .matches(&query, node.0, source.as_bytes())
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

    Arc::new(decls_(tree.root_node(), uri, source.as_bytes()))
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

/// Extracts pre and post zeekygen comments for the given node.
fn zeekygen_comments(x: Node, source: &[u8]) -> Option<String> {
    // Extracting the zeekygen comments with the query seems to hit some polynomial
    // edge case in tree-sitter. Extract them by hand for the time being.
    let mut docs = VecDeque::new();

    let mut node = x.prev_sibling();
    while let Some(n) = node {
        if n.kind() != "zeekygen_next_comment" {
            break;
        }

        let c = n.utf8_text(source).ok()?;
        let c = match c.strip_prefix("##") {
            Some(c) => c,
            None => c,
        };
        docs.push_front(c.trim());

        node = n.prev_sibling();
    }

    let mut node = x.next_sibling();
    while let Some(n) = node {
        if n.kind() != "zeekygen_prev_comment" {
            break;
        }

        let c = n.utf8_text(source).ok()?;
        let c = match c.strip_prefix("##<") {
            Some(c) => c,
            None => c,
        };
        docs.push_back(c.trim());

        node = n.next_sibling();
    }

    if docs.is_empty() {
        None
    } else {
        Some(docs.iter().join("\n"))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use crate::{lsp::Database, parse::Parse, query::Node, Files};
    use insta::assert_debug_snapshot;
    use lspower::lsp::{Position, Url};

    const SOURCE: &str = "module test;

              export {
                  const x = 1 &redef;
                  global y = 1;
              }

              ## Y does the y.
              ## It takes no arguments.
              type Y: record {
                  ## A field.
                  y: vector of count &optional;
              }; ##< But it also has a field y

              module bar;
              event zeek_init() { local x=1; \n
                  # Comment.
              }";

    #[test]
    fn loads_raw() {
        let parse = |source: &str| {
            let mut db = Database::default();
            let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());

            db.set_source(uri.clone(), Arc::new(source.to_string()));
            db.parse(uri)
        };

        let loads = |source: &'static str| {
            super::loads_raw(
                parse(&source).expect("cannot parse").root_node().into(),
                &source,
            )
        };

        assert_eq!(loads(""), Vec::<&str>::new());

        assert_eq!(
            loads("@load ./main\n @load base/misc/version"),
            vec!["./main", "base/misc/version"]
        );
    }

    #[test]
    fn decls_() {
        let mut db = Database::default();
        let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());
        db.set_source(uri.clone(), Arc::new(SOURCE.to_string()));

        let tree = db.parse(uri.clone()).expect("cannot parse");

        let decls_ = |n: Node| {
            let mut xs = super::decls_(n.into(), uri.clone(), SOURCE.as_bytes())
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
            .named_child("event_decl")
            .expect("cannot get event_decl")
            .named_child("func_body")
            .expect("cannot get func_body");
        assert_eq!(func_body.kind(), "func_body");
        let func_decls = decls_(func_body);
        assert_eq!(func_decls.len(), 1);
        assert_debug_snapshot!(func_decls);
    }

    #[test]
    fn in_export() {
        let mut db = Database::default();
        let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());
        db.set_source(uri.clone(), Arc::new(SOURCE.to_string()));
        let tree = db.parse(uri.clone()).unwrap();

        assert!(!super::in_export(tree.root_node()));

        let node = tree.root_node();
        let const_node = node
            .named_descendant_for_position(Position::new(3, 20))
            .unwrap();
        assert_eq!(const_node.kind(), "const_decl");
        assert!(super::in_export(const_node));

        let zeek_init_node = tree.root_node().named_child("event_decl").unwrap();
        assert_eq!(zeek_init_node.kind(), "event_decl");
        assert!(!super::in_export(zeek_init_node));
    }
}
