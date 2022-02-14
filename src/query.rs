use itertools::Itertools;
use lspower::lsp::{Position, Range, Url};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    hash::Hash,
    str::Utf8Error,
    sync::Arc,
};
use tracing::{debug, error, instrument};

use crate::parse::{tree_sitter_zeek, Parse};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum DeclKind {
    Global,
    Option,
    Const,
    Redef,
    Type(Vec<Decl>),
    RedefRecord(Vec<Decl>),
    Enum(Vec<Decl>),
    RedefEnum(Vec<Decl>),
    FuncDef(Signature),
    FuncDecl(Signature),
    Hook(Signature),
    Event(Signature),
    Variable,
    Field,
    EnumMember,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Signature {
    pub result: Option<String>,
    pub args: Vec<Decl>,
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

    #[must_use]
    pub fn error(&self) -> String {
        if self.0.is_error() {
            self.0
                .child(0)
                .map_or_else(|| self.to_sexp(), |c| format!("unexpected {}", c.kind()))
        } else if self.0.is_missing() {
            let msg = self.to_sexp().replacen("MISSING", "missing", 1);

            #[allow(clippy::map_unwrap_or)]
            msg.strip_prefix('(')
                .and_then(|m| m.strip_suffix(')'))
                .map(String::from)
                .unwrap_or_else(|| msg)
        } else {
            self.to_sexp()
        }
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
    fn next_sibling(&self) -> Option<Self> {
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
    fn prev_sibling(&self) -> Option<Self> {
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

    /// Extract all error nodes under the node.
    #[must_use]
    pub fn errors(&self) -> Vec<Node> {
        fn errors(n: tree_sitter::Node) -> Vec<tree_sitter::Node> {
            let mut cur = n.walk();

            let res = n.children(&mut cur).flat_map(errors);

            if n.is_error() || n.is_missing() {
                res.chain(std::iter::once(n)).collect()
            } else {
                res.collect()
            }
        }

        errors(self.0).into_iter().map(Node::from).collect()
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
        "(_ (_ ([\"global\" \"local\"]?)@scope (id)@id (type (func_params))?@fn)@decl)@outer_node",
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

    let c_fn = query
        .capture_index_for_name("fn")
        .expect("fn should be captured");

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

            // Helper to compute a module ID from a given string.
            let comp_module_id = |id: &str| match id {
                "GLOBAL" => ModuleId::Global,
                "" => ModuleId::None,
                _ => ModuleId::String(id.into()),
            };

            // Figure out the module this decl is for.
            let mut module = {
                let mut module_id = None;

                let mut node = decl;
                while let Some(n) = node.parent() {
                    if n.kind() == "source_file" {
                        // Found a source file. Now find the most recent
                        // module decl when looking backwards from `node`.
                        while let Some(m) = node.prev_sibling() {
                            if m.kind() == "module_decl" {
                                module_id = Some(comp_module_id(
                                    m.named_children_not("nl")
                                        .into_iter()
                                        .next()?
                                        .utf8_text(source)
                                        .ok()?,
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

                module_id.unwrap_or(ModuleId::None)
            };
            let module_name = module.clone();

            let id: Node = c.nodes_for_capture_index(c_id).next()?.into();

            let range = decl.range();
            let selection_range = id.range();

            let id = {
                // The grammar doesn't expose module ids in identifiers like `mod::f` directly, parse by hand.
                let x = id.utf8_text(source).ok()?;
                let spl = x.splitn(2, "::").collect::<Vec<_>>();

                match spl.len() {
                    // The module was part of the ID.
                    2 => {
                        module = comp_module_id(spl[0]);
                        spl[1].to_string()
                    }
                    // Just a plain local ID.
                    1 => spl[0].to_string(),
                    // This just looks plain wrong.
                    _ => {
                        debug!("unexpected empty id at {:?}", id.range());
                        return None;
                    }
                }
            };

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

            let mut fqid = match &module {
                ModuleId::Global | ModuleId::None => id.clone(),
                ModuleId::String(m) => format!("{}::{}", &m, &id),
            };

            let signature = |n: Node| -> Option<Signature> {
                let func_params = n.named_child("func_params")?;
                let result = func_params
                    .named_child("type")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(String::from);
                let args = func_params
                    .named_child("formal_args")
                    .map_or(Vec::new(), |args| {
                        args.named_children("formal_arg")
                            .into_iter()
                            .filter_map(|arg| {
                                let arg_id_ = arg.named_child("id")?;
                                let arg_id = arg_id_.utf8_text(source).ok()?;

                                Some(Decl {
                                    module: ModuleId::None,
                                    id: arg_id.to_string(),
                                    fqid: arg_id.to_string(),
                                    kind: DeclKind::Variable,
                                    is_export: None,
                                    range: arg_id_.range(),
                                    selection_range: arg.range(),
                                    uri: uri.clone(),
                                    documentation: format!(
                                        "```zeek\n{}\n```",
                                        arg.utf8_text(source).ok()?
                                    ),
                                })
                            })
                            .collect()
                    });
                Some(Signature { result, args })
            };

            let extract_documentation = |n: Node| -> Option<String> {
                let documentation = if let Some(docs) = zeekygen_comments(n, source) {
                    format!(
                        "{docs}\n```zeek\n# In {fqid}\n{source}\n```",
                        source = n.utf8_text(source).ok()?
                    )
                } else {
                    format!(
                        "```zeek\n# In {fqid}\n{source}\n```",
                        source = n.utf8_text(source).ok()?
                    )
                };

                Some(documentation)
            };

            let extract_fields = |decl: Node| {
                // Records wrap their field list in an extra `type` node, `redef_record_decl`
                // directly contain them.
                let typ = if let Some(c) = decl.named_child("type") {
                    c
                } else {
                    decl
                };

                let fields = typ
                    .named_children("type_spec")
                    .into_iter()
                    .filter_map(|c| {
                        let id_ = c.named_child("id")?;
                        let id = id_.utf8_text(source).ok()?;

                        let documentation = extract_documentation(c)?;

                        Some(Decl {
                            id: id.to_string(),
                            fqid: format!("{fqid}::{id}"),
                            kind: DeclKind::Field,
                            range: id_.range(),
                            selection_range: id_.range(),
                            documentation,
                            uri: uri.clone(),

                            module: ModuleId::None,
                            is_export: None,
                        })
                    })
                    .collect::<Vec<_>>();

                Some(fields)
            };

            let type_decl = |decl: Node| -> Option<DeclKind> {
                if let Some(enum_body) = decl.named_child("type")?.named_child("enum_body") {
                    let values = enum_body
                        .named_children("enum_body_elem")
                        .into_iter()
                        .filter_map(|n| {
                            let id_ = n.named_child("id")?;
                            let id = id_.utf8_text(source).ok()?;

                            // Enum values live in the parent scope.
                            let fqid = match &module_name {
                                ModuleId::Global | ModuleId::None => id.to_string(),
                                ModuleId::String(m) => format!("{m}::{id}"),
                            };
                            let id = id.to_string();

                            let range = id_.range();
                            let selection_range = range;
                            let documentation = extract_documentation(n)?;
                            Some(Decl {
                                module: module.clone(),
                                id,
                                fqid,
                                kind: DeclKind::EnumMember,
                                range,
                                selection_range,
                                documentation,
                                uri: uri.clone(),
                                // An enum value is exported if its wrapping decl is exported.
                                is_export: Some(in_export(decl)),
                            })
                        })
                        .collect();
                    Some(DeclKind::Enum(values))
                } else {
                    Some(DeclKind::Type(extract_fields(decl)?))
                }
            };

            // Declarations like enums inject their fields into the current scope. Store them here
            // so we can bubble them up as well.
            //
            // TODO(bbannier): This pollutes the global list of decls with decls which are
            // conceptually nested. Maybe we could not expose them here, but still have them
            // available in e.g., completions, lookups, etc.
            let mut additional_decls = Vec::new();

            let kind = match decl.kind() {
                "const_decl" => DeclKind::Const,
                "var_decl" => {
                    let scope = c
                        .nodes_for_capture_index(c_scope)
                        .next()
                        .expect("scope should be present");

                    if let Some(f) = c.nodes_for_capture_index(c_fn).next() {
                        DeclKind::FuncDef(signature(Node(f))?)
                    } else {
                        // Just a plain & clean variable declaration.
                        match scope.kind() {
                            "global" => DeclKind::Global,
                            "local" => {
                                fqid = id.clone();
                                module = ModuleId::None;
                                DeclKind::Variable
                            }
                            _ => {
                                error!("unhandled variable scope: {}", scope.kind());
                                return None;
                            }
                        }
                    }
                }
                "redef_enum_decl" => {
                    let fields = decl
                        .named_child("enum_body")?
                        .named_children("enum_body_elem")
                        .into_iter()
                        .filter_map(|c| {
                            let id_ = c.named_child("id")?;
                            let id = id_.utf8_text(source).ok()?;

                            // Enum values live in the parent scope.
                            let fqid = match &module_name {
                                ModuleId::Global | ModuleId::None => id.to_string(),
                                ModuleId::String(m) => format!("{m}::{id}"),
                            };
                            let id = id.to_string();

                            let documentation = extract_documentation(c)?;

                            Some(Decl {
                                module: module_name.clone(),
                                id,
                                fqid,
                                kind: DeclKind::EnumMember,
                                range: id_.range(),
                                selection_range: id_.range(),
                                documentation,
                                uri: uri.clone(),

                                // An enum value is exported if its wrapping decl is exported.
                                is_export: Some(in_export(decl)),
                            })
                        })
                        .collect::<Vec<_>>();
                    additional_decls.extend(fields.iter().cloned());
                    DeclKind::RedefEnum(fields)
                }
                "redef_record_decl" => DeclKind::RedefRecord(extract_fields(decl)?),
                "option_decl" => DeclKind::Option,
                "type_decl" => {
                    let kind = type_decl(decl)?;

                    if let DeclKind::Enum(fields) = &kind {
                        additional_decls.extend(fields.iter().cloned());
                    }

                    kind
                }
                "hook_decl" => DeclKind::Hook(signature(decl)?),
                "event_decl" => DeclKind::Event(signature(decl)?),
                "func_decl" => DeclKind::FuncDecl(signature(decl)?),
                _ => {
                    return None;
                }
            };

            Some(
                std::iter::once(Decl {
                    module: if in_export(decl) {
                        module
                    } else {
                        ModuleId::None
                    },
                    id,
                    fqid,
                    kind,
                    is_export: Some(in_export(decl)),
                    range,
                    selection_range,
                    documentation,
                    uri: uri.clone(),
                })
                .chain(additional_decls.into_iter()),
            )
        })
        .flatten()
        .chain(fn_param_decls(node, uri.clone(), source).into_iter())
        .collect()
}

/// Extract declarations for function parameters on the given node.
// TODO(bbannier): it seems we should be able to also accomplish this by looking at the function signature.
#[instrument]
pub fn fn_param_decls(node: Node, uri: Arc<Url>, source: &[u8]) -> HashSet<Decl> {
    match node.kind() {
        "func_decl" | "hook_decl" | "event_decl" => {}
        _ => return HashSet::new(),
    }

    // Synthesize declarations for function arguments. Ideally the grammar would expose
    // these directly.
    let func_params = match node.named_child("func_params") {
        Some(p) => p,
        None => return HashSet::new(),
    };

    let formal_args = match func_params.named_child("formal_args") {
        Some(a) => a,
        None => return HashSet::new(),
    };

    formal_args
        .named_children("formal_arg")
        .into_iter()
        .filter_map(|arg| {
            let arg_id_ = arg.named_child("id")?;
            let arg_id = arg_id_.utf8_text(source).ok()?;

            Some(Decl {
                module: ModuleId::None,
                id: arg_id.to_string(),
                fqid: arg_id.to_string(),
                kind: DeclKind::Variable,
                is_export: None,
                range: arg_id_.range(),
                selection_range: arg.range(),
                uri: uri.clone(),
                documentation: format!("```zeek\n{}\n```", arg.utf8_text(source).ok()?),
            })
        })
        .collect()
}

#[instrument]
pub fn decl_at(id: &str, mut node: Node, uri: Arc<Url>, source: &[u8]) -> Option<Decl> {
    loop {
        if let Some(decl) = decls_(node, uri.clone(), source)
            .into_iter()
            .find(|d| d.id == id || d.fqid == id)
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

    use crate::{
        lsp::{Database, TestDatabase},
        parse::Parse,
        query::Node,
        Files,
    };
    use insta::assert_debug_snapshot;
    use lspower::lsp::{Position, Url};

    use super::Query;

    const SOURCE: &str = r#"module test;

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
              }

              global fun: function(x: count): string;
              function fun(x: count): string { return ""; }

              redef record Y += {
                  ## A new field.
                  y2: count &optional;
              };
              "#;

    #[test]
    fn loads_raw() {
        let parse = |source: &str| {
            let mut db = Database::default();
            let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());

            db.set_source(uri.clone(), Arc::new(source.to_string()));
            db.parse(uri)
        };

        let loads = |source: &'static str| {
            super::loads_raw(parse(source).expect("cannot parse").root_node(), source)
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
            let mut xs = super::decls_(n, uri.clone(), SOURCE.as_bytes())
                .into_iter()
                .collect::<Vec<_>>();
            xs.sort_by(|a, b| a.range.start.cmp(&b.range.start));
            xs
        };

        // Test decls reachable from the root node. This is used e.g., to figure out what decls are
        // available in a module. This should not contain e.g., function-scope decls.
        let root_decls = decls_(tree.root_node());
        assert_eq!(7, root_decls.len());
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
    fn decls_weird_modules() {
        let mut db = Database::default();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.set_source(
            uri.clone(),
            Arc::new(
                "module x;
export {
global f1: function();
global foo::f2: function();
global GLOBAL::f3: function();
}"
                .into(),
            ),
        );

        let decls = db.decls(uri);
        let mut decls = decls.iter().collect::<Vec<_>>();
        decls.sort_by(|a, b| a.range.start.cmp(&b.range.start));

        assert_debug_snapshot!(decls);
    }

    #[test]
    fn in_export() {
        let mut db = Database::default();
        let uri = Arc::new(Url::from_file_path("/foo/bar.zeek").unwrap());
        db.set_source(uri.clone(), Arc::new(SOURCE.to_string()));
        let tree = db.parse(uri).unwrap();

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

    #[test]
    fn fn_param_decls() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/tmp/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "module x;
function f1(x: count, y: string) {
    # Inside.
}",
        );

        let db = db.snapshot();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();
        let source = db.source(uri.clone());

        let in_f1 = root
            .named_descendant_for_position(Position::new(1, 0))
            .unwrap();
        assert_eq!(in_f1.kind(), "func_decl");
        let mut decls = super::fn_param_decls(in_f1, uri.clone(), source.as_bytes())
            .into_iter()
            .collect::<Vec<_>>();
        decls.sort_by(|a, b| a.range.start.cmp(&b.range.start));
        assert_debug_snapshot!(decls);

        let outside_f1 = root
            .named_descendant_for_position(Position::new(0, 0))
            .unwrap();
        assert_eq!(outside_f1.kind(), "module_decl");
        assert!(super::fn_param_decls(outside_f1, uri, source.as_bytes()).is_empty());
    }
}
