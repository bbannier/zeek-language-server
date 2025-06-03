use itertools::Itertools;
use rustc_hash::FxHashSet;
use std::{
    collections::VecDeque,
    fmt,
    hash::Hash,
    str::Utf8Error,
    sync::{Arc, LazyLock},
};
use streaming_iterator::{convert, StreamingIterator, StreamingIteratorMut};
use tower_lsp_server::lsp_types::{Position, Range, Uri};
use tracing::{debug, error, instrument};
use tree_sitter_zeek::language_zeek;

use crate::{parse::Parse, rst::markdownify, Str};

#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub enum DeclKind {
    Module,
    Global,
    Option,
    Const,
    Redef,
    Type(Vec<Decl>),
    RedefRecord(Vec<Decl>),
    Enum(Vec<Decl>),
    RedefEnum(Vec<Decl>),
    FuncDecl(Signature),
    FuncDef(Signature),
    HookDecl(Signature),
    HookDef(Signature),
    EventDecl(Signature),
    EventDef(Signature),
    Variable,
    Field,
    EnumMember,
    Index(Index, Str), // Result of an indexing operation for a given init expression.
    Builtin(Type),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub enum Index {
    Loop(usize),
    Key(usize),
    Value,
}

#[derive(Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
pub enum Type {
    Id(Str),
    Addr,
    Any,
    Bool,
    Count,
    Double,
    Int,
    Interval,
    String,
    Subnet,
    Pattern,
    Port,
    Table(Vec<Type>, Box<Type>),
    Set(Vec<Type>),
    Time,
    Timer,
    List(Box<Type>),
    Vector(Box<Type>),
    File(Box<Type>),
    Opaque(Box<Type>),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct Signature {
    pub result: Option<Type>,
    pub args: Vec<Decl>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Location {
    pub range: Range,
    pub selection_range: Range,
    pub uri: Arc<Uri>,
}

impl PartialOrd for Location {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Location {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match OrderedRange(self.range).cmp(&OrderedRange(other.range)) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match OrderedRange(self.selection_range).cmp(&OrderedRange(other.selection_range)) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        self.uri.cmp(&other.uri)
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for Location {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        NodeLocation::from_range(Arc::clone(&self.uri), self.range).hash(state);
        NodeLocation::from_range(Arc::clone(&self.uri), self.selection_range).hash(state);
        self.uri.hash(state);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Decl {
    pub module: ModuleId,
    pub id: Str,
    pub fqid: Str,
    pub kind: DeclKind,
    pub is_export: Option<bool>,
    pub loc: Option<Location>,
    pub documentation: Str,
}

impl PartialOrd for Decl {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Decl {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.module.cmp(&other.module) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.id.cmp(&other.id) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.fqid.cmp(&other.fqid) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.kind.cmp(&other.kind) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.is_export.cmp(&other.is_export) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        self.documentation.cmp(&other.documentation)
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for Decl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.module.hash(state);
        self.id.hash(state);
        self.kind.hash(state);
        self.is_export.hash(state);
        self.is_export.hash(state);
        self.loc.hash(state);
        self.documentation.hash(state);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FunctionCall {
    pub f: NodeLocation,
    pub args: Vec<NodeLocation>,
}

#[derive(PartialEq, Eq)]
struct OrderedRange(pub Range);
impl PartialOrd for OrderedRange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OrderedRange {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.0.start.cmp(&other.0.start) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        self.0.end.cmp(&other.0.end)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLocation {
    pub range: Range,
    pub uri: Arc<Uri>,
}

impl NodeLocation {
    #[must_use]
    pub fn from_node(uri: Arc<Uri>, node: Node) -> Self {
        Self {
            range: node.range(),
            uri,
        }
    }

    #[must_use]
    pub fn from_range(uri: Arc<Uri>, range: Range) -> Self {
        Self { range, uri }
    }
}

#[allow(clippy::derived_hash_with_manual_eq)]
impl Hash for NodeLocation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.range.start.line.hash(state);
        self.range.start.character.hash(state);
        self.range.end.line.hash(state);
        self.range.end.character.hash(state);

        self.uri.hash(state);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ModuleId {
    String(Str),
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
        let position = |p: tree_sitter::Point| -> Option<Position> {
            let Ok(line) = u32::try_from(p.row) else {
                error!("line overflowed");
                return None;
            };

            let Ok(character) = u32::try_from(p.column) else {
                error!("character overflowed");
                return None;
            };

            Some(Position::new(line, character))
        };

        let Some(start) = position(r.start_point) else {
            return Range::default();
        };

        let Some(end) = position(r.end_point) else {
            return Range::default();
        };

        Range::new(start, end)
    }

    #[must_use]
    pub fn to_sexp(&self) -> Str {
        self.0.to_sexp().into()
    }

    pub fn utf8_text<'b>(&self, source: &'b [u8]) -> Result<&'b str, Utf8Error> {
        self.0.utf8_text(source)
    }

    #[must_use]
    pub fn error(&self) -> Str {
        if self.0.is_error() {
            self.0.child(0).map_or_else(
                || self.to_sexp(),
                |c| format!("unexpected {}", c.kind()).into(),
            )
        } else if self.0.is_missing() {
            let msg = Str::from(self.to_sexp().replacen("MISSING", "missing", 1));

            #[allow(clippy::map_unwrap_or)]
            msg.strip_prefix('(')
                .and_then(|m| m.strip_suffix(')'))
                .map(Str::from)
                .unwrap_or_else(|| msg)
        } else {
            self.to_sexp()
        }
    }

    #[must_use]
    pub fn is_missing(&self) -> bool {
        self.0.is_missing()
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
pub fn decls_(node: Node, uri: Arc<Uri>, source: &[u8]) -> FxHashSet<Decl> {
    static QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        let signature = "((formal_args)? (type)?@fn_result)@signature";
        let signature = format!("[{signature} (func_params ({signature}))]");
        let typ = format!("[(type {signature}?) {signature}]?@typ");
        tree_sitter::Query::new(
            &language_zeek(),
            &format!(r#"(_ (_ (["global" "local"]?)@scope (id)@id {typ})@decl)@outer_node"#),
        )
        .expect("invalid query")
    });

    static C_SCOPE: LazyLock<u32> = LazyLock::new(|| {
        QUERY
            .capture_index_for_name("scope")
            .expect("scope should be captured")
    });

    static C_ID: LazyLock<u32> = LazyLock::new(|| {
        QUERY
            .capture_index_for_name("id")
            .expect("id should be captured")
    });

    static C_TYP: LazyLock<u32> = LazyLock::new(|| {
        QUERY
            .capture_index_for_name("typ")
            .expect("typ should be captured")
    });

    static C_SIGNATURE: LazyLock<u32> = LazyLock::new(|| {
        QUERY
            .capture_index_for_name("signature")
            .expect("signature should be captured")
    });

    static C_FN_RESULT: LazyLock<u32> = LazyLock::new(|| {
        QUERY
            .capture_index_for_name("fn_result")
            .expect("fn_result should be captured")
    });

    static C_DECL: LazyLock<u32> = LazyLock::new(|| {
        QUERY
            .capture_index_for_name("decl")
            .expect("decl should be captured")
    });

    static C_OUTER_NODE: LazyLock<u32> = LazyLock::new(|| {
        QUERY
            .capture_index_for_name("outer_node")
            .expect("outer node should be captured")
    });

    tree_sitter::QueryCursor::new()
        .matches(&QUERY, node.0, source)
        .filter_map(|c| {
            let decl = c.nodes_for_capture_index(*C_DECL).next()?;
            let decl: Node = decl.into();

            // Skip children not directly below the node or in an `export` below the node.
            // TODO(bbannier): this would probably be better handled directly in the query.
            let outer_node = c
                .nodes_for_capture_index(*C_OUTER_NODE)
                .next()
                .expect("outer node should be present");
            if outer_node != node.0
                && (outer_node.kind() != "export_decl" && outer_node.parent() != Some(node.0))
            {
                return None;
            }

            // Figure out the module this decl is for.
            let mut module = parent_module(decl, source)?;
            let module_name = module.clone();

            let id: Node = c.nodes_for_capture_index(*C_ID).next()?.into();
            let id_written = id.utf8_text(source).ok()?;

            let typ = c.nodes_for_capture_index(*C_TYP).next().map(Node::from);

            let signature = c
                .nodes_for_capture_index(*C_SIGNATURE)
                .next()
                .map(Node::from);

            let fn_args = signature.map_or_else(Vec::new, |xs| xs.named_children("formal_arg"));

            let fn_result = c
                .nodes_for_capture_index(*C_FN_RESULT)
                .next()
                .and_then(|n| self::typ(n.into(), source));

            let range = decl.range();
            let selection_range = id.range();

            let id: Str = {
                // The grammar doesn't expose module ids in identifiers like `mod::f` directly, parse by hand.
                let spl = id_written.splitn(2, "::").collect::<Vec<_>>();

                match spl.len() {
                    // The module was part of the ID.
                    2 => {
                        module = compute_module_id(spl[0]);
                        spl[1].into()
                    }
                    // Just a plain local ID.
                    1 => spl[0].into(),
                    // This just looks plain wrong.
                    _ => {
                        debug!("unexpected empty id at {:?}", id.range());
                        return None;
                    }
                }
            };

            let documentation = if let Some(docs) = zeekygen_comments(decl, source) {
                format!(
                    "{docs}\n* * *\n```zeek\n{source}\n```",
                    source = decl.utf8_text(source).ok()?
                )
            } else {
                format!(
                    "```zeek\n{source}\n```",
                    source = decl.utf8_text(source).ok()?
                )
            }
            .as_str()
            .into();

            let mut fqid = match &module {
                ModuleId::Global | ModuleId::None => id.clone(),
                ModuleId::String(m) => format!("{}::{}", &m, &id).into(),
            };

            let signature = || -> Option<Signature> {
                let args = fn_args
                    .iter()
                    .filter_map(|arg| {
                        let arg_id_ = arg.named_child("id")?;
                        let arg_id = arg_id_.utf8_text(source).ok()?;

                        Some(Decl {
                            module: ModuleId::None,
                            id: arg_id.into(),
                            fqid: arg_id.into(),
                            kind: DeclKind::Variable,
                            is_export: None,
                            loc: Some(Location {
                                range: arg_id_.range(),
                                selection_range: arg.range(),
                                uri: Arc::clone(&uri),
                            }),
                            documentation: format!("```zeek\n{}\n```", arg.utf8_text(source).ok()?)
                                .as_str()
                                .into(),
                        })
                    })
                    .collect();
                Some(Signature {
                    result: fn_result,
                    args,
                })
            };

            let extract_documentation = |n: Node| -> Option<Str> {
                let documentation = if let Some(docs) = zeekygen_comments(n, source) {
                    format!(
                        "{docs}\n* * *\n```zeek\n# In {fqid}\n{source}\n```",
                        source = n.utf8_text(source).ok()?
                    )
                } else {
                    format!(
                        "```zeek\n# In {fqid}\n{source}\n```",
                        source = n.utf8_text(source).ok()?
                    )
                };

                Some(documentation.as_str().into())
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
                            id: id.into(),
                            fqid: format!("{fqid}::{id}").into(),
                            kind: DeclKind::Field,
                            loc: Some(Location {
                                range: id_.range(),
                                selection_range: id_.range(),
                                uri: Arc::clone(&uri),
                            }),
                            documentation,

                            module: ModuleId::None,
                            is_export: None,
                        })
                    })
                    .collect::<Vec<_>>();

                Some(fields)
            };

            let type_decl = |decl: Node| -> Option<DeclKind> {
                let enum_body_elems = decl.named_child("type")?.named_children("enum_body_elem");
                if enum_body_elems.is_empty() {
                    Some(DeclKind::Type(extract_fields(decl)?))
                } else {
                    let values = enum_body_elems
                        .into_iter()
                        .filter_map(|n| {
                            let id_ = n.named_child("id")?;
                            let id: Str = id_.utf8_text(source).ok()?.into();

                            // Enum values live in the parent scope.
                            let fqid = match &module_name {
                                ModuleId::Global | ModuleId::None => id.clone(),
                                ModuleId::String(m) => format!("{m}::{id}").into(),
                            };

                            let range = id_.range();
                            let selection_range = range;
                            let documentation = extract_documentation(n)?;
                            Some(Decl {
                                module: module.clone(),
                                id,
                                fqid,
                                kind: DeclKind::EnumMember,
                                loc: Some(Location {
                                    range,
                                    selection_range,
                                    uri: Arc::clone(&uri),
                                }),
                                documentation,
                                // An enum value is exported if its wrapping decl is exported.
                                is_export: Some(in_export(decl)),
                            })
                        })
                        .collect();
                    Some(DeclKind::Enum(values))
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
                        .nodes_for_capture_index(*C_SCOPE)
                        .next()
                        .expect("scope should be present");

                    // Translate typ into possible func-like kind. We need this since the grammar
                    // does not expose the type of these.
                    let fn_like = if let Some(typ) = typ.and_then(|n| n.utf8_text(source).ok()) {
                        if typ.starts_with("function(") {
                            Some(DeclKind::FuncDecl(signature()?))
                        } else if typ.starts_with("hook(") {
                            Some(DeclKind::HookDecl(signature()?))
                        } else if typ.starts_with("event(") {
                            Some(DeclKind::EventDecl(signature()?))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let Some(fn_like) = fn_like {
                        fn_like
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
                        .named_children("enum_body_elem")
                        .into_iter()
                        .filter_map(|c| {
                            let id_ = c.named_child("id")?;
                            let id = id_.utf8_text(source).ok()?;

                            // Enum values live in the parent scope.
                            let fqid = match &module_name {
                                ModuleId::Global | ModuleId::None => id.into(),
                                ModuleId::String(m) => format!("{m}::{id}").into(),
                            };
                            let id = id.into();

                            let documentation = extract_documentation(c)?;

                            Some(Decl {
                                module: module_name.clone(),
                                id,
                                fqid,
                                kind: DeclKind::EnumMember,
                                loc: Some(Location {
                                    range: id_.range(),
                                    selection_range: id_.range(),
                                    uri: Arc::clone(&uri),
                                }),
                                documentation,

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
                "hook_decl" => DeclKind::HookDef(signature()?),
                "event_decl" => DeclKind::EventDef(signature()?),
                "func_decl" => DeclKind::FuncDef(signature()?),
                _ => {
                    return None;
                }
            };

            // If a redef record isn't already fully qualified it either refers to something in the
            // current module which we can find, or it refers to a GLOBAL record. Sanitize the FQID
            // for that.
            if let DeclKind::RedefRecord(_) = &kind {
                if !id_written.contains("::") {
                    fqid = id.clone();
                }
            }

            Some(
                streaming_iterator::once(Decl {
                    module,
                    id,
                    fqid,
                    kind,
                    is_export: Some(in_export(decl)),
                    loc: Some(Location {
                        range,
                        selection_range,
                        uri: Arc::clone(&uri),
                    }),
                    documentation,
                })
                .chain(convert(additional_decls.into_iter())),
            )
        })
        .flatten()
        .chain(convert(
            fn_param_decls(node, Arc::clone(&uri), source).into_iter(),
        ))
        .chain(convert(loop_param_decls(node, &uri, source).into_iter()))
        .cloned()
        .collect()
}

#[instrument]
#[must_use]
pub fn typ(n: Node, source: &[u8]) -> Option<Type> {
    let typ: Node = n.0.child(0).unwrap_or(n.0).into();
    let type_text = typ.utf8_text(source).ok()?;
    typ_from_text(type_text).or_else(|| {
        Some(match type_text {
            "table" => {
                let children = typ.parent()?.named_children("type");
                let y = children
                    .last()
                    .and_then(|x| self::typ(*x, source))
                    .map(Into::into)?;
                let xs = children
                    .iter()
                    .take(children.len() - 1) // If we have `y` this never underflows.
                    .map(|x| self::typ(*x, source))
                    .collect::<Option<_>>()?;
                Type::Table(xs, y)
            }
            "set" => Type::Set(
                typ.parent()?
                    .named_children("type")
                    .into_iter()
                    .map(|x| self::typ(x, source))
                    .collect::<Option<_>>()?,
            ),
            "list" => Type::List(
                typ.parent()?
                    .named_child("type")
                    .and_then(|x| self::typ(x, source))
                    .map(Into::into)?,
            ),
            "vector" => Type::Vector(
                typ.parent()?
                    .named_child("type")
                    .and_then(|x| self::typ(x, source))
                    .map(Into::into)?,
            ),
            "file" => Type::File(
                typ.parent()?
                    .named_child("type")
                    .and_then(|x| self::typ(x, source))
                    .map(Into::into)?,
            ),
            "opaque" => Type::Opaque(
                typ.parent()?
                    .named_child("id")
                    .and_then(|x| self::typ(x, source))
                    .map(Into::into)?,
            ),
            _ => Type::Id(n.utf8_text(source).ok()?.into()),
        })
    })
}

/// Try to get the cast target type from an expr in `n` assuming it holds `_ as @type`.
pub(crate) fn typ_from_cast(n: Node, source: &[u8]) -> Option<Type> {
    static QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        tree_sitter::Query::new(&language_zeek(), r#"(expr (expr) "as" (type)@typ)"#)
            .expect("invalid query")
    });

    let c_typ = QUERY
        .capture_index_for_name("typ")
        .expect("typ should be captured");

    tree_sitter::QueryCursor::new()
        .matches(&QUERY, n.0, source)
        .filter_map(|c| c.nodes_for_capture_index(c_typ).next().map(Node::from))
        .next()
        .and_then(|t| typ(*t, source))
}

fn typ_from_text(text: &str) -> Option<Type> {
    Some(match text {
        "addr" => Type::Addr,
        "any" => Type::Any,
        "bool" => Type::Bool,
        "count" => Type::Count,
        "double" => Type::Double,
        "int" => Type::Int,
        "interval" => Type::Interval,
        "string" => Type::String,
        "subnet" => Type::Subnet,
        "pattern" => Type::Pattern,
        "port" => Type::Port,
        "time" => Type::Time,
        "timer" => Type::Timer,
        _ => return None,
    })
}

#[instrument]
#[must_use]
fn modules(node: Node, uri: Arc<Uri>, source: &[u8]) -> FxHashSet<Decl> {
    static QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        tree_sitter::Query::new(&language_zeek(), "(module_decl (id)@id)").expect("invalid query")
    });

    let c_id = QUERY
        .capture_index_for_name("id")
        .expect("id should be captured");

    tree_sitter::QueryCursor::new()
        .matches(&QUERY, node.0, source)
        .filter_map(|c| {
            let node_id = c.nodes_for_capture_index(c_id).next()?;
            let id = node_id.utf8_text(source).ok()?;
            Some(Decl {
                module: ModuleId::None,
                id: id.into(),
                fqid: id.into(),
                kind: DeclKind::Module,
                is_export: None,
                loc: None,
                documentation: format!("```zeek\n{id}\n```").as_str().into(),
            })
        })
        .cloned()
        .collect()
}

/// Helper to compute a module ID from a given string.
fn compute_module_id(id: &str) -> ModuleId {
    match id {
        "GLOBAL" => ModuleId::Global,
        "" => ModuleId::None,
        _ => ModuleId::String(id.into()),
    }
}

/// Compute the module a node is in.
#[must_use]
fn parent_module(node: Node, source: &[u8]) -> Option<ModuleId> {
    let Some(n) = node.parent() else {
        return Some(ModuleId::None);
    };

    if n.kind() == "source_file" {
        // Found a source file. Now find the most recent
        // module decl when looking backwards from `node`.
        let Some(m) = n
            .named_children("module_decl")
            .iter()
            .filter(|m| m.range().end < node.range().start)
            .min_by_key(|m| node.0.range().start_byte - m.0.range().end_byte)
            .and_then(|m| {
                Some(compute_module_id(
                    m.named_children_not("nl")
                        .into_iter()
                        .next()?
                        .utf8_text(source)
                        .ok()?,
                ))
            })
        else {
            return Some(ModuleId::None);
        };

        return Some(m);
    }

    // Go one level higher.
    parent_module(n, source)
}

/// Extract declarations for function parameters on the given node.
#[instrument]
pub fn fn_param_decls(node: Node, uri: Arc<Uri>, source: &[u8]) -> FxHashSet<Decl> {
    match node.kind() {
        "func_decl" | "hook_decl" | "event_decl" => {}
        _ => return FxHashSet::default(),
    }

    // Synthesize declarations for function arguments. Ideally the grammar would expose
    // these directly.
    let Some(func_params) = node.named_child("func_params") else {
        return FxHashSet::default();
    };

    let Some(formal_args) = func_params.named_child("formal_args") else {
        return FxHashSet::default();
    };

    formal_args
        .named_children("formal_arg")
        .into_iter()
        .filter_map(|arg| {
            let arg_id_ = arg.named_child("id")?;
            let arg_id = arg_id_.utf8_text(source).ok()?;

            Some(Decl {
                module: ModuleId::None,
                id: arg_id.into(),
                fqid: arg_id.into(),
                kind: DeclKind::Variable,
                is_export: None,
                loc: Some(Location {
                    range: arg_id_.range(),
                    selection_range: arg.range(),
                    uri: Arc::clone(&uri),
                }),
                documentation: format!("```zeek\n{}\n```", arg.utf8_text(source).ok()?)
                    .as_str()
                    .into(),
            })
        })
        .collect()
}

/// Extract for loop parameters on the given node.
#[instrument]
fn loop_param_decls(node: Node, uri: &Arc<Uri>, source: &[u8]) -> FxHashSet<Decl> {
    static QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        tree_sitter::Query::new(
            &language_zeek(),
            r#"
        (for
          [
              ("[" . ( (id)@key . ","? )* . "]" . (id)?@value)
              ( (id)@idx . ","? )*
          ]
          .
          "in"
          .
          (expr)@init
        )
        "#,
        )
        .expect("invalid query")
    });

    let c_idx = QUERY
        .capture_index_for_name("idx")
        .expect("idx should be captured");

    let c_key = QUERY
        .capture_index_for_name("key")
        .expect("key should be captured");

    let c_value = QUERY
        .capture_index_for_name("value")
        .expect("value should be captured");

    let c_init = QUERY
        .capture_index_for_name("init")
        .expect("init should be captured");

    tree_sitter::QueryCursor::new()
        .matches(&QUERY, node.0, source)
        .filter_map(|c| {
            let init = c
                .nodes_for_capture_index(c_init)
                .next()
                .and_then(|n| n.utf8_text(source).ok())?;

            let idx = c
                .nodes_for_capture_index(c_idx)
                .enumerate()
                .map(|(i, n)| (n, Index::Loop(i)));

            let key = c
                .nodes_for_capture_index(c_key)
                .enumerate()
                .map(|(i, n)| (n, Index::Key(i)));

            let value = c
                .nodes_for_capture_index(c_value)
                .map(|n| (n, Index::Value));

            Some(
                idx.chain(key)
                    .chain(value)
                    .filter_map(|(n, kind)| {
                        let n: Node = n.into();

                        let id: Str = n.utf8_text(source).ok()?.into();

                        let documentation = match kind {
                            Index::Loop(i) => format!("Index {i} of `{init}`"),
                            Index::Key(i) => format!("Key {i} of `{init}`"),
                            Index::Value => format!("Value of `{init}`"),
                        }
                        .into();

                        let kind = DeclKind::Index(kind, init.into());

                        Some(Decl {
                            module: ModuleId::None,
                            id: id.clone(),
                            fqid: id,
                            kind,
                            is_export: None,
                            loc: Some(Location {
                                range: n.range(),
                                selection_range: n.range(),
                                uri: Arc::clone(uri),
                            }),
                            documentation,
                        })
                    })
                    .collect(),
            )
        })
        .next()
        .cloned()
        .unwrap_or_default()
}

#[instrument]
fn loads_raw<'a>(node: Node, source: &'a str) -> Vec<&'a str> {
    static QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        tree_sitter::Query::new(&language_zeek(), "(\"@load\") (file)@file").expect("invalid query")
    });

    static C_FILE: LazyLock<u32> = LazyLock::new(|| {
        QUERY
            .capture_index_for_name("file")
            .expect("file should be captured")
    });

    tree_sitter::QueryCursor::new()
        .matches(&QUERY, node.0, source.as_bytes())
        .filter_map(|c| c.nodes_for_capture_index(*C_FILE).next())
        .filter_map(|f| f.utf8_text(source.as_bytes()).ok())
        .cloned()
        .collect()
}

#[salsa::query_group(QueryStorage)]
pub trait Query: Parse {
    #[must_use]
    fn decls(&self, uri: Arc<Uri>) -> Arc<[Decl]>;

    #[must_use]
    fn loads(&self, uri: Arc<Uri>) -> Arc<[Str]>;

    #[must_use]
    fn function_calls(&self, uri: Arc<Uri>) -> Arc<[FunctionCall]>;

    #[must_use]
    fn untyped_var_decls(&self, uri: Arc<Uri>) -> Arc<[Decl]>;

    #[must_use]
    fn ids(&self, uri: Arc<Uri>) -> Arc<[NodeLocation]>;
}

#[instrument(skip(db))]
fn decls(db: &dyn Query, uri: Arc<Uri>) -> Arc<[Decl]> {
    let Some(source) = db.source(Arc::clone(&uri)) else {
        return Arc::default();
    };

    let Some(tree) = db.parse(Arc::clone(&uri)) else {
        return Arc::default();
    };

    let decls = decls_(tree.root_node(), Arc::clone(&uri), source.as_bytes());
    let modules = modules(tree.root_node(), uri, source.as_bytes());

    Arc::from(
        decls
            .into_iter()
            .chain(modules.into_iter())
            .unique()
            .collect::<Vec<_>>(),
    )
}

#[instrument(skip(db))]
fn loads(db: &dyn Query, uri: Arc<Uri>) -> Arc<[Str]> {
    let Some(tree) = db.parse(Arc::clone(&uri)) else {
        return Arc::default();
    };

    let Some(source) = db.source(uri) else {
        return Arc::default();
    };

    Arc::from(
        loads_raw(tree.root_node(), &source)
            .iter()
            .map(ToString::to_string)
            .map(Str::from)
            .collect::<Vec<_>>(),
    )
}

#[instrument(skip(db))]
fn function_calls(db: &dyn Query, uri: Arc<Uri>) -> Arc<[FunctionCall]> {
    // Match things which look like function calls with arguments.
    static QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        tree_sitter::Query::new(&language_zeek(), "(expr (id) (expr_list))@fn")
            .expect("invalid query")
    });

    let Some(tree) = db.parse(Arc::clone(&uri)) else {
        return Arc::default();
    };

    let Some(source) = db.source(Arc::clone(&uri)) else {
        return Arc::default();
    };

    let c_fn = QUERY
        .capture_index_for_name("fn")
        .expect("call should be captured");

    Arc::from(
        tree_sitter::QueryCursor::new()
            .matches(&QUERY, tree.root_node().0, source.as_bytes())
            .filter_map(|c| {
                let (f, args) = c.nodes_for_capture_index(c_fn).next().and_then(|n| {
                    let n: Node = n.into();
                    let args = n
                        .named_child("expr_list")?
                        .named_children("expr")
                        .into_iter()
                        .map(|a| NodeLocation::from_node(Arc::clone(&uri), a))
                        .collect::<Vec<_>>();
                    Some((NodeLocation::from_node(Arc::clone(&uri), n), args))
                })?;

                Some(FunctionCall { f, args })
            })
            .cloned()
            .collect::<Vec<_>>(),
    )
}

#[instrument(skip(db))]
fn untyped_var_decls(db: &dyn Query, uri: Arc<Uri>) -> Arc<[Decl]> {
    // Match untyped var and const decls
    static QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        tree_sitter::Query::new(
            &language_zeek(),
            "[(const_decl) (option_decl) (var_decl)] @var",
        )
        .expect("invalid query")
    });

    let Some(tree) = db.parse(Arc::clone(&uri)) else {
        return Arc::default();
    };

    let Some(source) = db.source(Arc::clone(&uri)) else {
        return Arc::default();
    };

    let source = source.as_bytes();

    let c_var = QUERY
        .capture_index_for_name("var")
        .expect("call should be captured");

    Arc::from(
        tree_sitter::QueryCursor::new()
            .matches(&QUERY, tree.root_node().0, source)
            .filter_map(|m| {
                let m: Node = m.nodes_for_capture_index(c_var).next()?.into();

                // Reject decls which have a type.
                if m.named_child("type").is_some() {
                    return None;
                }

                let kind = match m.kind() {
                    "const_decl" => DeclKind::Const,
                    "var_decl" => DeclKind::Variable,
                    "option_decl" => DeclKind::Option,
                    _ => return None,
                };

                let empty: Str = "".into();

                // Definite abuse of the Decl type since we really only transport out locations. We
                // use `range` for the range of the decl, and `selection_range` for the range of
                // the identifier.
                Some(Decl {
                    module: ModuleId::None,
                    id: empty.clone(),
                    fqid: empty.clone(),
                    kind,
                    is_export: None,
                    loc: Some(Location {
                        range: m.range(),
                        selection_range: m.named_child("id")?.range(),
                        uri: Arc::clone(&uri),
                    }),
                    documentation: empty,
                })
            })
            .cloned()
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::needless_pass_by_value)]
fn ids(db: &dyn Query, uri: Arc<Uri>) -> Arc<[NodeLocation]> {
    // Match any id.
    static QUERY: LazyLock<tree_sitter::Query> = LazyLock::new(|| {
        tree_sitter::Query::new(&language_zeek(), "(id)@id").expect("invalid query")
    });

    let Some(tree) = db.parse(Arc::clone(&uri)) else {
        return Arc::default();
    };

    let Some(source) = db.source(Arc::clone(&uri)) else {
        return Arc::default();
    };

    let source = source.as_bytes();

    let c_id = QUERY
        .capture_index_for_name("id")
        .expect("id should be captured");

    Arc::from(
        tree_sitter::QueryCursor::new()
            .matches(&QUERY, tree.root_node().0, source)
            .filter_map(|m| {
                let m = m.nodes_for_capture_index(c_id).next()?;
                Some(NodeLocation::from_node(Arc::clone(&uri), m.into()))
            })
            .cloned()
            .collect::<Vec<_>>(),
    )
}

/// Extracts pre and post zeekygen comments for the given node.
fn zeekygen_comments(x: Node, source: &[u8]) -> Option<Str> {
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
        Some(markdownify(&docs.iter().join("\n")))
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use std::sync::Arc;

    use crate::{lsp::TestDatabase, parse::Parse, query::Node, Files};
    use insta::assert_debug_snapshot;
    use itertools::Itertools;
    use tower_lsp_server::{
        lsp_types::{Position, Uri},
        UriExt,
    };

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
              event zeek_init() { local x=1;
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
            let mut db = TestDatabase::default();
            let uri = Arc::new(Uri::from_file_path("/foo/bar.zeek").unwrap());

            db.add_file((*uri).clone(), source);
            db.0.parse(uri)
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
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/foo/bar.zeek").unwrap());
        db.add_file((*uri).clone(), SOURCE);

        let tree = db.0.parse(uri.clone()).expect("cannot parse");

        let decls_ = |n: Node| super::decls_(n, uri.clone(), SOURCE.as_bytes());

        // Test decls reachable from the root node. This is used e.g., to figure out what decls are
        // available in a module. This should not contain e.g., function-scope decls.
        let root_decls: Vec<_> = decls_(tree.root_node()).into_iter().sorted().collect();
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
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "module x;
export {
global f1: function();
global foo::f2: function();
global GLOBAL::f3: function();
}",
        );

        let decls = db.0.decls(uri);
        let mut decls = decls.iter().collect::<Vec<_>>();
        decls.sort_by(|a, b| a.loc.cmp(&b.loc));

        assert_debug_snapshot!(decls);
    }

    #[test]
    fn in_export() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/foo/bar.zeek").unwrap());
        db.add_file((*uri).clone(), SOURCE);
        let tree = db.0.parse(uri).unwrap();

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
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/tmp/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "module x;
function f1(x: count, y: string) {
    # Inside.
}",
        );

        let db = db.snapshot();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();
        let source = db.source(uri.clone()).unwrap();

        let in_f1 = root
            .named_descendant_for_position(Position::new(1, 0))
            .unwrap();
        assert_eq!(in_f1.kind(), "func_decl");
        let mut decls = super::fn_param_decls(in_f1, uri.clone(), source.as_bytes())
            .into_iter()
            .collect::<Vec<_>>();
        decls.sort_by(|a, b| a.loc.cmp(&b.loc));
        assert_debug_snapshot!(decls);

        let outside_f1 = root
            .named_descendant_for_position(Position::new(0, 0))
            .unwrap();
        assert_eq!(outside_f1.kind(), "module_decl");
        assert!(super::fn_param_decls(outside_f1, uri, source.as_bytes()).is_empty());
    }

    #[test]
    fn fn_like_decls() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "
global fn: function(n: count): string;
global ev: event(c: connection, os: endpoint_stats, rs: endpoint_stats);
global hk: hook(info: Info, s: Seen, items: set[Item]);",
        );

        let db = db.snapshot();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();
        let source = db.source(uri.clone()).unwrap();

        assert_debug_snapshot!(super::decls_(root, uri, source.as_bytes()));
    }

    #[test]
    fn markdown_docs() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
            "## With `link <http://example.com>`__
function f() {}",
        );

        let db = db.snapshot();
        let tree = db.parse(uri.clone()).unwrap();
        let root = tree.root_node();
        let source = db.source(uri.clone()).unwrap();

        let decls = super::decls_(root, uri, source.as_bytes());
        assert_eq!(decls.len(), 1);
        let d = decls.iter().next().unwrap();
        assert_eq!(d.id, "f");
        assert_eq!(
            d.documentation.lines().next(),
            Some("With [link](http://example.com)")
        );
    }
}
