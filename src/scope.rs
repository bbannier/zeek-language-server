use std::sync::Arc;

use tower_lsp_server::ls_types::{Position, Range};

use crate::{
    Db, InternedStr, InternedUri,
    ast::is_redef,
    query::{self, Decl, ModuleId, Node},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScopeId(usize);

#[derive(Debug, Clone, PartialEq)]
struct ScopeData {
    range: Range,
    parent: Option<ScopeId>,
    decls: Vec<Decl>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScopeGraph {
    scopes: Vec<ScopeData>,
    module_transitions: Vec<(Position, ModuleId)>,
}

impl ScopeGraph {
    fn add_scope(&mut self, range: Range, parent: Option<ScopeId>) -> ScopeId {
        let id = ScopeId(self.scopes.len());
        self.scopes.push(ScopeData {
            range,
            parent,
            decls: Vec::new(),
        });
        id
    }

    fn add_decls(&mut self, scope: ScopeId, decls: impl IntoIterator<Item = Decl>) {
        self.scopes[scope.0].decls.extend(decls);
    }

    fn scope_at(&self, pos: Position) -> Option<ScopeId> {
        self.scopes
            .iter()
            .enumerate()
            .filter(|(_, s)| s.range.start <= pos && pos <= s.range.end)
            .max_by(|(_, a), (_, b)| {
                a.range
                    .start
                    .cmp(&b.range.start)
                    .then(b.range.end.cmp(&a.range.end))
            })
            .map(|(i, _)| ScopeId(i))
    }

    #[must_use]
    pub fn module_at(&self, pos: Position) -> ModuleId {
        self.module_transitions
            .iter()
            .rev()
            .find(|(start, _)| *start <= pos)
            .map_or(ModuleId::None, |(_, m)| m.clone())
    }

    #[must_use]
    pub fn resolve_local(&self, id: InternedStr, pos: Position) -> Vec<&Decl> {
        let Some(scope) = self.scope_at(pos) else {
            return Vec::new();
        };

        let mut result = Vec::new();
        let mut current = Some(scope);

        while let Some(s) = current {
            let data = &self.scopes[s.0];
            result.extend(
                data.decls
                    .iter()
                    .filter(|d| d.id == id || d.fqid == id)
                    .filter(|d| d.loc.as_ref().is_some_and(|loc| loc.range.start <= pos)),
            );

            if result.iter().any(|d| !is_redef(d)) {
                break;
            }

            current = data.parent;
        }

        result
    }
}

#[salsa::tracked(returns(clone), unsafe(non_salsa_values))]
pub fn scope_graph(db: &dyn Db, uri: InternedUri) -> Arc<ScopeGraph> {
    let Some(tree) = crate::parse::parse(db, uri) else {
        return Arc::new(ScopeGraph::default());
    };
    let Some(source) = crate::source(db, uri) else {
        return Arc::new(ScopeGraph::default());
    };

    let mut graph = ScopeGraph::default();
    walk(
        db,
        tree.root_node(),
        uri,
        source.as_bytes(),
        None,
        &mut graph,
    );
    Arc::new(graph)
}

fn module_from_decl(node: Node, source: &[u8]) -> Option<ModuleId> {
    let name = node.named_child_not("nl")?.utf8_text(source).ok()?;
    Some(query::compute_module_id(name))
}

fn walk(
    db: &dyn Db,
    node: Node,
    uri: InternedUri,
    source: &[u8],
    parent_scope: Option<ScopeId>,
    graph: &mut ScopeGraph,
) {
    let mut current_scope = parent_scope;

    let decls: Vec<Decl> = query::decls_(db, node, uri, source)
        .into_iter()
        .chain(query::fn_param_decls(db, node, uri, source))
        .chain(query::loop_param_decls(db, node, uri, source))
        .collect();

    if !decls.is_empty() {
        let scope = graph.add_scope(node.range(), parent_scope);
        graph.add_decls(scope, decls);
        current_scope = Some(scope);
    }

    let mut cursor = node.0.walk();
    for child in node.0.children(&mut cursor) {
        let child: Node = child.into();
        if child.kind() == "module_decl"
            && let Some(module) = module_from_decl(child, source)
        {
            graph.module_transitions.push((child.range().end, module));
        }
        walk(db, child, uri, source, current_scope, graph);
    }
}
