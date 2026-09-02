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
    pub fn modules(&self) -> &[(Position, ModuleId)] {
        &self.module_transitions
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
    pub fn all_local_decls(&self, pos: Position) -> Vec<&Decl> {
        let Some(scope) = self.scope_at(pos) else {
            return Vec::new();
        };

        let mut result = Vec::new();
        let mut current = Some(scope);

        while let Some(s) = current {
            let data = &self.scopes[s.0];
            result.extend(&data.decls);
            current = data.parent;
        }

        result
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
pub fn module_transitions(db: &dyn Db, uri: InternedUri) -> Arc<Vec<(Position, ModuleId)>> {
    let Some(tree) = crate::parse::parse(db, uri) else {
        return Arc::default();
    };
    let Some(source) = crate::source(db, uri) else {
        return Arc::default();
    };

    let mut transitions = Vec::new();
    for child in tree.root_node().named_children("module_decl") {
        if let Some(name) = child.named_child_not("nl")
            && let Ok(text) = name.utf8_text(source.as_bytes())
        {
            transitions.push((child.range().end, query::compute_module_id(text)));
        }
    }
    Arc::new(transitions)
}

#[salsa::tracked(returns(clone), unsafe(non_salsa_values))]
pub fn scope_graph(db: &dyn Db, uri: InternedUri) -> Arc<ScopeGraph> {
    let Some(tree) = crate::parse::parse(db, uri) else {
        return Arc::new(ScopeGraph::default());
    };
    let Some(source) = crate::source(db, uri) else {
        return Arc::new(ScopeGraph::default());
    };

    let transitions = module_transitions(db, uri);
    let mut graph = ScopeGraph {
        module_transitions: (*transitions).clone(),
        ..ScopeGraph::default()
    };
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

fn walk(
    db: &dyn Db,
    node: Node,
    uri: InternedUri,
    source: &[u8],
    parent_scope: Option<ScopeId>,
    graph: &mut ScopeGraph,
) {
    let mut current_scope = parent_scope;

    if node.0.child_count() > 0 {
        let modules = &graph.module_transitions;
        let decls: Vec<Decl> = query::decls_(db, node, uri, source, Some(modules))
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
            walk(db, child.into(), uri, source, current_scope, graph);
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use std::sync::Arc;

    use tower_lsp_server::ls_types::{Position, Uri};

    use crate::lsp::TestDatabase;
    use crate::query::ModuleId;

    fn graph(source: &str) -> (TestDatabase, Arc<super::ScopeGraph>) {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/test.zeek").unwrap());
        db.add_file((*uri).clone(), source);
        let uri = crate::uri_db(&db.0, uri);
        let graph = super::scope_graph(&db.0, uri);
        (db, graph)
    }

    #[test]
    fn scope_nesting() {
        let (_, g) = graph(
            "global x = 0;
             event e() { local y = 1; }",
        );
        assert!(
            g.scopes.len() >= 2,
            "expected at least file and function scopes"
        );

        let file_pos = Position::new(0, 0);
        let func_pos = Position::new(1, 25);

        let file_decls: Vec<_> = g.all_local_decls(file_pos).iter().map(|d| d.id).collect();
        assert!(file_decls.iter().any(|id| id.as_str() == "x"));

        let func_decls: Vec<_> = g.all_local_decls(func_pos).iter().map(|d| d.id).collect();
        assert!(func_decls.iter().any(|id| id.as_str() == "y"));
        assert!(func_decls.iter().any(|id| id.as_str() == "x"));
    }

    #[test]
    fn module_transitions() {
        let (_, g) = graph(
            "module foo;
             global x = 0;
             module bar;
             global y = 0;",
        );
        assert_eq!(g.module_at(Position::new(0, 0)), ModuleId::None);
        assert_eq!(
            g.module_at(Position::new(1, 0)),
            ModuleId::String("foo".into())
        );
        assert_eq!(
            g.module_at(Position::new(3, 0)),
            ModuleId::String("bar".into())
        );
    }

    #[test]
    fn resolve_local_filters_by_name_and_position() {
        let (_, g) = graph(
            "global x = 0;
             global y = 1;",
        );

        let pos = Position::new(1, 14);
        let results: Vec<_> = g
            .resolve_local("x".into(), pos)
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        assert_eq!(results, vec!["x"]);
    }

    #[test]
    fn func_params_in_scope() {
        let (_, g) = graph("event e(x: count) { local y = x; }");

        let body_pos = Position::new(0, 25);
        let decls: Vec<_> = g.all_local_decls(body_pos).iter().map(|d| d.id).collect();
        assert!(
            decls.iter().any(|id| id.as_str() == "x"),
            "param x should be visible"
        );
        assert!(
            decls.iter().any(|id| id.as_str() == "y"),
            "local y should be visible"
        );
    }

    #[test]
    fn for_loop_params() {
        let (_, g) = graph(
            "event e() {
                 local t: table[string] of count;
                 for (k, v in t) { }
             }",
        );

        let loop_pos = Position::new(2, 35);
        let decls: Vec<_> = g.all_local_decls(loop_pos).iter().map(|d| d.id).collect();
        assert!(
            decls.iter().any(|id| id.as_str() == "k"),
            "loop key should be visible"
        );
    }

    #[test]
    fn empty_file() {
        let (_, g) = graph("");
        assert!(g.scopes.is_empty());
        assert!(g.module_transitions.is_empty());
        assert!(g.all_local_decls(Position::new(0, 0)).is_empty());
        assert_eq!(g.module_at(Position::new(0, 0)), ModuleId::None);
    }
}
