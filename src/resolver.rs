use std::sync::Arc;

use salsa::Snapshot;
use stack_graphs::{
    arena::Handle,
    graph::{File, StackGraph},
};
use tower_lsp::lsp_types::{Location, Position, Range, TextDocumentPositionParams, Url};
use tracing::instrument;
use tree_sitter_stack_graphs::{NoCancellation, StackGraphLanguage, Variables};

use crate::{ast::Ast, lsp::Database, parse::Parse, Files};

fn language() -> Option<StackGraphLanguage> {
    let config = tree_sitter_stack_graphs_zeek::language_configuration(&NoCancellation).ok()?;
    StackGraphLanguage::from_str(
        config.language,
        tree_sitter_stack_graphs_zeek::STACK_GRAPHS_TSG_SOURCE,
    )
    .ok()
}

#[instrument]
fn make_graph(state: &Snapshot<Database>, uri: Arc<Url>) -> Option<(StackGraph, Handle<File>)> {
    let mut graph = StackGraph::new();

    let file = graph.add_file(uri.path()).ok()?;
    let globals = Variables::new();

    let source = state.source(uri);

    language()?
        .build_stack_graph_into(&mut graph, file, &source, &globals, &NoCancellation)
        .ok()?;

    Some((graph, file))
}

#[instrument]
pub fn references(
    state: Snapshot<Database>,
    position: TextDocumentPositionParams,
) -> Option<Vec<Location>> {
    let uri = Arc::new(position.text_document.uri);

    let (mut graph, file) = make_graph(&state, uri.clone())?;
    for l in state.loaded_files(uri.clone()).as_ref() {
        let (g, _) = make_graph(&state, l.clone())?;
        graph.add_from_graph(&g).ok()?;
    }

    let tree = state.parse(uri.clone()).unwrap();
    let root = tree.root_node();

    let node = root.descendant_for_position(position.position)?;
    let anchor = graph.nodes_for_file(file).find(|n| {
        let s = match graph.source_info(*n) {
            Some(s) => &s.span,
            None => return false,
        };

        let range = Range::new(
            Position::new(
                u32::try_from(s.start.line).unwrap(),
                u32::try_from(s.start.column.utf8_offset).unwrap(),
            ),
            Position::new(
                u32::try_from(s.end.line).unwrap(),
                u32::try_from(s.end.column.utf8_offset).unwrap(),
            ),
        );

        range == node.range()
    })?;

    let nodes = vec![anchor];
    let anchor = &graph[anchor];

    let mut results = Vec::new();
    let mut paths = stack_graphs::paths::Paths::new();
    paths
        .find_all_paths(
            &graph,
            nodes,
            &stack_graphs::NoCancellation,
            |graph, _paths, path| {
                for n in [path.start_node, path.end_node] {
                    let node = &graph[n];

                    if node.symbol() != anchor.symbol() {
                        continue;
                    }

                    dbg!(node.display(graph).to_string());

                    let uri = match node.file() {
                        Some(f) => Url::from_file_path(graph[f].name()).unwrap(),
                        None => continue,
                    };

                    if let Some(s) = graph.source_info(n) {
                        let range = Range::new(
                            Position::new(
                                u32::try_from(s.span.start.line).unwrap(),
                                u32::try_from(s.span.start.column.utf8_offset).unwrap(),
                            ),
                            Position::new(
                                u32::try_from(s.span.end.line).unwrap(),
                                u32::try_from(s.span.end.column.utf8_offset).unwrap(),
                            ),
                        );
                        results.push(Location { uri, range });
                    }
                }
            },
        )
        .ok()?;

    Some(results)
}

// Path stitching:
//
// - per-file graph, then stitch with `StackGraph::add_from_graph`
// - preconstruct partial paths:
//
//  ```rust
//  let mut partials = PartialPaths::new();;
//  let mut database = Database::new();
//  partials
//    .find_all_partial_paths_in_file(graph, file, &NoCancellation, |graph, partials, path| {
//        database.add_partial_path(graph, partials, path);
//    })
//    .expect("should never be cancelled");
//  ```
