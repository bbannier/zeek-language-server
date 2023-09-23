use rustc_hash::FxHashSet;
use std::sync::Arc;

use crate::{
    ast::{self, Ast},
    lsp::Database,
    parse::Parse,
    query::{self, Decl, DeclKind, Node, NodeLocation, Query},
    Files,
};

use itertools::Itertools;
use tower_lsp::lsp_types::{
    CompletionItem, CompletionItemKind, CompletionItemLabelDetails, CompletionParams,
    CompletionResponse, Documentation, MarkupContent, Position, Url,
};
use tree_sitter_zeek::KEYWORDS;

pub(crate) fn complete(state: &Database, params: CompletionParams) -> Option<CompletionResponse> {
    let uri = Arc::new(params.text_document_position.text_document.uri);
    let position = params.text_document_position.position;

    let source = state.source(uri.clone())?;

    let Some(tree) = state.parse(uri.clone()) else {
        return None;
    };

    // Get the node directly under the cursor as a starting point.
    let root = tree.root_node();
    let Some(mut node) = root.descendant_for_position(position) else {
        return None;
    };

    let text = completion_text(node, &source);

    // If the node has no interesting text try to find an earlier node with text.
    while node
        .utf8_text(source.as_bytes())
        .ok()
        // The grammar might expose newlines as AST nodes. Such nodes should be ignored for completion.
        .map(str::trim)
        // The grammar might expose `$` or `?$` in a node. Strip it away. This also takes care of
        // explicit nodes for just the field access or check.
        .map(|s| s.replace(['$', '?'], ""))
        .map_or(0, |s| s.len())
        == 0
    {
        // If we are completing at the end of a line the end of the node will be on the next
        // line. Instead search the next node _before the_start_ of the current node.
        let start = node.range().start.character;
        if start == 0 {
            break;
        }

        node = match root.descendant_for_position(Position {
            character: start - 1,
            ..position
        }) {
            Some(n) => n,
            None => break,
        };
    }

    None.or_else(|| {
        // If we are completing after `$` try to return all fields for client-side filtering.
        // TODO(bbannier): we should also handle `$` in record initializations.

        let dd_triggered = params
            .context
            .and_then(|ctx| ctx.trigger_character)
            .map_or(false, |c| c == "$");

        let ends_in_dd = root
            .descendant_for_position(Position::new(
                    node.range().end.line,
                    node.range().end.character,
                    ))
            .and_then(|next_node| next_node.utf8_text(source.as_bytes()).ok())
            .map_or(false, |text| text.ends_with('$'));

        let is_partial = !dd_triggered && !ends_in_dd;

        if dd_triggered
            || ends_in_dd
            || node.parent().map_or(false, |p| {
                p.kind() == "field_access" || p.kind() == "field_check"
            }) {
            complete_field(state, node, uri.clone(), is_partial)
        } else {
            None
        }
    }).or_else(||
        // If we are completing a file return valid load patterns.
        if node.kind() == "file" {
            return Some(state
                .possible_loads(uri.clone())
                .iter()
                .map(|load| CompletionItem {
                    label: load.clone(),
                    kind: Some(CompletionItemKind::FILE),
                    ..CompletionItem::default()
                })
                .collect::<Vec<_>>());
        } else {
            None
        }
    ).or_else(||
        // If we are completing a function/event/hook definition complete from declarations.
        if node.kind() == "id" {
            source
                .lines()
                .nth(usize::try_from(node.range().start.line).expect("too many lines"))
                .and_then(|line| {
                    let re = regex::Regex::new(r"^(\w+)\s+\w*").expect("invalid regexp");
                    Some(re.captures(line)?.get(1)?.as_str())
                }).map(|kind| complete_from_decls(state, uri.clone(), kind))
        } else {
            None
        }
    ).or_else(||
        // We are just completing some arbitrary identifier at this point.
        Some(complete_any(state, root, node, uri))
    )
    .map(|items| items.into_iter().filter(|i|
            text.map_or(true, |t| rust_fuzzy_search::fuzzy_compare(&i.label.to_lowercase(), t) > 0.0)
            ).collect::<Vec<_>>())
    .map(CompletionResponse::from)
}

/// Complete a field after `$` or `?$`
///
/// # Arguments
///
/// * `state` - global database
/// * `node` - node to complete
/// * `uri` - document URI
/// * `is_partial` - whether the field identifier is already partial present
fn complete_field(
    state: &Database,
    mut node: Node,
    uri: Arc<Url>,
    is_partial: bool,
) -> Option<Vec<CompletionItem>> {
    // If we are completing with something after the `$` (e.g., `foo$a`), instead
    // obtain the stem (`foo`) for resolving.
    if is_partial {
        let stem = node
            .parent()
            .filter(|p| p.kind() == "field_access" || p.kind() == "field_check")
            .and_then(|p| p.named_child("expr"));

        // If we have a stem, perform any resolving with it; else use the original node.
        node = stem.unwrap_or(node);
    }

    if let Some(r) = state.resolve(NodeLocation::from_node(uri, node)) {
        let decl = state.typ(r).and_then(|d| match &d.kind {
            // If the decl refers to a field get the decl for underlying its type instead.
            DeclKind::Field => state.typ(d),
            _ => Some(d),
        });

        // Compute completion.
        if let Some(decl) = decl {
            if let DeclKind::Type(fields) = &decl.kind {
                return Some(
                    fields
                        .iter()
                        .map(to_completion_item)
                        .filter_map(|item| {
                            // By default we use FQIDs for completion labels. Since for
                            // record fields this would be e.g., `mod::rec::field` where we
                            // want just `field`, rework them slightly.
                            let label = item.label.split("::").last()?.to_string();
                            Some(CompletionItem { label, ..item })
                        })
                        .collect::<Vec<_>>(),
                );
            }
        }
    }

    None
}

fn complete_from_decls(state: &Database, uri: Arc<Url>, kind: &str) -> Vec<CompletionItem> {
    state
        .decls(uri.clone())
        .iter()
        .chain(state.implicit_decls().iter())
        .chain(state.explicit_decls_recursive(uri).iter())
        .filter(|d| match &d.kind {
            DeclKind::EventDecl(_) => kind == "event",
            DeclKind::FuncDecl(_) => kind == "function",
            DeclKind::HookDecl(_) => kind == "hook",
            _ => false,
        })
        .unique()
        .filter_map(|d| {
            let item = to_completion_item(d);
            let signature = match &d.kind {
                DeclKind::EventDecl(s) | DeclKind::FuncDecl(s) | DeclKind::HookDecl(s) => Some(
                    s.args
                        .iter()
                        .filter_map(|d| {
                            let Some(loc) = &d.loc else { return None };
                            let tree = state.parse(loc.uri.clone())?;
                            let source = state.source(loc.uri.clone())?;
                            tree.root_node()
                                .named_descendant_for_point_range(loc.selection_range)?
                                .utf8_text(source.as_bytes())
                                .map(String::from)
                                .ok()
                        })
                        .join(", "),
                ),
                _ => None,
            }?;

            Some(CompletionItem {
                insert_text: Some(format!("{id}({signature}) {{}}", id = item.label)),
                label: item.label,
                label_details: Some(CompletionItemLabelDetails {
                    detail: Some(format!("({signature})")),
                    ..CompletionItemLabelDetails::default()
                }),
                ..item
            })
        })
        .collect::<Vec<_>>()
}

fn complete_any(
    state: &Database,
    root: Node,
    mut node: Node,
    uri: Arc<Url>,
) -> Vec<CompletionItem> {
    let Some(source) = state.source(uri.clone()) else {
        return Vec::new();
    };

    let mut items = FxHashSet::default();

    let current_module = root
        .named_child("module_decl")
        .and_then(|m| m.named_child("id"))
        .and_then(|id| id.utf8_text(source.as_bytes()).ok());

    let text_at_completion = completion_text(node, &source);

    loop {
        for d in query::decls_(node, uri.clone(), source.as_bytes()) {
            // Slightly fudge the ID we use for local declarations by removing the current
            // module from the FQID.
            let fqid = match current_module {
                Some(mid) => {
                    let id = &*d.fqid;
                    id.strip_prefix(&format!("{mid}::")).unwrap_or(id)
                }
                None => &d.fqid,
            }
            .into();
            items.insert(Decl { fqid, ..d });
        }

        node = match node.parent() {
            Some(n) => n,
            None => break,
        };
    }

    let loaded_decls = state.explicit_decls_recursive(uri);
    let implicit_decls = state.implicit_decls();

    let other_decls = loaded_decls
        .iter()
        .chain(implicit_decls.iter())
        .filter(|i| {
            // Filter out redefs since they only add noise.
            !ast::is_redef(i)
        });

    items
        .iter()
        .chain(other_decls)
        .unique()
        .map(to_completion_item)
        // Also send filtered down keywords to the client.
        .chain(KEYWORDS.iter().filter_map(|kw| {
            let should_include = if let Some(text) = text_at_completion {
                text.is_empty()
                    || rust_fuzzy_search::fuzzy_compare(&text.to_lowercase(), &kw.to_lowercase())
                        > 0.0
            } else {
                true
            };

            if should_include {
                Some(CompletionItem {
                    kind: Some(CompletionItemKind::KEYWORD),
                    label: (*kw).to_string(),
                    ..CompletionItem::default()
                })
            } else {
                None
            }
        }))
        .collect::<Vec<_>>()
}

fn to_completion_item(d: &Decl) -> CompletionItem {
    CompletionItem {
        label: d.fqid.to_string(),
        kind: Some(to_completion_item_kind(&d.kind)),
        documentation: Some(Documentation::MarkupContent(MarkupContent {
            kind: tower_lsp::lsp_types::MarkupKind::Markdown,
            value: d.documentation.to_string(),
        })),
        ..CompletionItem::default()
    }
}

fn to_completion_item_kind(kind: &DeclKind) -> CompletionItemKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef | DeclKind::LoopIndex(_, _) => {
            CompletionItemKind::VARIABLE
        }
        DeclKind::Option => CompletionItemKind::PROPERTY,
        DeclKind::Const => CompletionItemKind::CONSTANT,
        DeclKind::Enum(_) | DeclKind::RedefEnum(_) => CompletionItemKind::ENUM,
        DeclKind::Type(_) | DeclKind::RedefRecord(_) => CompletionItemKind::CLASS,
        DeclKind::FuncDecl(_) | DeclKind::FuncDef(_) => CompletionItemKind::FUNCTION,
        DeclKind::HookDecl(_) | DeclKind::HookDef(_) => CompletionItemKind::OPERATOR,
        DeclKind::EventDecl(_) | DeclKind::EventDef(_) => CompletionItemKind::EVENT,
        DeclKind::Field => CompletionItemKind::FIELD,
        DeclKind::EnumMember => CompletionItemKind::ENUM_MEMBER,
    }
}

fn completion_text<'a>(node: Node, source: &'a str) -> Option<&'a str> {
    if node.kind() == "source_file" {
        return None;
    }

    node.utf8_text(source.as_bytes())
        .ok()?
        // This shouldn't happen; if we cannot get the node text there is some UTF-8 error.
        .lines()
        .next()
        .map(str::trim)
        .and_then(|t| if t.is_empty() { None } else { Some(t) })
}

#[cfg(test)]
mod test {
    use insta::assert_debug_snapshot;
    use tower_lsp::lsp_types::{
        CompletionContext, CompletionParams, CompletionResponse, CompletionTriggerKind,
        PartialResultParams, Position, TextDocumentIdentifier, TextDocumentPositionParams, Url,
        WorkDoneProgressParams,
    };

    use crate::{complete::complete, lsp::test::TestDatabase};

    #[test]
    fn field_access() {
        let mut db = TestDatabase::default();

        let uri1 = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri1.clone(),
            "type X: record { abc: count; };
            global foo: X;
            foo$
            ",
        );

        let uri2 = Url::from_file_path("/y.zeek").unwrap();
        db.add_file(
            uri2.clone(),
            "type X: record { abc: count; };
            global foo: X;
            foo?$
            ",
        );

        let uri = uri1;
        {
            let params = CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    position: Position::new(2, 16),
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            };

            assert_debug_snapshot!(complete(
                &db.0,
                CompletionParams {
                    context: None,
                    ..params.clone()
                }
            ));

            assert_debug_snapshot!(complete(
                &db.0,
                CompletionParams {
                    context: Some(CompletionContext {
                        trigger_kind: CompletionTriggerKind::TRIGGER_CHARACTER,
                        trigger_character: Some("$".into()),
                    },),
                    ..params
                }
            ));
        }

        let uri = uri2;
        {
            let params = CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    position: Position::new(2, 17),
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            };

            assert_debug_snapshot!(complete(
                &db.0,
                CompletionParams {
                    context: None,
                    ..params.clone()
                }
            ));

            assert_debug_snapshot!(complete(
                &db.0,
                CompletionParams {
                    context: Some(CompletionContext {
                        trigger_kind: CompletionTriggerKind::TRIGGER_CHARACTER,
                        trigger_character: Some("$".into()),
                    },),
                    ..params
                }
            ));
        }
    }

    #[test]
    fn field_access_chained() {
        let mut db = TestDatabase::default();
        let uri = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
        type X: record { n: count; };
        type Y: record { x: X; };
        event foo(y: Y) {
            y$x$
        }
        ",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(4, 16),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));
    }

    #[test]
    fn field_access_partial() {
        let mut db = TestDatabase::default();

        let uri1 = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri1.clone(),
            "type X: record { abc: count; };
            global foo: X;
            foo$a
            ",
        );

        let uri2 = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri2.clone(),
            "type X: record { abc: count; };
            global foo: X;
            foo?$a
            ",
        );

        {
            let uri = uri1;
            let position = Position::new(2, 17);
            let params = CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    position,
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            };
            assert_debug_snapshot!(complete(
                &db.0,
                CompletionParams {
                    context: None,
                    ..params
                }
            ));
        }

        {
            let uri = uri2;
            let position = Position::new(2, 17);
            let params = CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    position,
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            };
            assert_debug_snapshot!(complete(
                &db.0,
                CompletionParams {
                    context: None,
                    ..params
                }
            ));
        }
    }

    #[test]
    fn field_access_chained_partial() {
        let mut db = TestDatabase::default();
        let uri = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
        type X: record { abc: count; };
        type Y: record { x: X; };
        event foo(y: Y) {
            y$x$a
        }
        ",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(4, 17),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));
    }

    #[test]
    fn referenced_field_access() {
        let mut db = TestDatabase::default();
        let uri = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
        type X: record { abc: count; };
        type Y: record { x: X; };
        event foo(y: Y) {
            local x = y$x;
            x$
        }",
        );

        let x = complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(5, 14),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        )
        .unwrap();

        match x {
            CompletionResponse::Array(xs) => assert_eq!(xs.len(), 1),
            _ => unreachable!(),
        }

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(5, 14),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));
    }

    #[test]
    fn load() {
        let mut db = TestDatabase::default();
        db.add_prefix("/p1");
        db.add_prefix("/p2");
        db.add_file(Url::from_file_path("/p1/foo/a1.zeek").unwrap(), "");
        db.add_file(Url::from_file_path("/p2/foo/b1.zeek").unwrap(), "");

        let uri = Url::from_file_path("/x/x.zeek").unwrap();
        db.add_file(uri.clone(), "@load f");

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    position: Position::new(0, 6),
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));
    }

    #[test]
    fn event() {
        let mut db = TestDatabase::default();
        let uri = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
export {
    global evt: event(c: count, s: string);
    global fct: function(c: count, s: string);
    global hok: hook(c: count, s: string);
}

event e
function f
hook h
",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri.clone()),
                    position: Position::new(7, 6),
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri.clone()),
                    position: Position::new(8, 10),
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    position: Position::new(9, 6),
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));
    }

    #[test]
    fn keyword() {
        let mut db = TestDatabase::default();
        let uri = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
function foo() {}
f",
        );

        let result = complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    position: Position::new(2, 0),
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        );

        // Sort results for debug output diffing.
        let result = match result {
            Some(CompletionResponse::Array(mut r)) => {
                r.sort_by(|a, b| a.label.cmp(&b.label));
                r
            }
            _ => panic!(),
        };

        assert_debug_snapshot!(result);
    }
}
