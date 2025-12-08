use rustc_hash::FxHashSet;
use std::sync::{Arc, LazyLock};

use crate::{
    Files, Str,
    ast::{self, Ast},
    lsp::Database,
    parse::Parse,
    query::{self, Decl, DeclKind, Node, NodeLocation, Query},
};

use itertools::Itertools;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, CompletionItemLabelDetails, CompletionParams,
    CompletionResponse, Documentation, InsertTextFormat, MarkupContent, MarkupKind, Position, Uri,
};
use tree_sitter_zeek::KEYWORDS;

#[allow(clippy::too_many_lines)]
pub(crate) fn complete(state: &Database, params: CompletionParams) -> Option<CompletionResponse> {
    let uri = Arc::new(params.text_document_position.text_document.uri);
    let position = params.text_document_position.position;

    let source = state.source(Arc::clone(&uri))?;

    let tree = state.parse(Arc::clone(&uri))?;

    // Get the node directly under the cursor as a starting point.
    let root = tree.root_node();
    let mut node = root.descendant_for_position(position)?;

    let text = completion_text(node, &source, true);

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

    let mut items = None.or_else(|| {
        // If we are completing after `$` try to return all fields for client-side filtering.
        // TODO(bbannier): we should also handle `$` in record initializations.

        let dd_triggered = params
            .context
            .and_then(|ctx| ctx.trigger_character)
            .is_some_and(|c| c == "$");

        let ends_in_dd = root
            .descendant_for_position(node.range().end)
            .and_then(|next_node| next_node.utf8_text(source.as_bytes()).ok())
            .is_some_and(|text| text.ends_with('$'));

        let is_partial = !dd_triggered && !ends_in_dd;

        if dd_triggered
            || ends_in_dd
            || node.parent().is_some_and(|p| {
                matches!(p.kind() , "field_access" | "field_check")
            }) {
            complete_field(state, node, Arc::clone(&uri), is_partial)
        } else {
            None
        }
    }).or_else(|| {
        // If we are completing some identifier from a module got to the node containing the full
        // identifier.
        while node.utf8_text(source.as_bytes()) == Ok(":") {
            let p = node.parent()?;
            node = p;
        }

        None
    }).or_else(||
        // If we are completing a file return valid load patterns.
        if node.kind() == "file" {
            Some(state
                .possible_loads(Arc::clone(&uri))
                .iter()
                .map(|load| CompletionItem {
                    label: load.to_string(),
                    kind: Some(CompletionItemKind::FILE),
                    ..CompletionItem::default()
                })
                .collect::<Vec<_>>())
        } else {
            None
        }
    ).or_else(|| complete_record_initializer(state, node, Arc::clone(&uri))
    ).or_else(||
        // If we are completing a function/event/hook definition complete from declarations.
        if node.kind() == "id" {
            source
                .lines()
                .nth(usize::try_from(node.range().start.line).expect("too many lines"))
                .and_then(|line| {
                    static RE: LazyLock<regex::Regex> = LazyLock::new(|| { regex::Regex::new(r"^\s*(\w+)\s+\w*").expect("invalid regexp") });
                    Some(RE.captures(line)?.get(1)?.as_str())
                }).map(|kind| complete_from_decls(state, Arc::clone(&uri), kind))
        } else {
            None
        }
    ).or_else(||
        // We are just completing some arbitrary identifier at this point.
        Some(complete_any(state, root, node, uri))
    );

    // Snippet completions are always added.
    if let Some(text) = completion_text(node, &source, false) {
        let snippets = complete_snippet(text);
        items = items.map(|mut xs| {
            xs.extend(snippets);
            xs
        });
    }

    items
        .map(|items| {
            items
                .into_iter()
                .filter_map(|i| {
                    // For each completion item compute a similarity score compare to a possibly
                    // given input text. We convert to `u64` since `f64` does not implement `Ord`.
                    // The score is negative so that good matches sort before worse ones.
                    use conv::ConvUtil;

                    let score = text.and_then(|t| {
                        (rust_fuzzy_search::fuzzy_compare(&i.label.to_lowercase(), t)
                            * -100_000_000.)
                            .approx_as::<i64>()
                            .ok()
                    });
                    if score == Some(0) {
                        // Drop items with no relation to input text.
                        None
                    } else {
                        Some((i, score))
                    }
                })
                // Prioritize items with good match, i.e. lower score.
                .sorted_by_key(|(_, score)| *score)
                .map(|(i, _)| i)
                // For similar completions prefer to return the one with more docs (more likely to
                // include the full documentation since we always include the source). This prevents us
                // from emitting completions for implementations if we would also complete the
                // declaration (likely with docs).
                //
                // Items with same kind and label should refer to the same underlying entity.
                .chunk_by(|i| (i.kind, i.label.clone()))
                .into_iter()
                // Select the element with the longest documentation.
                .map(|(_, x)| x)
                .filter_map(|items| {
                    items.max_by_key(|completion_item| {
                        completion_item
                            .documentation
                            .as_ref()
                            .map_or(0, |d| match d {
                                Documentation::String(value)
                                | Documentation::MarkupContent(MarkupContent { value, .. }) => {
                                    value.len()
                                }
                            })
                    })
                })
                .collect::<Vec<_>>()
        })
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
    uri: Arc<Uri>,
    is_partial: bool,
) -> Option<Vec<CompletionItem>> {
    // If we are completing with something after the `$` (e.g., `foo$a`), instead
    // obtain the stem (`foo`) for resolving.
    if is_partial {
        let stem = node
            .parent()
            .filter(|p| matches!(p.kind(), "field_access" | "field_check"))
            .and_then(|p| p.named_child("expr"));

        // If we have a stem, perform any resolving with it; else use the original node.
        node = stem.unwrap_or(node);
    }

    if let Some(r) = state.resolve(NodeLocation::from_node(uri, node)) {
        let decl = state.typ(r).and_then(|d| match &d.kind {
            // If the decl refers to a field get the decl for underlying its type instead.
            DeclKind::Field(_) => state.typ(d),
            _ => Some(d),
        });

        // Compute completion.
        if let Some(decl) = decl
            && let DeclKind::Type(fields) = &decl.kind
        {
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

    None
}

fn complete_from_decls(state: &Database, uri: Arc<Uri>, kind: &str) -> Vec<CompletionItem> {
    let implicit_decls = state.implicit_decls();
    let explicit_decls_recursive = state.explicit_decls_recursive(Arc::clone(&uri));

    state
        .decls(uri)
        .iter()
        .chain(implicit_decls.iter())
        .chain(explicit_decls_recursive.iter())
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
                            let loc = &d.loc.as_ref()?;
                            let tree = state.parse(Arc::clone(&loc.uri))?;
                            let source = state.source(Arc::clone(&loc.uri))?;
                            tree.root_node()
                                .named_descendant_for_point_range(loc.selection_range)?
                                .utf8_text(source.as_bytes())
                                .map(Str::from)
                                .ok()
                        })
                        .join(", "),
                ),
                _ => None,
            }?;

            let label = item.label;

            Some(CompletionItem {
                insert_text: Some(format!("{label}({signature})\n\t{{\n\t${{0}}\n\t}}",)),
                insert_text_format: Some(InsertTextFormat::SNIPPET),
                label,
                label_details: Some(CompletionItemLabelDetails {
                    detail: Some(format!("({signature})")),
                    ..CompletionItemLabelDetails::default()
                }),
                ..item
            })
        })
        .collect::<Vec<_>>()
}

#[allow(clippy::too_many_lines)]
fn complete_snippet(text: &str) -> impl Iterator<Item = CompletionItem> {
    let snippets = vec![
        (
            "record",
            vec![
                "type ${1:Name}: record {",
                "\t${2:field_name}: ${3:field_type};",
                "};",
            ],
        ),
        (
            "enum",
            vec!["type ${1:Name}: enum {", "\t${2:value},", "};"],
        ),
        (
            "switch",
            vec![
                "switch ( ${1:var} )",
                "\t{",
                "\tcase ${2:case1}:",
                "\t\t${3:#code}",
                "\t\tbreak;",
                "\tdefault:",
                "\t\tbreak;",
                "\t}",
            ],
        ),
        (
            "for",
            vec!["for ( ${1:x} in ${2:xs} )", "\t{", "\t${3:#code}", "\t}"],
        ),
        (
            "while",
            vec!["while ( ${1:cond} )", "\t{", "\t${0:#code}", "\t}"],
        ),
        (
            "when",
            vec![
                "when ( ${1:cond} )",
                "\t{",
                "\t${2:#code}",
                "\t}",
                "timeout ${3:duration}",
                "\t{",
                "\t${4:#code}",
                "\t}",
            ],
        ),
        (
            "notice",
            vec![
                "NOTICE([\\$note=$1,",
                "\t\\$msg=fmt(\"${3:msg}\", ${4:args}),",
                "\t\\$conn=${5:c},",
                "\t\\$sub=fmt(\"${6:msg}\", ${7:args})]);",
            ],
        ),
        (
            "function",
            vec![
                "function ${1:function_name}(${2:${3:arg_name}: ${4:arg_type}}): ${5:return_type}",
                "\t{",
                "\t${6:#code}",
                "\t}",
            ],
        ),
        (
            "event",
            vec![
                "event ${1:zeek_init}(${2:${3:arg_name}: ${4:arg_type}})",
                "\t{",
                "\t${5:#code}",
                "\t}",
            ],
        ),
        ("if", vec!["if ( ${1:cond} )", "\t{", "\t${0:#code}", "\t}"]),
        ("@if", vec!["@if ( ${1:cond} )", "\t${0:#code}", "@endif"]),
        (
            "@ifdef",
            vec!["@ifdef ( ${1:cond} )", "\t${0:#code}", "@endif"],
        ),
        (
            "@ifndef",
            vec!["@ifndef ( ${1:cond} )", "\t${0:#code}", "@endif"],
        ),
        (
            "schedule",
            vec!["schedule ${1:10secs} { ${2:my_event}(${3:}) };"],
        ),
    ];

    snippets
        .into_iter()
        .filter_map(move |(trigger, completion)| {
            if trigger.contains(text) {
                let label = trigger.into();
                let insert_text = Some(completion.join("\n"));

                Some(CompletionItem {
                    label,
                    insert_text,
                    kind: Some(CompletionItemKind::SNIPPET),
                    insert_text_format: Some(InsertTextFormat::SNIPPET),
                    ..CompletionItem::default()
                })
            } else {
                None
            }
        })
}

fn complete_record_initializer(
    state: &Database,
    node: Node,
    uri: Arc<Uri>,
) -> Option<Vec<CompletionItem>> {
    let source = state.source(Arc::clone(&uri))?;

    // The member always needs to be an id.
    let id = match node.kind() {
        "id" => node.utf8_text(source.as_bytes()).ok()?,
        "[" | "(" => "",
        _ => return None,
    };

    let line = source
        .lines()
        .nth(usize::try_from(node.range().start.line).ok()?)
        .map(|line| line.trim_end_matches(id).trim_end_matches('$').trim())?;

    let type_ = if line.ends_with('(') {
        line.trim_end_matches('(').split_whitespace().last()
    } else if line.ends_with('[') {
        let line = line.trim_end_matches('[').trim();
        if line.ends_with('=') {
            line.trim_end_matches('=')
                .split_whitespace()
                .next_back()
                .and_then(|id| id.split(':').next_back())
        } else {
            None
        }
    } else {
        None
    };

    let type_ = state.resolve_id(type_?.into(), NodeLocation::from_node(uri, node))?;

    let DeclKind::Type(fields) = &type_.kind else {
        return None;
    };

    let mut completion: Vec<_> = fields
        .iter()
        .filter(|x| matches!(x.kind, DeclKind::Field(_)))
        .filter(|d| id.is_empty() || rust_fuzzy_search::fuzzy_compare(id, &d.id) > 0.0)
        .map(|d| {
            // Complete record fields.
            let id = d.id.to_string();

            CompletionItem {
                label: id.clone(),
                insert_text: Some(format!("{id}=")),
                ..to_completion_item(d)
            }
        })
        .collect();

    // If no field ID was provided also complete a record constructor snippet.
    if id.is_empty() {
        let dd = "\\$";

        completion.extend({
            let field_inits = fields
                .iter()
                .enumerate()
                .filter_map(|(i, f)| {
                    // Only complete required fields.
                    let DeclKind::Field(attrs) = &f.kind else {
                        return None;
                    };

                    if attrs.contains(&"&optional".into()) {
                        None
                    } else {
                        let id = &f.id;
                        let idx = i + 1;
                        Some(format!("{dd}{id}=${{{idx}:[]}}"))
                    }
                })
                .join(", ");

            // We already have `T($` or `[$` in the input, do not emit them again.
            let terminator = match line.chars().last() {
                Some('[') => ']',
                Some('(') => ')',
                // Probably impossible since we already restrict this whole
                // function to trigger only on proper record initializations.
                _ => return None,
            };
            let code = format!("{field_inits}{terminator}")
                .trim_start_matches(dd)
                .into();

            std::iter::once(CompletionItem {
                label: type_.id.to_string(),
                insert_text: Some(code),
                kind: Some(CompletionItemKind::SNIPPET),
                insert_text_format: Some(InsertTextFormat::SNIPPET),
                ..CompletionItem::default()
            })
        });
    }

    if completion.is_empty() {
        None
    } else {
        Some(completion)
    }
}

fn complete_any(
    state: &Database,
    root: Node,
    mut node: Node,
    uri: Arc<Uri>,
) -> Vec<CompletionItem> {
    let Some(source) = state.source(Arc::clone(&uri)) else {
        return Vec::new();
    };

    let mut items = FxHashSet::default();

    let current_module = root
        .named_child("module_decl")
        .and_then(|m| m.named_child("id"))
        .and_then(|id| id.utf8_text(source.as_bytes()).ok());

    let text_at_completion = completion_text(node, &source, true);

    loop {
        for d in query::decls_(node, &uri, source.as_bytes()) {
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
        .filter_map(|item| {
            // Filter down items so for `ns::id`-type identifiers we get more natural completions.

            // If there is no text to complete just return all results.
            let Some(text) = text_at_completion else {
                return Some(item);
            };
            if text.is_empty() {
                return Some(item);
            }

            let label = &item.label;

            // The the completion text contains a `::` interpret it as a namespace and only show
            // completions from that namespace. The namespace needs to match exactly, but we fuzzy
            // match items from the namespace.
            if let Some((t1, t2)) = text.split_once("::") {
                let (l1, l2) = label.split_once("::")?;

                return (t1 == l1
                    && (t2.is_empty() || rust_fuzzy_search::fuzzy_compare(t2, l2) > 0.0))
                    .then(|| CompletionItem {
                        insert_text: if t2.is_empty() {
                            Some(l2.to_string())
                        } else {
                            None
                        },
                        ..item.clone()
                    });
            }

            // Require completion text and item to either both be namespaced or none. This
            // e.g., removes a lot of identifiers in modules if we just want to complete a
            // keyword.
            (text.contains("::") == label.contains("::")
                         // Else just fuzzymatch.
                         && rust_fuzzy_search::fuzzy_compare(
                             &text.to_lowercase(),
                             &label.to_lowercase(),
                             ) > 0.0)
                .then_some(item)
        })
        .collect::<Vec<_>>()
}

fn to_completion_item(d: &Decl) -> CompletionItem {
    CompletionItem {
        label: d.fqid.to_string(),
        kind: Some(to_completion_item_kind(&d.kind)),
        documentation: Some(Documentation::MarkupContent(MarkupContent {
            kind: MarkupKind::Markdown,
            value: d.documentation.to_string(),
        })),
        ..CompletionItem::default()
    }
}

fn to_completion_item_kind(kind: &DeclKind) -> CompletionItemKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef | DeclKind::Index(_, _) => {
            CompletionItemKind::VARIABLE
        }
        DeclKind::Option => CompletionItemKind::PROPERTY,
        DeclKind::Const => CompletionItemKind::CONSTANT,
        DeclKind::Enum(_) | DeclKind::RedefEnum(_) => CompletionItemKind::ENUM,
        DeclKind::Type(_) | DeclKind::RedefRecord(_) => CompletionItemKind::CLASS,
        DeclKind::FuncDecl(_) | DeclKind::FuncDef(_) => CompletionItemKind::FUNCTION,
        DeclKind::HookDecl(_) | DeclKind::HookDef(_) => CompletionItemKind::OPERATOR,
        DeclKind::EventDecl(_) | DeclKind::EventDef(_) => CompletionItemKind::EVENT,
        DeclKind::Field(_) => CompletionItemKind::FIELD,
        DeclKind::EnumMember => CompletionItemKind::ENUM_MEMBER,
        DeclKind::Module => CompletionItemKind::MODULE,
        DeclKind::Builtin(_) => CompletionItemKind::KEYWORD,
    }
}

fn completion_text<'a>(node: Node, source: &'a str, reject_top_level: bool) -> Option<&'a str> {
    if reject_top_level && node.kind() == "source_file" {
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
    #![allow(clippy::unwrap_used)]

    use insta::assert_debug_snapshot;
    use tower_lsp_server::ls_types::{
        CompletionContext, CompletionItem, CompletionItemKind, CompletionParams,
        CompletionResponse, CompletionTriggerKind, Documentation, PartialResultParams, Position,
        TextDocumentIdentifier, TextDocumentPositionParams, Uri, WorkDoneProgressParams,
    };

    use crate::{complete::complete, lsp::test::TestDatabase};

    #[test]
    fn field_access() {
        let mut db = TestDatabase::default();

        let uri1 = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri1.clone(),
            "type X: record { abc: count; };
            global foo: X;
            foo$
            ",
        );

        let uri2 = Uri::from_file_path("/y.zeek").unwrap();
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
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(2, 16),
                ),
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
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(2, 17),
                ),
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
        let uri = Uri::from_file_path("/x.zeek").unwrap();
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

        let uri1 = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri1.clone(),
            "type X: record { abc: count; };
            global foo: X;
            foo$a
            ",
        );

        let uri2 = Uri::from_file_path("/x.zeek").unwrap();
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
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    position,
                ),
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
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    position,
                ),
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
        let uri = Uri::from_file_path("/x.zeek").unwrap();
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
    fn modules() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
            const X = T;
            module foo;
            export { const FOO = 0; }
            module bar;
            export { const BAR = 0; }
            module baz;
            foo
            ",
        );

        assert_debug_snapshot!(
            complete(
                &db.0,
                CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri),
                        Position::new(7, 15)
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                }
            )
            .map(|response| {
                // Filter out keywords since they only add noise for this test.
                let CompletionResponse::Array(xs) = response else {
                    unreachable!("expected response with array");
                };
                xs.into_iter()
                    .filter(|x| x.kind.is_some_and(|k| k != CompletionItemKind::KEYWORD))
                    .collect::<Vec<_>>()
            })
        );
    }

    #[test]
    fn module_entry() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
            const X = T;
            module foo;
            export { const BAR = 0; }
            foo::
            ",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(4, 17)
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));
    }

    #[test]
    fn referenced_field_access() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
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

        if let CompletionResponse::Array(xs) = x {
            assert_eq!(xs.len(), 1);
        } else {
            unreachable!()
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
        db.add_file(Uri::from_file_path("/p1/foo/a1.zeek").unwrap(), "");
        db.add_file(Uri::from_file_path("/p2/foo/b1.zeek").unwrap(), "");

        let uri = Uri::from_file_path("/x/x.zeek").unwrap();
        db.add_file(uri.clone(), "@load f");

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(0, 6),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));
    }

    #[test]
    fn event() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
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

  event e
",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(7, 6),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(8, 10),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(9, 6),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(11, 8),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            }
        ));
    }

    #[test]
    fn keyword() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
function foo() {}
f",
        );

        let result = complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(2, 0),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        );

        // Sort results for debug output diffing.
        let result = if let Some(CompletionResponse::Array(mut r)) = result {
            r.sort_by(|a, b| a.label.cmp(&b.label));
            r
        } else {
            unreachable!()
        };

        assert_debug_snapshot!(result);
    }

    #[test]
    fn snippet() {
        for input in [
            "rec", "swit", "for", "when", "notice", "function", "event", "if", "@if", "@ifdef",
            "@ifndef", "enum", "while", "schedule",
        ] {
            fn only_snippets(xs: CompletionResponse) -> Vec<CompletionItem> {
                match xs {
                    CompletionResponse::Array(xs) => xs
                        .into_iter()
                        .filter(|x| x.kind == Some(CompletionItemKind::SNIPPET))
                        .collect::<Vec<_>>(),
                    CompletionResponse::List(xs) => xs
                        .items
                        .into_iter()
                        .filter(|x| x.kind == Some(CompletionItemKind::SNIPPET))
                        .collect(),
                }
            }

            let mut db = TestDatabase::default();
            let uri = Uri::from_file_path("/x.zeek").unwrap();
            db.add_file(uri.clone(), input);

            let result = complete(
                &db.0,
                CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri),
                        Position::new(0, u32::try_from(input.len()).unwrap()),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                },
            )
            .map(only_snippets);

            assert_debug_snapshot!(result);
        }
    }

    #[test]
    fn declaration_and_definition() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
global foo: function();

## DOCSTRING.
function foo() {}

event zeek_init() {
    foo
    }",
        );

        let Some(CompletionResponse::Array(result)) = complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(7, 8),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ) else {
            panic!()
        };

        // We expect only one completion for this symbol.
        let foo: Vec<_> = result.iter().filter(|r| r.label == "foo").collect();
        assert_eq!(foo.len(), 1);

        // We should get the completion with the documentation.
        let Some(Documentation::MarkupContent(docs)) = foo[0].documentation.as_ref() else {
            panic!()
        };
        assert!(docs.value.contains("DOCSTRING"));

        // assert_debug_snapshot!(foo);
    }

    #[test]
    fn record_initializer() {
        let mut db = TestDatabase::default();
        db.add_file(
            Uri::from_file_path("/decls.zeek").unwrap(),
            "
type X: record {
    xa: count;
    xb: count &optional;
    y: count &optional;
};
            ",
        );

        let uri = Uri::from_file_path("/x.zeek").unwrap();

        db.add_file(
            uri.clone(),
            &format!(
                "@load ./decls
global x: X = [$
        "
            ),
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(1, 16),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));

        db.add_file(
            uri.clone(),
            &format!(
                "@load ./decls
global x: X = [$x
        "
            ),
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(1, 17),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));

        db.add_file(
            uri.clone(),
            &format!(
                "@load ./decls
global x: X = [$y
        "
            ),
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(1, 17),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));

        db.add_file(
            uri.clone(),
            &format!(
                "@load ./decls
global x:X = [$y
        "
            ),
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(1, 17),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));

        db.add_file(
            uri.clone(),
            &format!(
                "@load ./decls
global x:X = [$
        "
            ),
        );

        assert_debug_snapshot!(
            complete(
                &db.0,
                CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(1, 16),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                },
            )
            .and_then(|completion| {
                if let CompletionResponse::Array(items) = completion {
                    Some(
                        items
                            .into_iter()
                            .filter(|item| matches!(item.kind, Some(CompletionItemKind::SNIPPET)))
                            .collect::<Vec<_>>(),
                    )
                } else {
                    None
                }
            })
        );
    }

    #[test]
    fn record_initializer2() {
        let mut db = TestDatabase::default();
        db.add_file(
            Uri::from_file_path("/decls.zeek").unwrap(),
            "
type X: record {
    xa: count;
    xb: count &optional;
    y: count &optional;
};
            ",
        );

        let uri = Uri::from_file_path("/x.zeek").unwrap();

        db.add_file(
            uri.clone(),
            &format!(
                "@load ./decls
global x = X($x
        "
            ),
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(1, 14),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));

        db.add_file(
            uri.clone(),
            &format!(
                "@load ./decls
global x = X($
        "
            ),
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(1, 14),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));
    }
}
