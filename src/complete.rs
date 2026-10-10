use rustc_hash::FxHashSet;
use std::sync::Arc;

use crate::{
    InternedStr, InternedUri, ast,
    lsp::Database,
    query::{self, Decl, DeclKind, Node, NodeLocation},
    uri_db,
};

use itertools::Itertools;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, CompletionItemLabelDetails, CompletionParams,
    CompletionResponse, Documentation, InsertTextFormat, MarkupContent, MarkupKind, Position,
};
use tree_sitter::Parser;
use tree_sitter_zeek::{KEYWORDS, language_zeek};

const COMPLETION_MARKER: &str = "__ZEEK_LANGUAGE_SERVER_COMPLETION__";

fn byte_offset_of(source: &str, position: Position) -> usize {
    let line_start: usize = source
        .lines()
        .take(position.line as usize)
        .map(|l| l.len() + 1)
        .sum();
    let line_len = source[line_start..].lines().next().map_or(0, str::len);
    line_start + (position.character as usize).min(line_len)
}

/// Extract the text the user is completing from the marker node.
///
/// The marker node's text in the patched source contains `COMPLETION_MARKER`
/// surrounded by whatever the user has typed. We return the non-marker portion.
fn marker_text<'a>(marker: tree_sitter::Node<'_>, patched: &'a str) -> Option<&'a str> {
    let full = &patched[marker.start_byte()..marker.end_byte()];
    let (pre, post) = full.split_once(COMPLETION_MARKER)?;
    let text = if pre.is_empty() { post } else { pre };
    (!text.is_empty()).then_some(text)
}

fn find_ancestor<'a>(
    node: tree_sitter::Node<'a>,
    pred: impl Fn(tree_sitter::Node<'a>) -> bool,
) -> Option<tree_sitter::Node<'a>> {
    let mut cur = Some(node);
    while let Some(n) = cur {
        if pred(n) {
            return Some(n);
        }
        cur = n.parent();
    }
    None
}

/// Check whether the marker is in the name position of a declaration.
///
/// For complete declarations (`event_decl`, `func_decl`, `hook_decl`) the marker
/// must be the `id` child that is the declaration's name. For incomplete
/// declarations tree-sitter produces an `ERROR` node with the keyword as an
/// anonymous sibling preceding the marker.
fn completing_decl_name(marker: tree_sitter::Node<'_>) -> Option<&'static str> {
    let parent = marker.parent()?;

    // Complete declaration: marker is the name `id` directly under the decl node.
    if marker.kind() == "id"
        && parent
            .named_child(0)
            .is_some_and(|first| first.id() == marker.id())
    {
        match parent.kind() {
            kind @ ("event_decl" | "func_decl" | "hook_decl") => return Some(kind),
            "event_hdr" => return Some("event_decl"),
            _ => {}
        }
    }

    // Incomplete declaration: `event name` produces `(ERROR "event" (id))`.
    // With a line break between keyword and name there may be intervening `nl` nodes.
    if parent.kind() == "ERROR" {
        let mut prev = marker.prev_sibling();
        while prev.is_some_and(|n| n.kind() == "nl") {
            prev = prev.and_then(|n| n.prev_sibling());
        }
        return match prev?.kind() {
            "event" => Some("event_decl"),
            "function" => Some("func_decl"),
            "hook" => Some("hook_decl"),
            _ => None,
        };
    }

    None
}

/// Return the source text up to (but not including) the cursor position.
pub(crate) fn source_up_to(source: &str, position: Position) -> &str {
    &source[..byte_offset_of(source, position)]
}

enum CompletionKind<'a> {
    FieldAccess { stem: Node<'a> },
    Load,
    DeclName { kind: &'static str },
    General,
}

fn classify<'a>(marker: tree_sitter::Node<'_>, root: Node<'a>) -> CompletionKind<'a> {
    if let Some(fa) = find_ancestor(marker, |n| {
        matches!(n.kind(), "field_access" | "field_check")
    }) && let Some(stem) = fa.named_child(0).and_then(|s| {
        let r = s.range();
        root.named_descendant_for_point_range(tower_lsp_server::ls_types::Range::new(
            Position::new(
                u32::try_from(r.start_point.row).ok()?,
                u32::try_from(r.start_point.column).ok()?,
            ),
            Position::new(
                u32::try_from(r.end_point.row).ok()?,
                u32::try_from(r.end_point.column).ok()?,
            ),
        ))
    }) {
        return CompletionKind::FieldAccess { stem };
    }

    if find_ancestor(marker, |n| matches!(n.kind(), "file" | "string_directive")).is_some() {
        return CompletionKind::Load;
    }

    if let Some(kind) = completing_decl_name(marker) {
        return CompletionKind::DeclName { kind };
    }

    CompletionKind::General
}

#[allow(clippy::too_many_lines)]
pub(crate) fn complete(state: &Database, params: CompletionParams) -> Option<CompletionResponse> {
    let uri = Arc::new(params.text_document_position.text_document.uri);
    let position = params.text_document_position.position;

    let uri = uri_db(state, Arc::clone(&uri));
    let source = crate::source(state, uri)?;

    let tree = crate::parse::parse(state, uri)?;
    let root = tree.root_node();

    // Reparse with a marker inserted at the cursor for structural context.
    let marker_offset = byte_offset_of(&source, position);
    let patched = format!(
        "{}{COMPLETION_MARKER}{}",
        &source[..marker_offset],
        &source[marker_offset..]
    );
    let mut edited = tree.inner().clone();
    let point = tree_sitter::Point::new(position.line as usize, position.character as usize);
    edited.edit(&tree_sitter::InputEdit {
        start_byte: marker_offset,
        old_end_byte: marker_offset,
        new_end_byte: marker_offset + COMPLETION_MARKER.len(),
        start_position: point,
        old_end_position: point,
        new_end_position: tree_sitter::Point::new(
            point.row,
            point.column + COMPLETION_MARKER.len(),
        ),
    });
    let mut parser = Parser::new();
    parser
        .set_language(&language_zeek())
        .expect("cannot set parser language");
    let marker_tree = parser.parse(patched.as_bytes(), Some(&edited))?;
    let marker = marker_tree
        .root_node()
        .descendant_for_byte_range(marker_offset, marker_offset + COMPLETION_MARKER.len())?;

    // For Salsa queries and completion text we need a node from the original tree.
    // Walk back from the cursor until we find a token, skipping whitespace and newlines.
    let node = {
        let mut col = position.character;
        loop {
            let n = root.descendant_for_position(Position {
                character: col,
                ..position
            });
            match n {
                Some(n) if !matches!(n.kind(), "source_file" | "nl") => break n,
                _ if col > 0 => col -= 1,
                _ => break root,
            }
        }
    };

    let text = marker_text(marker, &patched);
    let kind = classify(marker, root);

    let mut items: Vec<CompletionItem> = match kind {
        CompletionKind::FieldAccess { stem } => {
            complete_field(state, stem, uri).unwrap_or_default()
        }
        CompletionKind::Load => crate::ast::possible_loads(state, uri)
            .iter()
            .map(|load| CompletionItem {
                label: load.to_string(),
                kind: Some(CompletionItemKind::FILE),
                ..CompletionItem::default()
            })
            .collect(),
        CompletionKind::DeclName { kind } => complete_from_decls(state, uri, kind),
        CompletionKind::General => complete_record_initializer(state, node, uri, position)
            .unwrap_or_else(|| complete_any(state, node, uri, text)),
    };

    if let Some(text) = text {
        items.extend(complete_snippet(text));
    }

    let items = items
        .into_iter()
        .filter_map(|i| {
            // For each completion item compute a similarity score compare to a possibly
            // given input text. We convert to `u64` since `f64` does not implement `Ord`.
            // The score is negative so that good matches sort before worse ones.
            let score = text.and_then(|t| {
                use az::CheckedCast;
                (rust_fuzzy_search::fuzzy_compare(&i.label.to_lowercase(), t) * -100_000_000.)
                    .checked_cast()
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
                        | Documentation::MarkupContent(MarkupContent { value, .. }) => value.len(),
                    })
            })
        })
        .collect::<Vec<_>>();

    Some(CompletionResponse::from(items))
}

/// Complete a field after `$` or `?$`
///
/// # Arguments
///
/// * `state` - global database
/// * `stem` - the expression node before `$` (e.g., `foo` in `foo$abc`)
/// * `uri` - document URI
fn complete_field(state: &Database, stem: Node, uri: InternedUri) -> Option<Vec<CompletionItem>> {
    let r = crate::ast::resolve(state, NodeLocation::from_node(uri, stem))?;
    let decl = crate::ast::typ(state, r).and_then(|d| match &d.kind {
        // If the decl refers to a field get the decl for underlying its type instead.
        DeclKind::Field(_) => crate::ast::typ(state, d),
        _ => Some(d),
    })?;
    let DeclKind::Type(fields) = &decl.kind else {
        return None;
    };

    Some(
        fields
            .iter()
            .map(to_completion_item)
            .filter_map(|item| {
                // Record field FQIDs are e.g. `mod::rec::field`; we want just `field`.
                let label = item.label.split("::").last()?.to_string();
                Some(CompletionItem { label, ..item })
            })
            .collect(),
    )
}

#[allow(clippy::needless_pass_by_value)]
fn complete_from_decls(state: &Database, uri: InternedUri, node_kind: &str) -> Vec<CompletionItem> {
    let implicit_decls = crate::ast::implicit_decls(state);
    let explicit_decls_recursive = crate::ast::explicit_decls_recursive(state, uri);

    crate::query::decls(state, uri)
        .iter()
        .chain(implicit_decls.iter())
        .chain(explicit_decls_recursive.iter())
        .filter(|d| match &d.kind {
            DeclKind::EventDecl(_) => node_kind == "event_decl",
            DeclKind::FuncDecl(_) => node_kind == "func_decl",
            DeclKind::HookDecl(_) => node_kind == "hook_decl",
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
                            let tree = crate::parse::parse(state, loc.uri)?;
                            let source = crate::source(state, loc.uri)?;
                            tree.root_node()
                                .named_descendant_for_point_range(loc.selection_range)?
                                .utf8_text(source.as_bytes())
                                .map(InternedStr::from)
                                .ok()
                        })
                        .join(", "),
                ),
                _ => None,
            }?;

            let label = item.label;

            Some(CompletionItem {
                insert_text: Some(format!("{label}({signature})\n\t{{\n\t${{0}}\n\t}}")),
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

/// Scan `line` backwards for an unbalanced `(` or `[`.
/// Returns `(type_name, delimiter, args_text)` where `delimiter` is `(` or `[` and `args_text`
/// is the slice of `line` after the delimiter.
/// For `X($` the type is named before `(`; for `[$` it comes from the variable's type annotation.
fn initializer_type_name(line: &str) -> Option<(&str, char, &str)> {
    let mut depth = 0i32;
    for (i, ch) in line.char_indices().rev() {
        match ch {
            ')' | ']' => depth += 1,
            '(' | '[' if depth > 0 => depth -= 1,
            '(' => {
                let name = line[..i].split_whitespace().last()?;
                return Some((name, '(', &line[i + 1..]));
            }
            '[' => {
                let before = line[..i].trim().trim_end_matches('=').trim();
                let name = before
                    .split_whitespace()
                    .next_back()
                    .and_then(|s| s.split(':').next_back())?;
                return Some((name, '[', &line[i + 1..]));
            }
            _ => {}
        }
    }
    None
}

fn complete_record_initializer(
    state: &Database,
    node: Node,
    uri: InternedUri,
    position: Position,
) -> Option<Vec<CompletionItem>> {
    let source = crate::source(state, uri)?;

    let id = match node.kind() {
        "id" => node.utf8_text(source.as_bytes()).ok()?,
        _ => "",
    };

    let text = source_up_to(&source, position);
    let line = text.trim_end_matches(id).trim_end_matches('$').trim();

    let (type_name, open_delim, args) = initializer_type_name(line)?;
    let line_nr = node.range().start.line;
    let pos = Position::new(line_nr, 0);
    let loc = NodeLocation::from_range(uri, tower_lsp_server::ls_types::Range::new(pos, pos));
    let type_ = crate::ast::resolve_id(state, type_name.into(), loc)?;

    let DeclKind::Type(fields) = &type_.kind else {
        return None;
    };

    // Collect field names already present in the initializer so we don't offer them again.
    let used: rustc_hash::FxHashSet<&str> = args
        .split('$')
        .skip(1)
        .filter_map(|s| s.split('=').next())
        .collect();

    let mut completion: Vec<_> = fields
        .iter()
        .filter(|x| matches!(x.kind, DeclKind::Field(_)))
        .filter(|d| !used.contains(&*d.id))
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

    let terminator = match open_delim {
        '(' => ')',
        '[' => ']',
        _ => unreachable!(),
    };
    if id.is_empty() {
        let dd = "\\$";
        let field_inits = fields
            .iter()
            .filter(|f| !used.contains(&*f.id))
            .enumerate()
            .filter_map(|(i, f)| {
                let DeclKind::Field(attrs) = &f.kind else {
                    return None;
                };
                if attrs
                    .iter()
                    .any(|a| a.starts_with("&optional") || a.starts_with("&default"))
                {
                    None
                } else {
                    let id = &f.id;
                    let idx = i + 1;
                    Some(format!("{dd}{id}=${{{idx}:[]}}"))
                }
            })
            .join(", ");
        if !field_inits.is_empty() {
            let code = format!("{field_inits}{terminator}")
                .trim_start_matches(dd)
                .into();
            completion.push(CompletionItem {
                label: type_.id.to_string(),
                insert_text: Some(code),
                kind: Some(CompletionItemKind::SNIPPET),
                insert_text_format: Some(InsertTextFormat::SNIPPET),
                ..CompletionItem::default()
            });
        }
    }

    if completion.is_empty() {
        None
    } else {
        Some(completion)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn complete_any(
    state: &Database,
    node: Node,
    uri: InternedUri,
    text_at_completion: Option<&str>,
) -> Vec<CompletionItem> {
    let mut items = FxHashSet::default();

    let graph = crate::scope::scope_graph(state, uri);
    let current_module = graph.module_at(node.range().start);

    for d in graph.all_local_decls(node.range().start) {
        // Strip the current module prefix from fqids so completions show short names.
        let fqid = if let query::ModuleId::String(m) = &current_module {
            let prefix = format!("{m}::");
            d.fqid.strip_prefix(&*prefix).unwrap_or(&d.fqid)
        } else {
            &d.fqid
        }
        .into();
        items.insert(Decl { fqid, ..d.clone() });
    }

    let loaded_decls = crate::ast::explicit_decls_recursive(state, uri);
    let implicit_decls = crate::ast::implicit_decls(state);

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

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use crate::test_util::assert_debug_snapshot;
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

        let evt = Uri::from_file_path("/evt.zeek").unwrap();
        db.add_file(
            evt.clone(),
            "global evt: event(c: count, s: string);\nevent e",
        );

        let fct = Uri::from_file_path("/fct.zeek").unwrap();
        db.add_file(
            fct.clone(),
            "global fct: function(c: count, s: string);\nfunction f",
        );

        let hok = Uri::from_file_path("/hok.zeek").unwrap();
        db.add_file(
            hok.clone(),
            "global hok: hook(c: count, s: string);\nhook h",
        );

        let indented = Uri::from_file_path("/indented.zeek").unwrap();
        db.add_file(
            indented.clone(),
            "global evt: event(c: count, s: string);\n  event e",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(evt),
                    Position::new(1, 6),
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
                    TextDocumentIdentifier::new(fct),
                    Position::new(1, 10),
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
                    TextDocumentIdentifier::new(hok),
                    Position::new(1, 6),
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
                    TextDocumentIdentifier::new(indented),
                    Position::new(1, 8),
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
    #[allow(clippy::too_many_lines)]
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
            "@load ./decls
global x: X = [$
        ",
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
            "@load ./decls
global x: X = [$x
        ",
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
            "@load ./decls
global x: X = [$y
        ",
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
            "@load ./decls
global x:X = [$y
        ",
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
            "@load ./decls
global x:X = [$
        ",
        );

        assert_debug_snapshot!(
            complete(
                &db.0,
                CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri),
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
    z: count &default=0;
};
type Y: record {
    ya: count;
    yb: count;
};
            ",
        );

        let uri = Uri::from_file_path("/x.zeek").unwrap();

        db.add_file(
            uri.clone(),
            "@load ./decls
global x = X($x
        ",
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
            "@load ./decls
global x = X($
        ",
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
            "@load ./decls
global x = X($xa=1, $
        ",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(1, 20),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));

        db.add_file(
            uri.clone(),
            "@load ./decls
global x = Y($ya=1, $
        ",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(1, 20),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));
    }

    #[test]
    fn record_initializer_multiline() {
        let mut db = TestDatabase::default();
        db.add_file(
            Uri::from_file_path("/decls.zeek").unwrap(),
            "
type X: record {
    xa: count;
    xb: count &optional;
};
            ",
        );

        let uri = Uri::from_file_path("/x.zeek").unwrap();

        // Multiline `[` initializer: cursor on the second line after `$`.
        db.add_file(
            uri.clone(),
            "@load ./decls
global x: X = [
    $
        ",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri.clone()),
                    Position::new(2, 5),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));

        // Multiline `(` initializer.
        db.add_file(
            uri.clone(),
            "@load ./decls
global x = X(
    $
        ",
        );

        assert_debug_snapshot!(complete(
            &db.0,
            CompletionParams {
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new(uri),
                    Position::new(2, 5),
                ),
                work_done_progress_params: WorkDoneProgressParams::default(),
                partial_result_params: PartialResultParams::default(),
                context: None,
            },
        ));
    }
}
