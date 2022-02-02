use crate::{
    parse::Parse,
    query::{self, Decl, DeclKind, ModuleId, Query},
    to_point, to_range, zeek, Files,
};
use itertools::Itertools;
use log::{error, warn};
use lspower::{
    jsonrpc::{Error, ErrorCode, Result},
    lsp::{
        notification::Progress, request::WorkDoneProgressCreate, CompletionItem,
        CompletionItemKind, CompletionOptions, CompletionParams, CompletionResponse,
        DidChangeTextDocumentParams, DidChangeWatchedFilesParams, DidOpenTextDocumentParams,
        DocumentSymbol, DocumentSymbolParams, DocumentSymbolResponse, Documentation,
        FileChangeType, FileEvent, GotoDefinitionParams, GotoDefinitionResponse, Hover,
        HoverContents, HoverParams, HoverProviderCapability, InitializeParams, InitializeResult,
        InitializedParams, LanguageString, Location, MarkedString, MessageType, OneOf, Position,
        ProgressParams, ProgressParamsValue, ProgressToken, Range, ServerCapabilities,
        SymbolInformation, SymbolKind, TextDocumentSyncCapability, TextDocumentSyncKind, Url,
        WorkDoneProgress, WorkDoneProgressBegin, WorkDoneProgressCreateParams, WorkDoneProgressEnd,
        WorkDoneProgressReport, WorkspaceSymbolParams,
    },
    Client, LanguageServer, LspService, Server, TokenCanceller,
};
use salsa::{ParallelDatabase, Snapshot};
use std::{
    collections::{BTreeSet, HashSet},
    fmt::Debug,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use tracing::instrument;

#[salsa::database(
    crate::parse::ParseStorage,
    crate::query::QueryStorage,
    ServerStateStorage,
    crate::FilesStorage
)]
#[derive(Default)]
pub struct Database {
    storage: salsa::Storage<Self>,
}

impl salsa::Database for Database {}

impl salsa::ParallelDatabase for Database {
    fn snapshot(&self) -> salsa::Snapshot<Self> {
        salsa::Snapshot::new(Database {
            storage: self.storage.snapshot(),
        })
    }
}

impl Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database").finish()
    }
}

#[salsa::query_group(ServerStateStorage)]
pub trait ServerState: Files + Parse + Query {
    #[salsa::input]
    fn prefixes(&self) -> Arc<Vec<PathBuf>>;

    #[salsa::input]
    fn files(&self) -> Arc<BTreeSet<Arc<Url>>>;

    #[must_use]
    fn loaded_files(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;

    #[must_use]
    fn loaded_files_recursive(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;

    #[must_use]
    fn loaded_decls(&self, url: Arc<Url>) -> Arc<Vec<Decl>>;

    #[must_use]
    fn implicit_decls(&self) -> Arc<Vec<Decl>>;
}

#[allow(clippy::needless_pass_by_value)]
fn loaded_files(db: &dyn ServerState, uri: Arc<Url>) -> Arc<Vec<Arc<Url>>> {
    let files = db.files();

    let prefixes = db.prefixes();

    let loads: Vec<_> = db.loads(uri.clone()).iter().map(PathBuf::from).collect();

    let mut loaded_files = Vec::new();

    for load in &loads {
        if let Some(f) = load_to_file(load, uri.as_ref(), &files, &prefixes) {
            loaded_files.push(f);
        }
    }

    Arc::new(loaded_files)
}

#[instrument(skip(db))]
fn loaded_files_recursive(db: &dyn ServerState, url: Arc<Url>) -> Arc<Vec<Arc<Url>>> {
    let mut files = db.loaded_files(url).as_ref().clone();

    loop {
        let mut new_files = Vec::new();

        for f in &files {
            for load in db.loaded_files(f.clone()).as_ref() {
                if !files.iter().any(|f| f.as_ref() == load.as_ref()) {
                    new_files.push(load.clone());
                }
            }
        }

        if new_files.is_empty() {
            break;
        }

        for n in new_files {
            files.push(n);
        }
    }

    Arc::new(files)
}

fn load_to_file(
    load: &Path,
    base: &Url,
    files: &BTreeSet<Arc<Url>>,
    prefixes: &[PathBuf],
) -> Option<Arc<Url>> {
    let file_dir = base
        .to_file_path()
        .ok()
        .and_then(|f| f.parent().map(Path::to_path_buf));

    let load = match load.strip_prefix(".") {
        Ok(l) => l,
        Err(_) => load,
    };

    file_dir.iter().chain(prefixes.iter()).find_map(|prefix| {
        // Files in the given prefix.
        let files: Vec<_> = files
            .iter()
            .filter_map(|f| {
                if let Ok(p) = f.to_file_path().ok()?.strip_prefix(prefix) {
                    Some((f, p.to_path_buf()))
                } else {
                    None
                }
            })
            .collect();

        // File known w/ extension.
        let known_exactly = files.iter().find(|(_, p)| p.ends_with(load));

        // File known w/o extension.
        let known_no_ext = files
            .iter()
            .find(|(_, p)| p.ends_with(load.with_extension("zeek")));

        // Load is directory with `__load__.zeek`.
        let known_directory = files
            .iter()
            .find(|(_, p)| p.ends_with(load.join("__load__.zeek")));

        known_exactly
            .or(known_no_ext)
            .or(known_directory)
            .map(|(f, _)| (*f).clone())
    })
}

#[instrument(skip(db))]
fn loaded_decls(db: &dyn ServerState, url: Arc<Url>) -> Arc<Vec<Decl>> {
    let mut decls = Vec::new();

    for load in db.loaded_files_recursive(url).as_ref() {
        for decl in db.decls(load.clone()).iter() {
            decls.push(decl.clone());
        }
    }

    Arc::new(decls)
}

#[instrument(skip(db))]
fn implicit_decls(db: &dyn ServerState) -> Arc<Vec<Decl>> {
    let implicit_load = zeek::init_script_filename();

    let mut implicit_file = None;
    // This loop looks horrible, but is okay since this function will be cached most of the time
    // (unless global state changes).
    for f in db.files().iter() {
        let path = match f.to_file_path() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if !path.ends_with(&implicit_load) {
            continue;
        }

        for p in db.prefixes().iter() {
            if path.strip_prefix(p).is_ok() {
                implicit_file = Some(f.clone());
                break;
            }
        }
    }

    let implicit_load = match implicit_file {
        Some(f) => f,
        None => return Arc::new(Vec::new()), // TODO(bbannier): this could also be an error.
    };

    db.loaded_decls(implicit_load)
}

#[derive(Debug)]
struct Backend {
    client: Option<Client>,
    state: Mutex<Database>,
}

impl Backend {
    async fn log_message<M>(&self, typ: lspower::lsp::MessageType, message: M)
    where
        M: std::fmt::Display,
    {
        if let Some(client) = &self.client {
            client.log_message(typ, message).await;
        }
    }

    fn state(&self) -> Result<Snapshot<Database>> {
        self.state_mut().map(|d| d.snapshot())
    }

    fn state_mut(&self) -> Result<MutexGuard<Database>> {
        self.state
            .lock()
            .map_err(|_| Error::new(ErrorCode::InternalError))
    }

    async fn progress_begin<T>(&self, title: T) -> Result<ProgressToken>
    where
        T: Into<String> + std::fmt::Display,
    {
        let token = ProgressToken::String(format!("zeek-language-server/{}", &title));

        if let Some(client) = &self.client {
            let canceller = TokenCanceller::new();
            client
                .send_custom_request::<WorkDoneProgressCreate>(
                    WorkDoneProgressCreateParams {
                        token: token.clone(),
                    },
                    canceller.token(),
                )
                .await?;

            let params = ProgressParams {
                token: token.clone(),
                value: ProgressParamsValue::WorkDone(WorkDoneProgress::Begin(
                    WorkDoneProgressBegin {
                        title: title.into(),
                        ..WorkDoneProgressBegin::default()
                    },
                )),
            };
            client.send_custom_notification::<Progress>(params).await;
        }

        Ok(token)
    }

    async fn progress_end(&self, token: Option<ProgressToken>) {
        let token = match token {
            Some(t) => t,
            None => return,
        };

        if let Some(client) = &self.client {
            let params = ProgressParams {
                token: token.clone(),
                value: ProgressParamsValue::WorkDone(WorkDoneProgress::End(
                    WorkDoneProgressEnd::default(),
                )),
            };
            client.send_custom_notification::<Progress>(params).await;
        }
    }

    async fn progress(
        &self,
        token: Option<ProgressToken>,
        message: Option<String>,
        percentage: Option<u32>,
    ) {
        let token = match token {
            Some(t) => t,
            None => return,
        };

        if let Some(client) = &self.client {
            let params = ProgressParams {
                token,
                value: ProgressParamsValue::WorkDone(WorkDoneProgress::Report(
                    WorkDoneProgressReport {
                        message,
                        percentage,
                        ..WorkDoneProgressReport::default()
                    },
                )),
            };

            client.send_custom_notification::<Progress>(params).await;
        }
    }
}

#[lspower::async_trait]
impl LanguageServer for Backend {
    #[instrument]
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        if let Ok(mut state) = self.state_mut() {
            state.set_files(Arc::new(BTreeSet::new()));
            state.set_prefixes(Arc::new(Vec::new()));
        }

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                workspace_symbol_provider: Some(OneOf::Left(true)),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec!["$".into(), "?".into()]),
                    ..CompletionOptions::default()
                }),
                definition_provider: Some(OneOf::Left(true)),
                ..ServerCapabilities::default()
            },
            ..InitializeResult::default()
        })
    }

    #[instrument]
    async fn initialized(&self, _: InitializedParams) {
        self.log_message(MessageType::INFO, "server initialized!")
            .await;

        let prefixes = match zeek::prefixes().await {
            Ok(p) => p,
            Err(_) => Vec::new(),
        };

        if let Ok(mut state) = self.state_mut() {
            state.set_prefixes(Arc::new(prefixes));
        }

        match zeek::system_files().await {
            Ok(files) => {
                self.did_change_watched_files(DidChangeWatchedFilesParams {
                    changes: files
                        .into_iter()
                        .filter_map(|f| {
                            let uri = Url::from_file_path(f.path).ok()?;
                            Some(FileEvent::new(uri, FileChangeType::CREATED))
                        })
                        .collect(),
                })
                .await;
            }
            Err(e) => {
                self.log_message(MessageType::ERROR, e).await;
            }
        }
    }

    #[instrument]
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    #[instrument]
    async fn did_change_watched_files(&self, params: DidChangeWatchedFilesParams) {
        let progress_token = self.progress_begin("Indexing").await.ok();

        for change in params.changes {
            let uri = change.uri;

            #[allow(clippy::cast_possible_truncation)]
            self.progress(progress_token.clone(), Some(uri.path().to_string()), None)
                .await;

            let source = match std::fs::read_to_string(uri.path()) {
                Ok(s) => s,
                Err(e) => {
                    warn!("failed to read '{}': {}", &uri, e);
                    continue;
                }
            };

            if let Ok(mut state) = self.state_mut() {
                let uri = Arc::new(uri);

                state.set_source(uri.clone(), Arc::new(source));

                let mut files = state.files();
                let files = Arc::make_mut(&mut files);
                files.insert(uri.clone());
                state.set_files(Arc::new(files.clone()));

                // Precompute decls in the file.
                let _decls = state.decls(uri);
            };
        }

        // Reload implicit declarations.
        self.progress(
            progress_token.clone(),
            Some("implicit loads".to_string()),
            None,
        )
        .await;
        let _implicit = self.state().map(|s| s.implicit_decls());

        self.progress_end(progress_token).await;
    }

    #[instrument]
    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let source = params.text_document.text;

        if let Ok(mut state) = self.state_mut() {
            let uri = Arc::new(uri);

            state.set_source(uri.clone(), Arc::new(source));

            let mut files = state.files();
            if !files.contains(&uri) {
                let files = Arc::make_mut(&mut files);
                files.insert(uri.clone());
                state.set_files(Arc::new(files.clone()));
            }

            // Precompute decls in this module.
            let _decls = state.decls(uri);
        }
    }

    #[instrument]
    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let changes = params.content_changes;
        assert_eq!(
            changes.len(),
            1,
            "more than one change received even though we only advertize full update mode"
        );
        let changes = changes.get(0).unwrap();
        assert!(changes.range.is_none(), "unexpected diff mode");

        let uri = params.text_document.uri;

        let source = changes.text.to_string();

        if let Ok(mut state) = self.state_mut() {
            let uri = Arc::new(uri);
            state.set_source(uri, Arc::new(source));
        }
    }

    #[instrument]
    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let params = params.text_document_position_params;

        let uri = Arc::new(params.text_document.uri);

        let state = self.state()?;

        let source = state.source(uri.clone());

        let tree = state.parse(uri.clone());
        let tree = match tree.as_ref() {
            Some(t) => t,
            None => return Ok(None),
        };

        let node = match tree.named_descendant_for_position(&params.position) {
            Some(n) => n,
            None => return Ok(None),
        };

        let text = node.utf8_text(source.as_bytes()).map_err(|e| {
            error!("could not get source text: {}", e);
            Error::new(ErrorCode::InternalError)
        })?;

        let mut contents = vec![
            #[cfg(debug_assertions)]
            MarkedString::LanguageString(LanguageString {
                value: text.into(),
                language: "zeek".into(),
            }),
            #[cfg(debug_assertions)]
            MarkedString::LanguageString(LanguageString {
                value: node.to_sexp(),
                language: "lisp".into(),
            }),
        ];

        match node.kind() {
            "id" => {
                if let Some(decl) = resolve(&state, node, None, uri) {
                    contents.push(MarkedString::String(decl.documentation));
                }
            }
            "file" => {
                let file = PathBuf::from(text);
                let uri = load_to_file(
                    &file,
                    uri.as_ref(),
                    state.files().as_ref(),
                    state.prefixes().as_ref(),
                );
                if let Some(uri) = uri {
                    contents.push(MarkedString::String(uri.path().to_string()));
                }
            }
            _ => {}
        }

        let hover = Hover {
            contents: HoverContents::Array(contents),
            range: to_range(node.range()).ok(),
        };

        Ok(Some(hover))
    }

    #[instrument]
    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let state = self.state()?;

        let uri = Arc::new(params.text_document.uri);

        let symbol = |d: &Decl| -> DocumentSymbol {
            #[allow(deprecated)]
            DocumentSymbol {
                name: d.id.clone(),
                range: d.range,
                selection_range: d.selection_range,
                kind: to_symbol_kind(&d.kind),
                deprecated: None,
                detail: None,
                tags: None,
                children: match &d.kind {
                    DeclKind::Type(fields) => Some(
                        fields
                            .iter()
                            .map(|f| DocumentSymbol {
                                name: f.id.clone(),
                                range: f.range,
                                selection_range: f.selection_range,
                                deprecated: None,
                                children: None,
                                kind: to_symbol_kind(&f.kind),
                                tags: None,
                                detail: None,
                            })
                            .collect(),
                    ),
                    _ => None,
                },
            }
        };

        let modules = state
            .decls(uri)
            .iter()
            .group_by(|d| &d.module)
            .into_iter()
            .map(|(m, decls)| {
                #[allow(deprecated)]
                DocumentSymbol {
                    name: format!("{}", m),
                    kind: SymbolKind::MODULE,
                    children: Some(decls.map(symbol).collect()),

                    // FIXME(bbannier): Weird ranges.
                    range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                    selection_range: Range::new(Position::new(0, 0), Position::new(0, 0)),

                    deprecated: None,

                    detail: None,
                    tags: None,
                }
            })
            .collect();

        Ok(Some(DocumentSymbolResponse::Nested(modules)))
    }

    #[instrument]
    async fn symbol(
        &self,
        params: WorkspaceSymbolParams,
    ) -> Result<Option<Vec<SymbolInformation>>> {
        let state = self.state()?;

        let query = params.query.to_lowercase();

        let files = state.files();
        let symbols = files.iter().flat_map(|uri| {
            state
                .decls(uri.clone())
                .iter()
                .filter(|d| rust_fuzzy_search::fuzzy_compare(&query, &d.fqid.to_lowercase()) > 0.0)
                .map(|d| {
                    let url: &Url = &**uri;

                    #[allow(deprecated)]
                    SymbolInformation {
                        name: d.fqid.clone(),
                        kind: to_symbol_kind(&d.kind),

                        location: Location::new(url.clone(), d.range),
                        container_name: Some(format!("{}", &d.module)),

                        tags: None,
                        deprecated: None,
                    }
                })
                .collect::<Vec<_>>()
        });

        Ok(Some(symbols.collect()))
    }

    #[instrument]
    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let position = params.text_document_position;
        let uri = Arc::new(position.text_document.uri);

        let state = self.state()?;

        let source = state.source(uri.clone());

        let tree = match state.parse(uri.clone()) {
            Some(t) => t,
            None => return Ok(None),
        };

        // Get the node directly under the cursor as a starting point.
        let mut node = match tree.descendant_for_position(&position.position) {
            Some(n) => n,
            None => return Ok(None),
        };

        // If the node has no text try to find a previous node with text.
        while node
            .utf8_text(source.as_bytes())
            .ok()
            // The grammar might expose newlines as AST nodes. Such nodes should be ignored for
            // completion.
            .map(str::trim)
            .map_or(0, str::len)
            == 0
        {
            node = match node.prev_named_sibling() {
                Some(s) => s,
                None => match node.parent() {
                    Some(p) => p,
                    // We might arrive here if we are completing for a source file without any
                    // text. In that case we return the original node since there is nothing
                    // interesting to find.
                    None => node,
                },
            };
        }

        let text_at_completion = node
            .utf8_text(source.as_bytes())
            // This shouldn't happen; if we cannot get the node text there is some UTF-8 error.
            .map_err(|_| Error::new(ErrorCode::InternalError))?
            .lines()
            .next()
            .map(str::trim);

        // If we are completing after `$` try to return all fields for client-side filtering.
        // TODO(bbannier): if `$` wasn't a trigger char, also check the input text.
        // TODO(bbannier): we should also handle `$` in record initializations.
        if params
            .context
            .and_then(|ctx| ctx.trigger_character)
            .map_or(false, |c| c == "$")
        {
            if let Some(r) = resolve(&state, node, None, uri.clone()) {
                // The decl might live in another tree.
                let tree = match state.parse(r.uri) {
                    Some(t) => t,
                    None => return Ok(None),
                };

                let start = match to_point(r.range.start) {
                    Ok(p) => p,
                    _ => return Ok(None),
                };
                let end = match to_point(r.range.end) {
                    Ok(p) => p,
                    _ => return Ok(None),
                };

                let decl = tree
                    .root_node()
                    .named_descendant_for_point_range(start, end)
                    .and_then(|n| typ(&state, n, n, &uri));

                // Compute completion.
                if let Some(decl) = decl {
                    // FIXME(bbannier): also complete for redefs of record or enums.
                    if let DeclKind::Type(fields) = decl.kind {
                        return Ok(Some(CompletionResponse::from(
                            fields
                                .iter()
                                .map(to_completion_item)
                                .filter_map(|item| {
                                    // By default we use FQIDs for completion labels. Since for
                                    // record fields this would be e.g., `mod::rec::field` where we
                                    // want just `field` rework them slightly.
                                    let label = item.label.split("::").last()?.to_string();
                                    Some(CompletionItem { label, ..item })
                                })
                                .collect::<Vec<_>>(),
                        )));
                    }
                }
            }
        }

        // We are just completing some arbitrary identifier at this point.
        let items: Vec<_> = {
            let mut items = HashSet::new();
            let mut node = node;

            loop {
                for d in query::decls_(node, uri.clone(), source.as_bytes()) {
                    items.insert(d);
                }

                node = match node.parent() {
                    Some(n) => n,
                    None => break,
                };
            }

            let loaded_decls = state.loaded_decls(uri);
            let implicit_decls = state.implicit_decls();

            let other_decls = loaded_decls
                .iter()
                .chain(implicit_decls.iter())
                // Only return external decls which somehow match the text to complete to keep the response sent to the client small.
                .filter(|i| {
                    if let Some(text) = text_at_completion {
                        rust_fuzzy_search::fuzzy_compare(
                            &text.to_lowercase(),
                            &i.fqid.to_lowercase(),
                        ) > 0.0
                    } else {
                        true
                    }
                });

            items
                .iter()
                .chain(other_decls)
                .filter(|d| d.kind != DeclKind::Event)
                .unique()
                .map(to_completion_item)
                .collect()
        };

        Ok(Some(CompletionResponse::from(items)))
    }

    #[instrument]
    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let params = params.text_document_position_params;
        let uri = Arc::new(params.text_document.uri);
        let position = params.position;

        let state = self.state()?;
        let tree = state.parse(uri.clone());
        let tree = match tree.as_ref() {
            Some(t) => t,
            None => return Ok(None),
        };
        let node = match tree.named_descendant_for_position(&position) {
            Some(n) => n,
            None => return Ok(None),
        };
        let source = state.source(uri.clone());

        let text = node.utf8_text(source.as_bytes()).map_err(|e| {
            error!("could not get source text: {}", e);
            Error::new(ErrorCode::InternalError)
        })?;

        let location = match node.kind() {
            "id" => resolve(&state, node, None, uri)
                .map(|d| Location::new(d.uri.as_ref().clone(), d.range)),
            "file" => {
                let file = PathBuf::from(text);
                load_to_file(
                    &file,
                    uri.as_ref(),
                    state.files().as_ref(),
                    state.prefixes().as_ref(),
                )
                .map(|uri| Location::new(uri.as_ref().clone(), Range::default()))
            }
            _ => None,
        };

        Ok(location.map(GotoDefinitionResponse::Scalar))
    }
}

/// Extract all error nodes under the given node.
fn _errors(n: tree_sitter::Node) -> Vec<tree_sitter::Node> {
    let mut cur = n.walk();

    let res = n.children(&mut cur).flat_map(_errors);

    if n.is_error() || n.is_missing() {
        res.chain(std::iter::once(n)).collect()
    } else {
        res.collect()
    }
}

/// Find decl with ID from the node up the tree and in all other loaded files.
fn resolve(
    snapshot: &Snapshot<Database>,
    node: tree_sitter::Node,
    scope: Option<tree_sitter::Node>,
    uri: Arc<Url>,
) -> Option<Decl> {
    let source = snapshot.source(uri.clone());

    // By default we interpret `node` as the scope.
    let scope = match scope {
        Some(s) => s,
        None => node,
    };

    match node.kind() {
        // If we are on an `expr` or `init` node unwrap it and work on whatever is inside.
        "expr" | "init" => {
            return node
                .named_child(0)
                .and_then(|c| resolve(snapshot, c, Some(scope), uri.clone()));
        }
        // If we are on a `field_access` or `field_check` search the rhs in the scope of the lhs.
        "field_access" | "field_check" => {
            let rhs = node.named_child(0)?;
            let lhs = node.named_child(1)?;

            return resolve(snapshot, lhs, Some(rhs), uri);
        }
        _ => {}
    }

    // If the ID is part of a field access or check resolve it in the referenced record.
    if let Some(p) = node.parent() {
        let id = node.utf8_text(source.as_bytes()).ok()?;

        if p.kind() == "field_access" || p.kind() == "field_check" {
            let lhs = node
                .prev_named_sibling()
                .and_then(|s| resolve(snapshot, s, Some(scope), uri.clone()))?;

            let typ = {
                let tree = snapshot.parse(uri.clone())?;
                let node = tree.root_node().named_descendant_for_point_range(
                    to_point(lhs.range.start).ok()?,
                    to_point(lhs.range.end).ok()?,
                )?;

                typ(snapshot, node, scope, &uri)?
            };

            let fields = match typ.kind {
                DeclKind::Type(fields) => fields,
                _ => return None,
            };

            // Find the given id in the fields.
            let field = fields.into_iter().find(|f| f.id == id);

            if field.is_some() {
                return field;
            }
        }
    }

    // Try to find a decl with name of the given node up the tree.
    let id = node.utf8_text(source.as_bytes()).ok()?;

    let mut node = node;
    let mut decl;
    loop {
        decl = query::decl_at(id, node, uri.clone(), source.as_bytes()).or(match node.kind() {
            "func_decl" => {
                // Synthesize declarations for function arguments. Ideally the grammar would expose
                // these directly.
                let func_params = node.named_child(1)?;
                assert_eq!(func_params.kind(), "func_params");

                let formal_args = func_params.named_child(0)?;
                assert_eq!(formal_args.kind(), "formal_args");

                for i in 0..formal_args.named_child_count() {
                    let arg = formal_args.named_child(i)?;
                    assert_eq!(arg.kind(), "formal_arg");

                    let arg_id_ = arg.named_child(0)?;
                    assert_eq!(arg_id_.kind(), "id");

                    let arg_id = arg_id_.utf8_text(source.as_bytes()).ok()?;
                    if arg_id != id {
                        continue;
                    }

                    return Some(Decl {
                        module: ModuleId::None,
                        id: arg_id.to_string(),
                        fqid: arg_id.to_string(),
                        kind: DeclKind::Variable,
                        is_export: None,
                        range: to_range(arg_id_.range()).ok()?,
                        selection_range: to_range(arg.range()).ok()?,
                        uri,
                        documentation: format!(
                            "```zeek\n{}\n```",
                            arg.utf8_text(source.as_bytes()).ok()?
                        ),
                    });
                }
                None
            }
            _ => None,
        });

        if decl.is_some() {
            return decl;
        }

        if let Some(p) = node.parent() {
            node = p;
        } else {
            break;
        }
    }

    // We haven't found a decl yet, look in loaded modules.
    snapshot
        .implicit_decls()
        .iter()
        .chain(snapshot.loaded_decls(uri).iter())
        .find(|d| d.fqid == id)
        .cloned()
}

/// Determine the type of the given node.
fn typ(
    snapshot: &Snapshot<Database>,
    node: tree_sitter::Node,
    scope: tree_sitter::Node,
    uri: &Arc<Url>,
) -> Option<Decl> {
    let source = snapshot.source(uri.clone());
    let source = source.as_bytes();

    let d = match node.kind() {
        "var_decl" | "formal_arg" => {
            let typ = node.named_child(1)?;

            match typ.kind() {
                "type" => resolve(snapshot, typ, Some(scope), uri.clone()),
                "initializer" => typ
                    .named_children(&mut typ.walk())
                    .find(|n| n.kind() == "init")
                    .and_then(|n| resolve(snapshot, n, Some(scope), uri.clone())),
                _ => None,
            }
        }
        "id" => {
            let parent = node.parent()?;
            parent
                .named_children(&mut parent.walk())
                .find_map(|n| match n.kind() {
                    "type" => resolve(snapshot, n, Some(scope), uri.clone()),
                    _ => None,
                })
        }
        _ => None,
    };

    // Perform additional unwrapping if needed.
    let d = match d.as_ref().map(|d| &d.kind) {
        // For function declarations produce the function's return type.
        Some(DeclKind::Func(Some(return_))) => {
            // FIXME(bbannier): if the return type cannot be resolved in this file, also look into
            // other files. In that case the string should probably contain a module scope.
            query::decl_at(return_, node, uri.clone(), source)
        }
        Some(DeclKind::Func(None)) => None,

        // Other kinds we return directly.
        _ => d,
    };

    d
}

fn to_symbol_kind(kind: &DeclKind) -> SymbolKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef => SymbolKind::VARIABLE,
        DeclKind::Option => SymbolKind::PROPERTY,
        DeclKind::Const => SymbolKind::CONSTANT,
        DeclKind::RedefEnum => SymbolKind::ENUM,
        DeclKind::RedefRecord => SymbolKind::INTERFACE,
        DeclKind::Type(_) => SymbolKind::CLASS,
        DeclKind::Func(_) => SymbolKind::FUNCTION,
        DeclKind::Hook => SymbolKind::OPERATOR,
        DeclKind::Event => SymbolKind::EVENT,
    }
}

fn to_completion_item(d: &Decl) -> CompletionItem {
    CompletionItem {
        label: d.fqid.clone(),
        kind: Some(to_completion_item_kind(&d.kind)),
        documentation: Some(Documentation::String(d.documentation.clone())),
        ..CompletionItem::default()
    }
}

fn to_completion_item_kind(kind: &DeclKind) -> CompletionItemKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef => CompletionItemKind::VARIABLE,
        DeclKind::Option => CompletionItemKind::PROPERTY,
        DeclKind::Const => CompletionItemKind::CONSTANT,
        DeclKind::RedefEnum => CompletionItemKind::ENUM,
        DeclKind::RedefRecord => CompletionItemKind::INTERFACE,
        DeclKind::Type(_) => CompletionItemKind::CLASS,
        DeclKind::Func(_) => CompletionItemKind::FUNCTION,
        DeclKind::Hook => CompletionItemKind::OPERATOR,
        DeclKind::Event => CompletionItemKind::EVENT,
    }
}

pub async fn run() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, messages) = LspService::new(|client| Backend {
        client: Some(client),
        state: Mutex::default(),
    });
    Server::new(stdin, stdout)
        .interleave(messages)
        .serve(service)
        .await;
}

#[cfg(test)]
mod test {
    use std::{
        collections::BTreeSet,
        path::PathBuf,
        str::FromStr,
        sync::{Arc, Mutex},
    };

    use insta::assert_debug_snapshot;
    use lspower::{
        lsp::{
            CompletionParams, HoverParams, PartialResultParams, Position, TextDocumentIdentifier,
            TextDocumentPositionParams, Url, WorkDoneProgressParams, WorkspaceSymbolParams,
        },
        LanguageServer,
    };
    use salsa::{ParallelDatabase, Snapshot};

    use crate::{lsp, parse::Parse, Files};

    use super::{Backend, ServerState};

    struct TestDatabase(lsp::Database);

    impl TestDatabase {
        fn new() -> Self {
            let mut db = lsp::Database::default();
            db.set_files(Arc::new(BTreeSet::new()));
            db.set_prefixes(Arc::new(Vec::new()));

            Self(db)
        }

        fn add_file(&mut self, uri: Arc<Url>, source: &str) {
            self.0.set_source(uri.clone(), Arc::new(source.to_string()));

            let mut files = self.0.files();
            let files = Arc::make_mut(&mut files);
            files.insert(uri);
            self.0.set_files(Arc::new(files.clone()));
        }

        fn add_prefix<P>(&mut self, prefix: P)
        where
            P: Into<PathBuf>,
        {
            let mut prefixes = self.0.prefixes();
            let prefixes = Arc::make_mut(&mut prefixes);
            prefixes.push(prefix.into());
            self.0.set_prefixes(Arc::new(prefixes.clone()));
        }

        fn snapshot(self) -> Snapshot<lsp::Database> {
            self.0.snapshot()
        }
    }

    fn serve(database: TestDatabase) -> Backend {
        Backend {
            client: None,
            state: Mutex::new(database.0),
        }
    }

    #[test]
    fn debug_database() {
        let db = TestDatabase::new();

        assert_eq!(format!("{:?}", db.0), "Database");
    }

    #[test]
    fn loaded_files() {
        let mut db = TestDatabase::new();

        // Prefix file both in file directory and in prefix. This should appear exactly once.
        let pre1 = PathBuf::from_str("/tmp/p").unwrap();
        let p1 = Arc::new(Url::from_file_path(pre1.join("p1/p1.zeek")).unwrap());
        db.add_prefix(pre1);
        db.add_file(p1.clone(), "");

        // Prefix file in external directory.
        let pre2 = PathBuf::from_str("/p").unwrap();
        let p2 = Arc::new(Url::from_file_path(pre2.join("p2/p2.zeek")).unwrap());
        db.add_prefix(pre2);
        db.add_file(p2.clone(), "");

        let foo = Arc::new(Url::from_file_path("/tmp/foo.zeek").unwrap());
        db.add_file(
            foo.clone(),
            "@load foo\n
             @load foo.zeek\n
             @load p1/p1\n
             @load p2/p2",
        );

        assert_debug_snapshot!(db.0.loaded_files(foo));
    }

    #[test]
    fn loaded_files_recursive() {
        let mut db = TestDatabase::new();

        let a = Arc::new(Url::from_file_path("/tmp/a.zeek").unwrap());
        db.add_file(
            a.clone(),
            "@load b\n
             @load d;",
        );

        let b = Arc::new(Url::from_file_path("/tmp/b.zeek").unwrap());
        db.add_file(b.clone(), "@load c");

        let c = Arc::new(Url::from_file_path("/tmp/c.zeek").unwrap());
        db.add_file(c.clone(), "@load d");

        let d = Arc::new(Url::from_file_path("/tmp/d.zeek").unwrap());
        db.add_file(d.clone(), "");

        assert_debug_snapshot!(db.0.loaded_files_recursive(a));
    }

    #[tokio::test]
    async fn symbol() {
        let mut db = TestDatabase::new();
        db.add_prefix("/p1");
        db.add_prefix("/p2");
        db.add_file(
            Arc::new(Url::from_file_path("/p1/a.zeek").unwrap()),
            "module mod_a; global A = 1;",
        );
        db.add_file(
            Arc::new(Url::from_file_path("/p2/b.zeek").unwrap()),
            "module mod_b; global B = 2;",
        );
        db.add_file(
            Arc::new(Url::from_file_path("/x/x.zeek").unwrap()),
            "module mod_x; global X = 3;",
        );

        let server = serve(db);

        let query = |q: &str| {
            server.symbol(WorkspaceSymbolParams {
                query: q.to_string(),
                ..WorkspaceSymbolParams::default()
            })
        };

        assert_debug_snapshot!(query("").await);
        assert_debug_snapshot!(query("mod").await);
        assert_debug_snapshot!(query("A").await);
        assert_debug_snapshot!(query("X").await);
        assert_debug_snapshot!(query("F").await);
    }

    #[tokio::test]
    async fn completion() {
        let mut db = TestDatabase::new();
        db.add_prefix("/p1");
        db.add_prefix("/p2");
        db.add_file(
            Arc::new(Url::from_file_path("/p1/a.zeek").unwrap()),
            "module mod_a; global A = 1;",
        );
        db.add_file(
            Arc::new(Url::from_file_path("/p2/b.zeek").unwrap()),
            "module mod_b; global B = 2;",
        );
        db.add_file(
            Arc::new(Url::from_file_path("/x/x.zeek").unwrap()),
            "module mod_x; global X = 3;",
        );

        let server = serve(db);

        let result = server
            .completion(CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(
                        Url::from_file_path("/x/x.zeek").unwrap(),
                    ),
                    position: Position::new(0, 0),
                },
                work_done_progress_params: WorkDoneProgressParams {
                    work_done_token: None,
                },
                partial_result_params: PartialResultParams {
                    partial_result_token: None,
                },
                context: None,
            })
            .await;

        assert_debug_snapshot!(result);
    }

    #[tokio::test]
    async fn hover_decl_in_func_parameters() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(uri.clone(), "function f(x: X, y: Y) {\ny;\n}");
        let server = serve(db);

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier::new(uri.as_ref().clone()),
                position: Position::new(1, 0),
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
        };

        assert_debug_snapshot!(server.hover(params).await);
    }

    #[test]
    fn resolve() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());

        db.add_file(
            uri.clone(),
            "module x;

type X: record {
    f1: count &optional;
};

type Y: record {
    yx: X &optional;
};

global c: count;
global x: X;

c;
x$f1;
x?$f1;

function fn(x2: X, y: count) {
    y;
    x2$f1;
    x2?$f1;
}

global y: Y;
y$yx$f1;
",
        );

        let db = db.snapshot();
        let source = db.source(uri.clone());
        let tree = db.parse(uri.clone()).unwrap();

        // `c` resolves to `local c: ...`.
        let node = tree
            .named_descendant_for_position(&Position::new(13, 0))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("c"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `s?$f1` resolves to `f1: count`.
        let node = tree
            .named_descendant_for_position(&Position::new(15, 3))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `y` resolves to `y: count` via function argument.
        let node = tree
            .named_descendant_for_position(&Position::new(18, 4))
            .unwrap();
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `x2$f1` resolves to `f1:count ...` via function argument.
        let node = tree
            .named_descendant_for_position(&Position::new(19, 7))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `x$f1` resolves to `f1: count ...`.
        let node = tree
            .named_descendant_for_position(&Position::new(14, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // `x2$f1` resolves to `f1: count ...`.
        let node = tree
            .named_descendant_for_position(&Position::new(20, 8))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));

        // Check resolution when multiple field accesses are involved.
        let node = tree
            .named_descendant_for_position(&Position::new(24, 5))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f1"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri.clone()));
    }

    #[test]
    fn resolve_initializer() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());

        db.add_file(
            uri.clone(),
            "module x;
type X: record { f: count &optional; };
function fun(): X { return X(); }
global x = fun();
x$f;",
        );

        let db = db.snapshot();
        let source = db.source(uri.clone());
        let tree = db.parse(uri.clone()).unwrap();

        let node = tree
            .named_descendant_for_position(&Position::new(4, 2))
            .unwrap();
        assert_eq!(node.utf8_text(source.as_bytes()), Ok("f"));
        assert_debug_snapshot!(super::resolve(&db, node, None, uri));
    }
}
