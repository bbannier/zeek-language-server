use crate::{
    ast::{load_to_file, Ast},
    complete::complete,
    parse::Parse,
    query::{self, Decl, DeclKind, ModuleId, NodeLocation, Query},
    zeek, Client, Files,
};
use itertools::Itertools;
use salsa::{ParallelDatabase, Snapshot};
use std::{
    collections::BTreeSet,
    fmt::Debug,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tower_lsp::{
    jsonrpc::{Error, Result},
    lsp_types::{
        notification::Progress,
        request::{
            GotoDeclarationResponse, GotoImplementationParams, GotoImplementationResponse,
            WorkDoneProgressCreate,
        },
        CompletionOptions, CompletionParams, CompletionResponse, DeclarationCapability, Diagnostic,
        DiagnosticSeverity, DidChangeTextDocumentParams, DidChangeWatchedFilesParams,
        DidOpenTextDocumentParams, DidSaveTextDocumentParams, DocumentFormattingParams,
        DocumentSymbol, DocumentSymbolParams, DocumentSymbolResponse, FileChangeType, FileEvent,
        FoldingRange, FoldingRangeParams, FoldingRangeProviderCapability, GotoDefinitionParams,
        GotoDefinitionResponse, Hover, HoverContents, HoverParams, HoverProviderCapability,
        ImplementationProviderCapability, InitializeParams, InitializeResult, InitializedParams,
        Location, MarkedString, MessageType, OneOf, ParameterInformation, ParameterLabel, Position,
        ProgressParams, ProgressParamsValue, ProgressToken, Range, ServerCapabilities, ServerInfo,
        SignatureHelp, SignatureHelpOptions, SignatureHelpParams, SignatureInformation,
        SymbolInformation, SymbolKind, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit,
        Url, WorkDoneProgress, WorkDoneProgressBegin, WorkDoneProgressCreateParams,
        WorkDoneProgressEnd, WorkDoneProgressReport, WorkspaceSymbolParams,
    },
    LanguageServer, LspService, Server,
};
use tracing::{error, instrument, trace_span, warn};
use walkdir::WalkDir;

#[cfg(test)]
pub(crate) use test::TestDatabase;

#[salsa::database(
    crate::ast::AstStorage,
    crate::parse::ParseStorage,
    crate::query::QueryStorage,
    crate::FilesStorage,
    crate::ClientStorage
)]
#[derive(Default)]
pub struct Database {
    storage: salsa::Storage<Self>,
}

impl Database {
    fn file_changed(&self, uri: Arc<Url>) {
        // Precompute decls in this file.
        let _d = self.decls(uri);
    }
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

#[derive(Debug)]
pub(crate) struct Backend {
    client: Option<tower_lsp::Client>,
    state: Mutex<Database>,
}

impl Backend {
    async fn warn_message<M>(&self, message: M)
    where
        M: std::fmt::Display,
    {
        if let Some(client) = &self.client {
            // Show warnings to the user.
            client.show_message(MessageType::WARNING, message).await;
        }
    }

    fn with_state<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(Snapshot<Database>) -> R,
    {
        let db = self
            .state
            .lock()
            .map_err(|_| Error::internal_error())?
            .snapshot();
        Ok(f(db))
    }

    fn with_state_mut<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Database) -> R,
    {
        let mut db = self.state.lock().map_err(|_| Error::internal_error())?;
        Ok(f(&mut db))
    }

    async fn progress_begin<T>(&self, title: T) -> Option<ProgressToken>
    where
        T: Into<String> + std::fmt::Display,
    {
        // Short circuit progress report if client doesn't support it.
        if !self
            .with_state(|s| {
                s.capabilities()
                    .window
                    .as_ref()
                    .and_then(|w| w.work_done_progress)
                    .unwrap_or(false)
            })
            .ok()?
        {
            return None;
        }

        let token = ProgressToken::String(format!("zeek-language-server/{}", &title));

        if let Some(client) = &self.client {
            client
                .send_request::<WorkDoneProgressCreate>(WorkDoneProgressCreateParams {
                    token: token.clone(),
                })
                .await
                .ok()?;

            let params = ProgressParams {
                token: token.clone(),
                value: ProgressParamsValue::WorkDone(WorkDoneProgress::Begin(
                    WorkDoneProgressBegin {
                        title: title.into(),
                        ..WorkDoneProgressBegin::default()
                    },
                )),
            };
            client.send_notification::<Progress>(params).await;
        }

        Some(token)
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
            client.send_notification::<Progress>(params).await;
        }
    }

    async fn progress(&self, token: Option<ProgressToken>, message: Option<String>) {
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
                        percentage: None,
                        ..WorkDoneProgressReport::default()
                    },
                )),
            };

            client.send_notification::<Progress>(params).await;
        }
    }

    async fn file_changed(&self, uri: Arc<Url>) -> Result<()> {
        if let Some(client) = &self.client {
            let diags = self.with_state(|state| {
                state.file_changed(uri.clone());

                let tree = match state.parse(uri.clone()) {
                    Some(t) => t,
                    None => return Vec::new(),
                };

                tree.root_node()
                    .errors()
                    .into_iter()
                    .map(|err| {
                        Diagnostic::new(
                            err.range(),
                            Some(DiagnosticSeverity::WARNING),
                            None,
                            None,
                            err.error(),
                            None,
                            None,
                        )
                    })
                    .collect()
            })?;

            client
                .publish_diagnostics(uri.as_ref().clone(), diags, None)
                .await;
        }

        Ok(())
    }

    async fn visible_files(&self) -> Result<Vec<Url>> {
        let system_files = zeek::system_files()
            .await
            .map_err(|e| {
                error!("could not read system files: {e}");
                Error::internal_error()
            })?
            .into_iter()
            .filter_map(|f| Url::from_file_path(f.path).ok());

        let workspace_folders = self.with_state(|s| s.workspace_folders())?;

        let workspace_files = workspace_folders
            .iter()
            .filter_map(|f| f.to_file_path().ok())
            .flat_map(|dir| {
                WalkDir::new(dir)
                    .into_iter()
                    .filter_map(std::result::Result::ok)
                    .filter(|e| !e.file_type().is_dir())
                    .filter_map(|f| {
                        if f.path().extension()? == "zeek" {
                            Url::from_file_path(f.path()).ok()
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            });

        Ok(system_files.chain(workspace_files).collect())
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    #[instrument]
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        // Check prerequistes.
        if let Err(e) = zeek::prefixes(None).await {
            self.warn_message(format!(
                "cannot detect Zeek prefixes, results will be incomplete or incorrect: {e}"
            ))
            .await;
        }

        let workspace_folders = params
            .workspace_folders
            .map_or_else(Vec::new, |xs| xs.into_iter().map(|x| x.uri).collect());

        self.with_state_mut(move |state| {
            state.set_files(Arc::new(BTreeSet::new()));
            state.set_prefixes(Arc::new(Vec::new()));
            state.set_workspace_folders(Arc::new(workspace_folders));
            state.set_capabilities(Arc::new(params.capabilities));
        })?;

        // Set system prefixes.
        match zeek::prefixes(None).await {
            Ok(prefixes) => {
                self.with_state_mut(move |state| {
                    state.set_prefixes(Arc::new(prefixes));
                })?;
            }
            Err(e) => error!("{e}"),
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
                    trigger_characters: Some(vec!["$".into()]),
                    ..CompletionOptions::default()
                }),
                declaration_provider: Some(DeclarationCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                implementation_provider: Some(ImplementationProviderCapability::Simple(true)),
                signature_help_provider: Some(SignatureHelpOptions {
                    trigger_characters: Some(vec!["(".into(), ",".into()]),
                    ..SignatureHelpOptions::default()
                }),
                folding_range_provider: Some(FoldingRangeProviderCapability::Simple(true)),
                document_formatting_provider: Some(OneOf::Left(zeek::has_format().await)),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: env!("CARGO_PKG_NAME").to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    #[instrument]
    async fn initialized(&self, _: InitializedParams) {
        // Load all currently visible files. These are likely only files in system prefixes.
        if let Ok(files) = self.visible_files().await {
            let update = self.did_change_watched_files(DidChangeWatchedFilesParams {
                changes: files
                    .into_iter()
                    .map(|f| FileEvent::new(f, FileChangeType::CREATED))
                    .collect(),
            });
            update.await;
        }
    }

    #[instrument]
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    #[instrument]
    async fn did_change_watched_files(&self, params: DidChangeWatchedFilesParams) {
        let _update_files = self.with_state_mut(|s| {
            // Create new list of files and update individual sources.
            let mut files = s.files().as_ref().clone();

            {
                let span = trace_span!("updating");
                let _enter = span.enter();
                for change in params.changes {
                    let uri = Arc::new(change.uri);

                    match change.typ {
                        FileChangeType::DELETED => {
                            files.remove(uri.as_ref());
                            continue;
                        }
                        FileChangeType::CREATED => {
                            files.insert(uri.clone());
                        }
                        _ => {}
                    }

                    // At this point we are working with CREATED or CHANGED events.

                    // TODO(bbannier): Parallelize file reading.
                    let source = match std::fs::read_to_string(uri.path()) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("failed to read '{}': {}", &uri, e);
                            continue;
                        }
                    };

                    s.set_source(uri.clone(), Arc::new(source));
                }
            }

            let files = Arc::new(files);

            // Commit new file list.
            s.set_files(files);
        });

        // Preload expensive information. Ultimately we want to be able to load implicit
        // declarations quickly since they are on the critical part of getting the user to useful
        // completions right after server startup.
        //
        // We explicitly precompute per-file information here so we can parallelize this work.

        let progress_token = self.progress_begin("Indexing").await;

        self.progress(progress_token.clone(), Some("declarations".to_string()))
            .await;
        let files = match self.with_state(|s| s.files().as_ref().clone()) {
            Ok(xs) => xs,
            Err(_) => return,
        };

        if let Ok(preloaded_decls) = self.with_state(|state| {
            let span = trace_span!("preloading");
            let _enter = span.enter();

            files
                .iter()
                .map(|f| {
                    let f = f.clone();
                    let db = state.snapshot();
                    tokio::spawn(async move {
                        let _x = db.decls(f.clone());
                        let _x = db.loads(f.clone());
                        let _x = db.loaded_files(f.clone());
                    })
                })
                .collect::<Vec<_>>()
        }) {
            futures::future::join_all(preloaded_decls).await;
        }

        // Reload implicit declarations.
        self.progress(progress_token.clone(), Some("implicit loads".to_string()))
            .await;
        let _implicit = self.with_state(|s| s.implicit_decls());

        self.progress_end(progress_token).await;
    }

    #[instrument]
    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let source = params.text_document.text;
        let uri = Arc::new(uri);

        let _set_files = self.with_state_mut(|state| {
            state.set_source(uri.clone(), Arc::new(source));

            let mut files = state.files();
            if !files.contains(&uri) {
                let files = Arc::make_mut(&mut files);
                files.insert(uri.clone());
                state.set_files(Arc::new(files.clone()));
            }
        });

        // Reload implicit declarations since their result depends on the list of known files and
        // is on the critical path for e.g., completion.
        let _implicit = self.with_state(|s| s.implicit_decls());

        if let Err(e) = self.file_changed(uri).await {
            error!("could not apply file change: {e}");
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

        let uri = Arc::new(params.text_document.uri);

        let source = changes.text.to_string();

        let _set_source = self.with_state_mut(|state| {
            state.set_source(uri.clone(), Arc::new(source));
        });

        if let Err(e) = self.file_changed(uri).await {
            error!("could not apply file change: {e}");
        }
    }

    #[instrument]
    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;

        let file = match uri.to_file_path() {
            Ok(p) => p,
            Err(_) => return,
        };

        // Figure out a directory to run the check from. If there is any workspace folder we just
        // pick the first one (TODO: this might be incorrect if there are multiple folders given);
        // else use the directory the file is in.
        let workspace_folder = self
            .with_state(|s| {
                s.workspace_folders()
                    .get(0)
                    .and_then(|f| f.to_file_path().ok())
            })
            .ok()
            .flatten();

        let file_dir = match file.parent() {
            Some(p) => p,
            None => return,
        };

        let checks = if let Some(folder) = workspace_folder {
            zeek::check(&file, folder).await
        } else {
            zeek::check(&file, file_dir).await
        };

        let checks = match checks {
            Ok(c) => c,
            Err(e) => {
                self.warn_message(format!("cannot run zeek for error checking: {e}"))
                    .await;
                return;
            }
        };

        let diags = checks
            .into_iter()
            // Only look at diagnostics for the saved file.
            // TODO(bbannier): We could look at all files here.
            .filter(|c| c.file == file.to_string_lossy())
            .map(|c| {
                // Zeek positions index starting with one.
                let line = if c.line == 0 { 0 } else { c.line - 1 };

                let position = Position::new(line, 0);
                // TODO(bbannier): More granular severity, distinguish between warnings and errors.
                Diagnostic::new(
                    Range::new(position, position),
                    None,
                    None,
                    Some("zeek".to_string()),
                    c.error,
                    None,
                    None,
                )
            })
            .collect();

        if let Some(client) = &self.client {
            client.publish_diagnostics(uri, diags, None).await;
        }
    }

    #[instrument]
    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let params = params.text_document_position_params;

        let uri = Arc::new(params.text_document.uri);

        self.with_state(move |state| {
            let source = state.source(uri.clone());

            let tree = state.parse(uri.clone());
            let tree = match tree.as_ref() {
                Some(t) => t,
                None => return Ok(None),
            };

            let node = tree.root_node();
            let node = match node.named_descendant_for_position(params.position) {
                Some(n) => n,
                None => return Ok(None),
            };

            let text = node.utf8_text(source.as_bytes()).map_err(|e| {
                error!("could not get source text: {}", e);
                Error::internal_error()
            })?;

            let mut contents = vec![
                #[cfg(debug_assertions)]
                MarkedString::LanguageString(tower_lsp::lsp_types::LanguageString {
                    value: text.into(),
                    language: "zeek".into(),
                }),
                #[cfg(debug_assertions)]
                MarkedString::LanguageString(tower_lsp::lsp_types::LanguageString {
                    value: node.to_sexp(),
                    language: "lisp".into(),
                }),
            ];

            match node.kind() {
                "id" => {
                    if let Some(decl) = &state.resolve(NodeLocation::from_node(uri, node)) {
                        let kind = match decl.kind {
                            DeclKind::Global => "global",
                            DeclKind::Option => "option",
                            DeclKind::Const => "constant",
                            DeclKind::Redef => "redef",
                            DeclKind::RedefEnum(_) => "redef enum",
                            DeclKind::RedefRecord(_) => "redef record",
                            DeclKind::Enum(_) => "enum",
                            DeclKind::Type(_) => "record",
                            DeclKind::FuncDef(_) | DeclKind::FuncDecl(_) => "function",
                            DeclKind::HookDef(_) | DeclKind::HookDecl(_) => "hook",
                            DeclKind::EventDef(_) | DeclKind::EventDecl(_) => "event",
                            DeclKind::Variable => "variable",
                            DeclKind::Field => "field",
                            DeclKind::EnumMember => "enum member",
                            DeclKind::LoopIndex(_, _) => "loop index",
                        };
                        contents.push(MarkedString::String(format!(
                            "### {kind} `{id}`",
                            id = decl.id
                        )));

                        if let Some(typ) = state.typ(decl.clone()) {
                            contents.push(MarkedString::String(format!("Type: `{}`", typ.id)));
                        }

                        contents.push(MarkedString::String(decl.documentation.clone()));
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
                        contents.push(MarkedString::String(format!("`{}`", uri.path())));
                    }
                }
                _ => {}
            }

            let hover = Hover {
                contents: HoverContents::Array(contents),
                range: Some(node.range()),
            };

            Ok(Some(hover))
        })?
    }

    #[instrument]
    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
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
                    DeclKind::Type(fields)
                    | DeclKind::RedefRecord(fields)
                    | DeclKind::Enum(fields)
                    | DeclKind::RedefEnum(fields) => Some(
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

        let modules = self.with_state(move |state| {
            // Even though a valid source file can only contain a single module, one can still make
            // declarations in other modules. Sort declarations by module so users get a clean view.
            // Then show declarations under their module, or at the top-level if they aren't exported
            // into a module.
            let decls = state.decls(uri);
            let mut decls = decls
                .iter()
                // Filter out top-level enum members since they are also exposed inside their enum here.
                .filter(|d| d.kind != DeclKind::EnumMember)
                .collect::<Vec<_>>();
            decls.sort_by_key(|d| format!("{}", d.module));
            let (decls_w_mod, decls_wo_mod): (Vec<_>, _) =
                decls.into_iter().partition(|d| d.module != ModuleId::None);

            decls_w_mod
                .into_iter()
                .group_by(|d| &d.module)
                .into_iter()
                .map(|(m, decls)| {
                    #[allow(deprecated)]
                    DocumentSymbol {
                        name: format!("{}", m),
                        kind: SymbolKind::NAMESPACE,
                        children: Some(decls.map(symbol).collect()),

                        // FIXME(bbannier): Weird ranges.
                        range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                        selection_range: Range::new(Position::new(0, 0), Position::new(0, 0)),

                        deprecated: None,

                        detail: None,
                        tags: None,
                    }
                })
                .chain(decls_wo_mod.into_iter().map(symbol))
                .collect()
        })?;

        Ok(Some(DocumentSymbolResponse::Nested(modules)))
    }

    #[instrument]
    async fn symbol(
        &self,
        params: WorkspaceSymbolParams,
    ) -> Result<Option<Vec<SymbolInformation>>> {
        let query = params.query.to_lowercase();

        let symbols = self.with_state(|state| {
            let files = state.files();
            files
                .iter()
                .flat_map(|uri| {
                    state
                        .decls(uri.clone())
                        .iter()
                        .filter(|d| {
                            rust_fuzzy_search::fuzzy_compare(&query, &d.fqid.to_lowercase()) > 0.0
                        })
                        .map(|d| {
                            let url: &Url = uri;

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
                })
                .collect()
        })?;

        Ok(Some(symbols))
    }

    #[instrument]
    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        self.with_state(move |state| complete(&state, params))
            .map_err(|_| Error::internal_error())
    }

    #[instrument]
    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let params = params.text_document_position_params;
        let uri = Arc::new(params.text_document.uri);
        let position = params.position;

        let location = self.with_state(|state| {
            let tree = state.parse(uri.clone());
            let tree = tree.as_ref()?;
            let node = tree.root_node().named_descendant_for_position(position)?;
            let source = state.source(uri.clone());

            match node.kind() {
                "id" => state
                    .resolve(NodeLocation::from_node(uri, node))
                    .map(|d| Location::new(d.uri.as_ref().clone(), d.range)),
                "file" => {
                    let text = node
                        .utf8_text(source.as_bytes())
                        .map_err(|e| {
                            error!("could not get source text: {}", e);
                            Error::internal_error()
                        })
                        .ok()?;

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
            }
        })?;

        Ok(location.map(GotoDefinitionResponse::Scalar))
    }

    #[instrument]
    async fn signature_help(&self, params: SignatureHelpParams) -> Result<Option<SignatureHelp>> {
        let uri = Arc::new(params.text_document_position_params.text_document.uri);
        let position = params.text_document_position_params.position;

        self.with_state(move |state| {
            let source = state.source(uri.clone());
            let tree = match state.parse(uri.clone()) {
                Some(t) => t,
                None => return Ok(None),
            };

            // TODO(bbannier): We do not handle newlines between the function name and any ultimate parameter.
            let line = match source.lines().nth(position.line as usize) {
                Some(l) => l,
                None => return Ok(None),
            };
            #[allow(clippy::cast_possible_truncation)]
            let line = if (line.len() + 1) as u32 > position.character {
                &line[..position.character as usize]
            } else {
                return Ok(None);
            };

            // Search backward in the line for '('. The identifier before that could be a function name.
            let node = match line
                .chars()
                .rev()
                .enumerate()
                .filter(|(_, c)| !char::is_whitespace(*c))
                .skip_while(|(_, c)| c != &'(')
                .nth(1)
                .and_then(|(i, _)| {
                    #[allow(clippy::cast_possible_truncation)]
                    let character = (line.len() - i - 1) as u32;
                    tree.root_node().named_descendant_for_position(Position {
                        character,
                        ..position
                    })
                }) {
                Some(n) => n,
                None => return Ok(None),
            };

            #[allow(clippy::cast_possible_truncation)]
            let active_parameter = Some(line.chars().filter(|c| c == &',').count() as u32);

            let id = match node.utf8_text(source.as_bytes()) {
                Ok(id) => id,
                Err(_) => return Ok(None),
            };

            let f = match state.resolve_id(Arc::new(id.into()), NodeLocation::from_node(uri, node))
            {
                Some(f) => f,
                _ => return Ok(None),
            };

            let signature = match &f.kind {
                DeclKind::FuncDecl(s)
                | DeclKind::FuncDef(s)
                | DeclKind::EventDecl(s)
                | DeclKind::EventDef(s)
                | DeclKind::HookDecl(s)
                | DeclKind::HookDef(s) => s,
                _ => return Ok(None),
            };

            // Recompute `tree` and `source` in the context of the function declaration.
            let tree = match state.parse(f.uri.clone()) {
                Some(t) => t,
                None => return Ok(None),
            };
            let source = state.source(f.uri.clone());

            let label = format!(
                "{}({})",
                f.id,
                signature
                    .args
                    .iter()
                    .filter_map(|a| {
                        tree.root_node()
                            .named_descendant_for_point_range(a.selection_range)?
                            .utf8_text(source.as_bytes())
                            .ok()
                    })
                    .join(", ")
            );

            let parameters = Some(
                signature
                    .args
                    .iter()
                    .map(|a| ParameterInformation {
                        label: ParameterLabel::Simple(a.id.clone()),
                        documentation: None,
                    })
                    .collect(),
            );

            Ok(Some(SignatureHelp {
                signatures: vec![SignatureInformation {
                    label,
                    documentation: None,
                    parameters,
                    active_parameter,
                }],
                active_signature: None,
                active_parameter,
            }))
        })?
    }

    #[instrument]
    async fn folding_range(&self, params: FoldingRangeParams) -> Result<Option<Vec<FoldingRange>>> {
        fn compute_folds(n: query::Node, include_self: bool) -> Vec<FoldingRange> {
            let range = n.range();
            let mut folds = if include_self {
                vec![FoldingRange {
                    start_line: range.start.line,
                    start_character: Some(range.start.character),
                    end_line: range.end.line,
                    end_character: Some(range.end.character),
                    kind: None,
                }]
            } else {
                Vec::new()
            };

            for child in n.named_children_not("nl") {
                folds.extend(compute_folds(child, true));
            }

            folds
        }

        let tree = self.with_state(|state| state.parse(Arc::new(params.text_document.uri)))?;

        Ok(tree.map(|t| compute_folds(t.root_node(), false)))
    }

    #[instrument]
    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = Arc::new(params.text_document.uri);

        let source = self.with_state(|state| Some(state.source(uri)))?;

        let source = match source {
            Some(s) => s,
            None => return Ok(None),
        };

        let num_lines = u32::try_from(source.lines().count()).expect("too many lines");
        let end = u32::try_from(source.lines().last().map_or(0, str::len)).expect("line too long");
        let end = Position::new(num_lines, end);
        let range = Range::new(Position::new(0, 0), end);

        let formatted = if let Ok(f) = zeek::format(&source).await {
            f
        } else {
            // Swallow errors from zeek-format, we likely already emitted a diagnostic.
            return Ok(None);
        };

        // The edit consists of removing the original source range, and inserting the new text
        // after that (edits cannot overlap).
        Ok(Some(vec![
            TextEdit::new(range, String::new()),
            TextEdit::new(Range::new(end, end), formatted),
        ]))
    }

    #[instrument]
    async fn goto_declaration(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDeclarationResponse>> {
        let params = params.text_document_position_params;
        let uri = Arc::new(params.text_document.uri);
        let position = params.position;

        let decl = self.with_state(|state| {
            let tree = state.parse(uri.clone());
            let tree = tree.as_ref()?;
            let node = tree.root_node().named_descendant_for_position(position)?;

            let decl = state.resolve(NodeLocation::from_node(uri.clone(), node))?;

            match &decl.kind {
                // We are done as we have found a declaration.
                DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_) => {
                    Some(decl.as_ref().clone())
                }
                // If we resolved to a definition, look for the declaration.
                DeclKind::EventDef(_) | DeclKind::FuncDef(_) | DeclKind::HookDef(_) => state
                    .decls(uri.clone())
                    .iter()
                    .chain(state.implicit_decls().iter())
                    .chain(state.explicit_decls_recursive(uri).iter())
                    .filter(|&d| {
                        matches!(
                            &d.kind,
                            DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_)
                        )
                    })
                    .find(|&d| d.id == decl.id)
                    .map(Clone::clone),
                _ => None,
            }
        })?;

        Ok(decl.map(|d| {
            GotoDeclarationResponse::Scalar(Location::new(d.uri.as_ref().clone(), d.range))
        }))
    }

    #[instrument]
    async fn goto_implementation(
        &self,
        params: GotoImplementationParams,
    ) -> Result<Option<GotoImplementationResponse>> {
        let params = params.text_document_position_params;
        let uri = Arc::new(params.text_document.uri);
        let position = params.position;

        let response = self.with_state(|state| {
            let tree = state.parse(uri.clone());
            let tree = tree.as_ref()?;
            let node = tree.root_node().named_descendant_for_position(position)?;

            let decl = state.resolve(NodeLocation::from_node(uri, node))?;

            match &decl.kind {
                DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_) => {}
                _ => return None,
            }

            Some(
                state
                    .files()
                    .iter()
                    .flat_map(|f| {
                        state
                            .decls(f.clone())
                            .as_ref()
                            .clone()
                            .into_iter()
                            .collect::<Vec<_>>()
                    })
                    .filter(|d| {
                        matches!(
                            &d.kind,
                            DeclKind::EventDef(_) | DeclKind::FuncDef(_) | DeclKind::HookDef(_)
                        )
                    })
                    .filter_map(|d| {
                        if d.id == decl.id {
                            Some(Location::new(d.uri.as_ref().clone(), d.range))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        })?;

        Ok(response.map(GotoImplementationResponse::from))
    }
}

fn to_symbol_kind(kind: &DeclKind) -> SymbolKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef | DeclKind::LoopIndex(_, _) => {
            SymbolKind::VARIABLE
        }
        DeclKind::Option => SymbolKind::PROPERTY,
        DeclKind::Const => SymbolKind::CONSTANT,
        DeclKind::Enum(_) | DeclKind::RedefEnum(_) => SymbolKind::ENUM,
        DeclKind::Type(_) | DeclKind::RedefRecord(_) => SymbolKind::CLASS,
        DeclKind::FuncDecl(_) | DeclKind::FuncDef(_) => SymbolKind::FUNCTION,
        DeclKind::HookDecl(_) | DeclKind::HookDef(_) => SymbolKind::OPERATOR,
        DeclKind::EventDecl(_) | DeclKind::EventDef(_) => SymbolKind::EVENT,
        DeclKind::Field => SymbolKind::FIELD,
        DeclKind::EnumMember => SymbolKind::ENUM_MEMBER,
    }
}

pub async fn run() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| Backend {
        client: Some(client),
        state: Mutex::default(),
    });
    Server::new(stdin, stdout, socket).serve(service).await;
}

#[cfg(test)]
pub(crate) mod test {
    use std::{
        collections::BTreeSet,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use insta::assert_debug_snapshot;
    use salsa::{ParallelDatabase, Snapshot};
    use tower_lsp::{
        lsp_types::{
            CompletionParams, CompletionResponse, FormattingOptions, HoverParams,
            PartialResultParams, Position, TextDocumentIdentifier, TextDocumentPositionParams, Url,
            WorkDoneProgressParams, WorkspaceSymbolParams,
        },
        LanguageServer,
    };

    use crate::{ast::Ast, lsp, Files};

    use super::Backend;

    pub(crate) struct TestDatabase(pub(crate) lsp::Database);

    impl TestDatabase {
        pub(crate) fn new() -> Self {
            let mut db = lsp::Database::default();
            db.set_files(Arc::new(BTreeSet::new()));
            db.set_prefixes(Arc::new(Vec::new()));

            Self(db)
        }

        pub(crate) fn add_file(&mut self, uri: Arc<Url>, source: &str) {
            self.0.set_source(uri.clone(), Arc::new(source.to_string()));

            let mut files = self.0.files();
            let files = Arc::make_mut(&mut files);
            files.insert(uri);
            self.0.set_files(Arc::new(files.clone()));
        }

        pub(crate) fn add_prefix<P>(&mut self, prefix: P)
        where
            P: Into<PathBuf>,
        {
            let mut prefixes = self.0.prefixes();
            let prefixes = Arc::make_mut(&mut prefixes);
            prefixes.push(prefix.into());
            self.0.set_prefixes(Arc::new(prefixes.clone()));
        }

        pub(crate) fn snapshot(self) -> Snapshot<lsp::Database> {
            self.0.snapshot()
        }
    }

    pub(crate) fn serve(database: TestDatabase) -> Backend {
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

        let uri = Arc::new(Url::from_file_path("/x/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "module mod_x;
@load a
@load b
global X = 3;
global mod_x::Z = 3;
global GLOBAL::Y = 3;
",
        );

        let server = serve(db);

        let result = server
            .completion(CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri.as_ref().clone()),
                    position: Position::new(6, 0),
                },
                partial_result_params: PartialResultParams::default(),
                work_done_progress_params: WorkDoneProgressParams::default(),
                context: None,
            })
            .await;

        // Sort results for debug output diffing.
        let result = match result {
            Ok(Some(CompletionResponse::Array(mut r))) => {
                r.sort_by(|a, b| a.label.cmp(&b.label));
                r
            }
            _ => panic!(),
        };

        assert_debug_snapshot!(result);
    }

    #[tokio::test]
    async fn hover_variable() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "
type X: record {};
global f: function(): X;
local x = f();
",
        );
        let server = serve(db);

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier::new(uri.as_ref().clone()),
                position: Position::new(3, 7),
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
        };

        assert_debug_snapshot!(server.hover(params).await);
    }

    #[tokio::test]
    async fn hover_decl_in_func_parameters() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "
type X: record {};
type Y: record {};
function f(x: X, y: Y) {
    y;
}",
        );
        let server = serve(db);

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier::new(uri.as_ref().clone()),
                position: Position::new(4, 4),
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
        };

        assert_debug_snapshot!(server.hover(params).await);
    }

    #[tokio::test]
    async fn signature_help() {
        let mut db = TestDatabase::new();
        let uri_x = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri_x.clone(),
            "module x;
global f: function(x: count, y: string): string;
local x = f(",
        );
        let uri_y = Arc::new(Url::from_file_path("/y.zeek").unwrap());
        db.add_file(
            uri_y.clone(),
            "module y;
global f: function(x: count, y: string): string;
local x = f(1,2,3",
        );
        let uri_z = Arc::new(Url::from_file_path("/z.zeek").unwrap());
        db.add_file(
            uri_z.clone(),
            "module z;
@load ./ext
local x = ext::f(",
        );
        db.add_file(
            Arc::new(Url::from_file_path("/ext.zeek").unwrap()),
            "module ext;
export {
global f: function(x: count, y: string): string;
}",
        );

        let server = serve(db);

        let params = super::SignatureHelpParams {
            context: None,
            text_document_position_params: TextDocumentPositionParams::new(
                TextDocumentIdentifier::new(uri_x.as_ref().clone()),
                Position::new(2, 12),
            ),
            work_done_progress_params: WorkDoneProgressParams::default(),
        };
        assert_debug_snapshot!(server.signature_help(params).await);

        let params = super::SignatureHelpParams {
            context: None,
            text_document_position_params: TextDocumentPositionParams::new(
                TextDocumentIdentifier::new(uri_y.as_ref().clone()),
                Position::new(2, 16),
            ),
            work_done_progress_params: WorkDoneProgressParams::default(),
        };
        assert_debug_snapshot!(server.signature_help(params).await);

        let params = super::SignatureHelpParams {
            context: None,
            text_document_position_params: TextDocumentPositionParams::new(
                TextDocumentIdentifier::new(uri_z.as_ref().clone()),
                Position::new(2, 17),
            ),
            work_done_progress_params: WorkDoneProgressParams::default(),
        };
        assert_debug_snapshot!(server.signature_help(params).await);
    }

    #[tokio::test]
    async fn goto_declaration() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri.clone(),
            "module x;
@load events.bif
global yeah: event(f:string);
event yeah(c:count) {}
event zeek_init() {}",
        );

        let uri_evts = Arc::new(Url::from_file_path("/events.bif.zeek").unwrap());
        db.add_file(uri_evts.clone(), "global zeek_init: event();");

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .goto_declaration(super::GotoDefinitionParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.as_ref().clone()),
                        Position::new(3, 8),
                    ),
                    partial_result_params: PartialResultParams::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .goto_declaration(super::GotoDefinitionParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.as_ref().clone()),
                        Position::new(4, 8),
                    ),
                    partial_result_params: PartialResultParams::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn goto_implementation() {
        let mut db = TestDatabase::new();
        let uri_evts = Arc::new(Url::from_file_path("/events.bif.zeek").unwrap());
        db.add_file(
            uri_evts.clone(),
            "export {
global zeek_init: event();",
        );

        let uri_x = Arc::new(Url::from_file_path("/x.zeek").unwrap());
        db.add_file(
            uri_x.clone(),
            "module x;
@load events.bif
export { global foo: event(); }
event zeek_init() {}
event zeek_init() {}
event foo() {}
event x::foo() {}",
        );

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .goto_implementation(super::GotoImplementationParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri_evts.as_ref().clone()),
                        Position::new(1, 11)
                    ),
                    partial_result_params: PartialResultParams::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .goto_implementation(super::GotoImplementationParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri_x.as_ref().clone()),
                        Position::new(2, 17)
                    ),
                    partial_result_params: PartialResultParams::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[ignore]
    #[tokio::test]
    async fn formatting() {
        let mut db = TestDatabase::new();
        let uri_ok = Arc::new(Url::from_file_path("/ok.zeek").unwrap());
        db.add_file(uri_ok.clone(), "event zeek_init(){}");

        let uri_invalid = Arc::new(Url::from_file_path("/invalid.zeek").unwrap());
        db.add_file(uri_invalid.clone(), "event ssl");

        let server = serve(db);

        assert!(server
            .formatting(super::DocumentFormattingParams {
                text_document: TextDocumentIdentifier {
                    uri: uri_ok.as_ref().clone(),
                },
                options: FormattingOptions::default(),
                work_done_progress_params: WorkDoneProgressParams::default(),
            })
            .await
            .is_ok());

        assert_eq!(
            server
                .formatting(super::DocumentFormattingParams {
                    text_document: TextDocumentIdentifier {
                        uri: uri_invalid.as_ref().clone(),
                    },
                    options: FormattingOptions::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await,
            Ok(None)
        );
    }
}
