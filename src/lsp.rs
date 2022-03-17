use crate::{
    ast::{self, load_to_file, Ast},
    parse::Parse,
    query::{self, Decl, DeclKind, ModuleId, NodeLocation, Query},
    zeek, Files,
};
use itertools::Itertools;
use lspower::{
    jsonrpc::{Error, Result},
    lsp::{
        notification::Progress,
        request::{
            GotoDeclarationResponse, GotoImplementationParams, GotoImplementationResponse,
            WorkDoneProgressCreate,
        },
        CompletionItem, CompletionItemKind, CompletionOptions, CompletionParams,
        CompletionResponse, DeclarationCapability, Diagnostic, DiagnosticSeverity,
        DidChangeTextDocumentParams, DidChangeWatchedFilesParams, DidOpenTextDocumentParams,
        DidSaveTextDocumentParams, DocumentFormattingParams, DocumentSymbol, DocumentSymbolParams,
        DocumentSymbolResponse, Documentation, FileChangeType, FileEvent, FoldingRange,
        FoldingRangeParams, FoldingRangeProviderCapability, GotoDefinitionParams,
        GotoDefinitionResponse, Hover, HoverContents, HoverParams, HoverProviderCapability,
        ImplementationProviderCapability, InitializeParams, InitializeResult, InitializedParams,
        Location, MarkedString, MarkupContent, MessageType, OneOf, ParameterInformation,
        ParameterLabel, Position, ProgressParams, ProgressParamsValue, ProgressToken, Range,
        ServerCapabilities, ServerInfo, SignatureHelp, SignatureHelpOptions, SignatureHelpParams,
        SignatureInformation, SymbolInformation, SymbolKind, TextDocumentSyncCapability,
        TextDocumentSyncKind, TextEdit, Url, WorkDoneProgress, WorkDoneProgressBegin,
        WorkDoneProgressCreateParams, WorkDoneProgressEnd, WorkDoneProgressReport,
        WorkspaceSymbolParams,
    },
    Client, LanguageServer, LspService, Server, TokenCanceller,
};
use salsa::{ParallelDatabase, Snapshot};
use std::{
    collections::{BTreeSet, HashSet},
    fmt::Debug,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};
use tracing::{error, instrument, warn};
use walkdir::WalkDir;

#[cfg(test)]
pub(crate) use test::TestDatabase;

#[salsa::database(
    crate::ast::AstStorage,
    crate::parse::ParseStorage,
    crate::query::QueryStorage,
    crate::FilesStorage
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
struct Backend {
    client: Option<Client>,
    state: Mutex<Database>,
}

impl Backend {
    async fn info_message<M>(&self, message: M)
    where
        M: std::fmt::Display,
    {
        if let Some(client) = &self.client {
            // Send these to the log by default.
            client.log_message(MessageType::INFO, message).await;
        }
    }

    async fn warn_message<M>(&self, message: M)
    where
        M: std::fmt::Display,
    {
        if let Some(client) = &self.client {
            // Show warnings to the user.
            client.show_message(MessageType::WARNING, message).await;
        }
    }

    fn state(&self) -> Result<Snapshot<Database>> {
        self.state_mut().map(|d| d.snapshot())
    }

    fn state_mut(&self) -> Result<MutexGuard<Database>> {
        self.state.lock().map_err(|_| Error::internal_error())
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

    async fn file_changed(&self, uri: Arc<Url>) -> Result<()> {
        let state = self.state()?;

        state.file_changed(uri.clone());

        if let Some(client) = &self.client {
            let tree = match state.parse(uri.clone()) {
                Some(t) => t,
                None => return Ok(()),
            };

            let diags = tree
                .root_node()
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
                .collect();

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

        let workspace_folders = self.state()?.workspace_folders();

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

#[lspower::async_trait]
impl LanguageServer for Backend {
    #[instrument]
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        // Check prerequistes.
        if let Err(e) = zeek::prefixes().await {
            self.warn_message(format!(
                "cannot detect Zeek prefixes, results will be incomplete or incorrect: {e}"
            ))
            .await;
        }

        let workspace_folders = params
            .workspace_folders
            .map_or_else(Vec::new, |xs| xs.into_iter().map(|x| x.uri).collect());

        if let Ok(mut state) = self.state_mut() {
            state.set_files(Arc::new(BTreeSet::new()));
            state.set_prefixes(Arc::new(Vec::new()));
            state.set_workspace_folders(Arc::new(workspace_folders));
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
        match zeek::prefixes().await {
            Ok(prefixes) => {
                if let Ok(mut state) = self.state_mut() {
                    state.set_prefixes(Arc::new(prefixes));
                }
            }
            Err(e) => error!("{e}"),
        }

        // Load all visible files.
        if let Ok(files) = self.visible_files().await {
            self.did_change_watched_files(DidChangeWatchedFilesParams {
                changes: files
                    .into_iter()
                    .map(|f| FileEvent::new(f, FileChangeType::CREATED))
                    .collect(),
            })
            .await;
        }

        self.info_message("server initialized!").await;
    }

    #[instrument]
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    #[instrument]
    async fn did_change_watched_files(&self, params: DidChangeWatchedFilesParams) {
        let progress_token = self.progress_begin("Indexing").await.ok();

        // Create new list of files and update individual sources.
        let mut files = match self.state() {
            Ok(s) => s.files().as_ref().clone(),
            Err(e) => {
                error!("could not get current state: {e}");
                return;
            }
        };

        for change in params.changes {
            let uri = Arc::new(change.uri);

            #[allow(clippy::cast_possible_truncation)]
            self.progress(progress_token.clone(), Some(uri.path().to_string()), None)
                .await;

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

            if let Ok(mut state) = self.state_mut() {
                state.set_source(uri.clone(), Arc::new(source));
            };
        }

        let files = Arc::new(files);

        // Commit new file list.
        if let Ok(mut state) = self.state_mut() {
            state.set_files(files.clone());
        }

        // Preload expensive information. Ultimately we want to be able to load implicit
        // declarations quickly since they are on the critical part of getting the user to useful
        // completions right after server startup.
        //
        // We explicitly precompute per-file information here so we can parallelize this work.
        if let Ok(state) = self.state() {
            let mut _preload_decls = Vec::new();
            for f in files.as_ref() {
                let f = f.clone();
                let db = state.snapshot();
                _preload_decls.push(tokio::spawn(async move {
                    let _x = db.decls(f.clone());
                    let _x = db.loads(f.clone());
                    let _x = db.loaded_files(f.clone());
                }));
            }
            futures::future::join_all(_preload_decls).await;
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
        let uri = Arc::new(uri);

        if let Ok(mut state) = self.state_mut() {
            state.set_source(uri.clone(), Arc::new(source));

            let mut files = state.files();
            if !files.contains(&uri) {
                let files = Arc::make_mut(&mut files);
                files.insert(uri.clone());
                state.set_files(Arc::new(files.clone()));
            }
        }

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

        if let Ok(mut state) = self.state_mut() {
            state.set_source(uri.clone(), Arc::new(source));
        }

        if let Err(e) = self.file_changed(uri).await {
            error!("could not apply file change: {e}");
        }
    }

    #[instrument]
    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let state = match self.state() {
            Ok(s) => s,
            Err(_) => return,
        };

        let uri = params.text_document.uri;

        let file = match uri.to_file_path() {
            Ok(p) => p,
            Err(_) => return,
        };

        // Figure out a directory to run the check from. If there is any workspace folder we just
        // pick the first one (TODO: this might be incorrect if there are multiple folders given);
        // else use the directory the file is in.
        let workspace_folder = state
            .workspace_folders()
            .get(0)
            .and_then(|f| f.to_file_path().ok());

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

        let state = self.state()?;

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
            MarkedString::LanguageString(lspower::lsp::LanguageString {
                value: text.into(),
                language: "zeek".into(),
            }),
            #[cfg(debug_assertions)]
            MarkedString::LanguageString(lspower::lsp::LanguageString {
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

        let modules = decls_w_mod
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
        let uri = Arc::new(params.text_document_position.text_document.uri);
        let position = params.text_document_position.position;

        let state = self.state()?;

        let source = state.source(uri.clone());

        let tree = match state.parse(uri.clone()) {
            Some(t) => t,
            None => return Ok(None),
        };

        // Get the node directly under the cursor as a starting point.
        let root = tree.root_node();
        let mut node = match root.descendant_for_position(position) {
            Some(n) => n,
            None => return Ok(None),
        };

        // If the node has no interesting text try to find an earlier node with text.
        while node
            .utf8_text(source.as_bytes())
            .ok()
            // The grammar might expose newlines as AST nodes. Such nodes should be ignored for completion.
            .map(str::trim)
            // The grammar might expose `$` or `?$` in a node. Strip it away. This also takes care of
            // explicit nodes for just the field access or check.
            .map(|s| s.replace(&['$', '?'], ""))
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

        let text_at_completion = node
            .utf8_text(source.as_bytes())
            // This shouldn't happen; if we cannot get the node text there is some UTF-8 error.
            .map_err(|_| Error::internal_error())?
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
            if let Some(r) = state.resolve(NodeLocation::from_node(uri.clone(), node)) {
                let decl = state.typ(r);

                // Compute completion.
                if let Some(decl) = decl {
                    if let DeclKind::Type(fields) = &decl.kind {
                        return Ok(Some(CompletionResponse::from(
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
                        )));
                    }
                }
            }
        }

        // If we are completing a file return valid load patterns.
        if node.kind() == "file" {
            return Ok(Some(CompletionResponse::from(
                state
                    .possible_loads(uri)
                    .iter()
                    .map(|load| CompletionItem {
                        label: load.clone(),
                        kind: Some(CompletionItemKind::FILE),
                        ..CompletionItem::default()
                    })
                    .collect::<Vec<_>>(),
            )));
        }

        // If we are completing a function/event/hook definition complete from declarations.
        if node.kind() == "id" {
            if let Some(kind) = source
                .lines()
                .nth(usize::try_from(node.range().start.line).expect("too many lines"))
                .and_then(|line| {
                    let re = regex::Regex::new(r"^(\w+)\s+\w*").expect("invalid regexp");
                    Some(re.captures(line)?.get(1)?.as_str())
                })
            {
                return Ok(Some(CompletionResponse::from(
                    state
                        .decls(uri.clone())
                        .iter()
                        .chain(state.implicit_decls().iter())
                        .chain(state.explicit_decls_recursive(uri.clone()).iter())
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
                                DeclKind::EventDecl(s)
                                | DeclKind::FuncDecl(s)
                                | DeclKind::HookDecl(s) => {
                                    let args = &s.args;
                                    Some(
                                        args.iter()
                                            .filter_map(|d| {
                                                let tree = state.parse(d.uri.clone())?;
                                                let source = state.source(d.uri.clone());
                                                tree.root_node()
                                                    .named_descendant_for_point_range(
                                                        d.selection_range,
                                                    )?
                                                    .utf8_text(source.as_bytes())
                                                    .map(String::from)
                                                    .ok()
                                            })
                                            .join(", "),
                                    )
                                }
                                _ => None,
                            }?;

                            Some(CompletionItem {
                                label: format!("{id}({signature}) {{}}", id = item.label),
                                ..item
                            })
                        })
                        .collect::<Vec<_>>(),
                )));
            }
        }

        // We are just completing some arbitrary identifier at this point.
        let mut items = HashSet::new();
        let mut node = node;

        let current_module = root
            .named_child("module_decl")
            .and_then(|m| m.named_child("id"))
            .and_then(|id| id.utf8_text(source.as_bytes()).ok());

        loop {
            for d in query::decls_(node, uri.clone(), source.as_bytes()) {
                // Slightly fudge the ID we use for local declarations by removing the current
                // module from the FQID.
                let fqid = match current_module {
                    Some(mid) => {
                        let id = d.fqid.as_str();
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
                !ast::is_redef(i) &&
                // Only return external decls which somehow match the text to complete to keep the response sent to the client small.
                if let Some(text) = text_at_completion {
                    rust_fuzzy_search::fuzzy_compare(&text.to_lowercase(), &i.fqid.to_lowercase())
                        > 0.0
                } else {
                    true
                }
            });

        Ok(Some(CompletionResponse::from(
            items
                .iter()
                .chain(other_decls)
                .unique()
                .map(to_completion_item)
                .collect::<Vec<_>>(),
        )))
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
        let node = match tree.root_node().named_descendant_for_position(position) {
            Some(n) => n,
            None => return Ok(None),
        };
        let source = state.source(uri.clone());

        let location = match node.kind() {
            "id" => state
                .resolve(NodeLocation::from_node(uri, node))
                .map(|d| Location::new(d.uri.as_ref().clone(), d.range)),
            "file" => {
                let text = node.utf8_text(source.as_bytes()).map_err(|e| {
                    error!("could not get source text: {}", e);
                    Error::internal_error()
                })?;

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

    #[instrument]
    async fn signature_help(&self, params: SignatureHelpParams) -> Result<Option<SignatureHelp>> {
        let uri = Arc::new(params.text_document_position_params.text_document.uri);
        let position = params.text_document_position_params.position;

        let state = self.state()?;
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

        let f = match state.resolve_id(Arc::new(id.into()), NodeLocation::from_node(uri, node)) {
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

        let tree = match self.state()?.parse(Arc::new(params.text_document.uri)) {
            Some(t) => t,
            None => return Ok(None),
        };

        Ok(Some(compute_folds(tree.root_node(), false)))
    }

    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = Arc::new(params.text_document.uri);
        let source = self.state()?.source(uri);

        let num_lines = u32::try_from(source.lines().count()).expect("too many lines");
        let end = u32::try_from(source.lines().last().map_or(0, str::len)).expect("line too long");
        let end = Position::new(num_lines, end);
        let range = Range::new(Position::new(0, 0), end);

        let formatted = zeek::format(&source)
            .await
            .map_err(|_| Error::internal_error())?;

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

        let state = self.state()?;
        let tree = state.parse(uri.clone());
        let tree = match tree.as_ref() {
            Some(t) => t,
            None => return Ok(None),
        };
        let node = match tree.root_node().named_descendant_for_position(position) {
            Some(n) => n,
            None => return Ok(None),
        };

        let decl = match state.resolve(NodeLocation::from_node(uri.clone(), node)) {
            Some(d) => d,
            None => return Ok(None),
        };

        let decl = match &decl.kind {
            // We are done as we have found a declaration.
            DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_) => {
                decl.as_ref().clone()
            }
            // If we resolved to a definition, look for the declaration.
            DeclKind::EventDef(_) | DeclKind::FuncDef(_) | DeclKind::HookDef(_) => {
                match state
                    .decls(uri.clone())
                    .iter()
                    .chain(state.implicit_decls().iter())
                    .chain(state.explicit_decls_recursive(uri.clone()).iter())
                    .filter(|&d| match &d.kind {
                        DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_) => {
                            true
                        }
                        _ => false,
                    })
                    .find(|&d| d.id == decl.id)
                {
                    Some(d) => d.clone(),
                    None => return Ok(None),
                }
            }
            _ => return Ok(None),
        };

        Ok(Some(GotoDeclarationResponse::Scalar(Location::new(
            decl.uri.as_ref().clone(),
            decl.range,
        ))))
    }

    #[instrument]
    async fn goto_implementation(
        &self,
        params: GotoImplementationParams,
    ) -> Result<Option<GotoImplementationResponse>> {
        let params = params.text_document_position_params;
        let uri = Arc::new(params.text_document.uri);
        let position = params.position;

        let state = self.state()?;
        let tree = state.parse(uri.clone());
        let tree = match tree.as_ref() {
            Some(t) => t,
            None => return Ok(None),
        };
        let node = match tree.root_node().named_descendant_for_position(position) {
            Some(n) => n,
            None => return Ok(None),
        };

        let decl = match state.resolve(NodeLocation::from_node(uri.clone(), node)) {
            Some(d) => d,
            None => return Ok(None),
        };

        match &decl.kind {
            DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_) => {}
            _ => return Ok(None),
        }

        Ok(Some(GotoImplementationResponse::from(
            state
                .files()
                .iter()
                .map(|f| {
                    state
                        .decls(f.clone())
                        .as_ref()
                        .clone()
                        .into_iter()
                        .collect::<Vec<_>>()
                })
                .flatten()
                .filter(|d| match &d.kind {
                    DeclKind::EventDef(_) | DeclKind::FuncDef(_) | DeclKind::HookDef(_) => true,
                    _ => false,
                })
                .filter_map(|d| {
                    if &d.id == &decl.id {
                        Some(Location::new(d.uri.as_ref().clone(), d.range))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>(),
        )))
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

fn to_completion_item(d: &Decl) -> CompletionItem {
    CompletionItem {
        label: d.fqid.clone(),
        kind: Some(to_completion_item_kind(&d.kind)),
        documentation: Some(Documentation::MarkupContent(MarkupContent {
            kind: lspower::lsp::MarkupKind::Markdown,
            value: d.documentation.clone(),
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
pub(crate) mod test {
    use std::{
        collections::BTreeSet,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use insta::assert_debug_snapshot;
    use lspower::{
        lsp::{
            CompletionParams, CompletionResponse, HoverParams, PartialResultParams, Position,
            TextDocumentIdentifier, TextDocumentPositionParams, Url, WorkDoneProgressParams,
            WorkspaceSymbolParams,
        },
        LanguageServer,
    };
    use salsa::{ParallelDatabase, Snapshot};

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
             global GLOBAL::Y = 3;",
        );

        let server = serve(db);

        let result = server
            .completion(CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier::new(uri.as_ref().clone()),
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
    async fn completion_load() {
        let mut db = TestDatabase::new();
        db.add_prefix("/p1");
        db.add_prefix("/p2");
        db.add_file(
            Arc::new(Url::from_file_path("/p1/foo/a1.zeek").unwrap()),
            "",
        );
        db.add_file(
            Arc::new(Url::from_file_path("/p2/foo/b1.zeek").unwrap()),
            "",
        );

        let uri = Arc::new(Url::from_file_path("/x/x.zeek").unwrap());
        db.add_file(uri.clone(), "@load f");

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier::new(uri.as_ref().clone()),
                        position: Position::new(0, 6),
                    },
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                })
                .await
        );
    }

    #[tokio::test]
    async fn completion_event() {
        let mut db = TestDatabase::new();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
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

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier::new(uri.as_ref().clone()),
                        position: Position::new(7, 6),
                    },
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier::new(uri.as_ref().clone()),
                        position: Position::new(8, 10),
                    },
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier::new(uri.as_ref().clone()),
                        position: Position::new(9, 6),
                    },
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: None,
                })
                .await
        );
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
                    partial_result_params: Default::default(),
                    work_done_progress_params: Default::default(),
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
                    partial_result_params: Default::default(),
                    work_done_progress_params: Default::default(),
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
                    work_done_progress_params: Default::default(),
                    partial_result_params: Default::default(),
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
                    work_done_progress_params: Default::default(),
                    partial_result_params: Default::default(),
                })
                .await
        );
    }
}
