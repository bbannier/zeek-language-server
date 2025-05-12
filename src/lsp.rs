pub(crate) use crate::{
    ast::{load_to_file, Ast},
    complete::complete,
    parse::Parse,
    query::{self, Decl, DeclKind, ModuleId, NodeLocation, Query},
    zeek, Client, Files, Str,
};
use itertools::Itertools;
use rayon::prelude::*;
use rustc_hash::FxHashSet;
use salsa::ParallelDatabase;
use semver::Version;
use serde::Deserialize;
use std::{fmt::Debug, path::PathBuf, sync::Arc};
use tower_lsp_server::{
    jsonrpc::{Error, Result},
    lsp_types::{
        notification::Progress,
        request::{
            GotoDeclarationResponse, GotoImplementationParams, GotoImplementationResponse,
            WorkDoneProgressCreate,
        },
        CodeAction, CodeActionKind, CodeActionParams, CodeActionProviderCapability,
        CodeActionResponse, CompletionOptions, CompletionParams, CompletionResponse,
        DeclarationCapability, Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams,
        DidChangeWatchedFilesParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
        DidSaveTextDocumentParams, DocumentFormattingParams, DocumentRangeFormattingParams,
        DocumentSymbol, DocumentSymbolParams, DocumentSymbolResponse, FileChangeType, FileEvent,
        FoldingRange, FoldingRangeParams, FoldingRangeProviderCapability, GotoDefinitionParams,
        GotoDefinitionResponse, Hover, HoverContents, HoverParams, HoverProviderCapability,
        ImplementationProviderCapability, InitializeParams, InitializeResult, InitializedParams,
        InlayHint, InlayHintKind, InlayHintLabel, InlayHintParams, InlayHintTooltip,
        LanguageString, Location, MarkedString, MarkupContent, MarkupKind, MessageType,
        NumberOrString, OneOf, ParameterInformation, ParameterLabel, Position, ProgressParams,
        ProgressParamsValue, ProgressToken, Range, ReferenceParams, RenameParams,
        SemanticTokensFullOptions, SemanticTokensOptions, SemanticTokensParams,
        SemanticTokensResult, SemanticTokensServerCapabilities, ServerCapabilities, ServerInfo,
        SignatureHelp, SignatureHelpOptions, SignatureHelpParams, SignatureInformation,
        SymbolInformation, SymbolKind, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit,
        Uri, WorkDoneProgress, WorkDoneProgressBegin, WorkDoneProgressCreateParams,
        WorkDoneProgressEnd, WorkDoneProgressReport, WorkspaceEdit, WorkspaceSymbolParams,
    },
    LanguageServer, LspService, Server, UriExt,
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
pub struct Database {
    storage: salsa::Storage<Self>,
}

unsafe impl Sync for Database {}

pub enum SourceUpdate {
    Remove(Arc<Uri>),
    Update(Arc<Uri>, Str),
}

impl Database {
    pub fn update_sources(&mut self, updates: &[SourceUpdate]) {
        let mut files: FxHashSet<_> = self.files().iter().cloned().collect();

        let mut needs_files_update = false;

        for u in updates {
            match u {
                SourceUpdate::Update(uri, source) => {
                    self.set_unsafe_source(Arc::clone(uri), source.clone());

                    if !files.contains(uri) {
                        files.insert(Arc::clone(uri));
                        needs_files_update = true;
                    }
                }
                SourceUpdate::Remove(uri) => {
                    if files.contains(uri) {
                        files.remove(uri);
                        needs_files_update = true;
                    }
                }
            }
        }

        if needs_files_update {
            self.set_files(Arc::from(files.into_iter().collect::<Vec<_>>()));
        }
    }

    fn file_changed(&self, uri: Arc<Uri>) {
        // Precompute decls in this file.
        let _d = self.decls(uri);
    }
}

impl Default for Database {
    fn default() -> Self {
        let mut db = Self {
            storage: salsa::Storage::default(),
        };

        db.set_files(Arc::default());
        db.set_prefixes(Arc::default());
        db.set_workspace_folders(Arc::default());
        db.set_capabilities(Arc::default());
        db.set_initialization_options(Arc::new(InitializationOptions::new()));

        db
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

#[derive(Debug, Default)]
pub struct Backend {
    pub client: Option<tower_lsp_server::Client>,
    state: tokio::sync::RwLock<Database>,
}

enum ParseResult {
    Ok,
    HasDiagnostics,
}

impl Backend {
    async fn client_message<M>(&self, level: MessageType, message: M)
    where
        M: std::fmt::Display,
    {
        if let Some(client) = &self.client {
            // Show warnings to the user.
            client.show_message(level, message).await;
        }
    }
    async fn warn_message<M>(&self, message: M)
    where
        M: std::fmt::Display,
    {
        self.client_message(MessageType::WARNING, message).await;
    }

    async fn info_message<M>(&self, message: M)
    where
        M: std::fmt::Display,
    {
        self.client_message(MessageType::INFO, message).await;
    }

    async fn progress_begin<T>(&self, title: T) -> Option<ProgressToken>
    where
        T: Into<String> + std::fmt::Display,
    {
        // Short circuit progress report if client doesn't support it.
        if !self
            .state
            .read()
            .await
            .capabilities()
            .window
            .as_ref()
            .and_then(|w| w.work_done_progress)
            .unwrap_or(false)
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
        let Some(token) = token else {
            return;
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
        let Some(token) = token else {
            return;
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

    async fn file_changed(&self, uri: Arc<Uri>) -> Result<ParseResult> {
        if let Some(client) = &self.client {
            let state = self.state.read().await;
            let diags = {
                state.file_changed(Arc::clone(&uri));

                if let Some(tree) = state.parse(Arc::clone(&uri)) {
                    tree_diagnostics(&tree.root_node())
                } else {
                    Vec::new()
                }
            };

            let parse_result = if diags.is_empty() {
                ParseResult::Ok
            } else {
                ParseResult::HasDiagnostics
            };

            client
                .publish_diagnostics((*uri).clone(), diags, None)
                .await;

            return Ok(parse_result);
        }

        Ok(ParseResult::Ok)
    }

    pub async fn visible_files(&self) -> Result<Vec<Uri>> {
        let system_files = zeek::system_files()
            .await
            .map_err(|e| {
                error!("could not read system files: {e}");
                Error::internal_error()
            })?
            .into_par_iter()
            .filter_map(|f| Uri::from_file_path(f.path));

        let workspace_folders = self.state.read().await.workspace_folders();

        let workspace_files = workspace_folders
            .par_iter()
            .filter_map(UriExt::to_file_path)
            .flat_map(|dir| {
                WalkDir::new(dir)
                    .into_iter()
                    .filter_map(std::result::Result::ok)
                    .filter(|e| !e.file_type().is_dir())
                    .filter_map(|f| {
                        if f.path().extension()? == "zeek" {
                            Uri::from_file_path(f.path())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            });

        Ok(system_files.chain(workspace_files).collect())
    }

    pub async fn get_latest_release(&self, uri: Option<&str>) -> Option<Version> {
        #[derive(Deserialize, Debug)]
        struct GithubRelease {
            name: String,
        }

        let client = reqwest::ClientBuilder::new()
            .user_agent("zeek-language-server")
            .build()
            .ok()?;

        let uri = uri.unwrap_or(
            "https://api.github.com/repos/bbannier/zeek-language-server/releases/latest",
        );

        let resp = client.get(uri).send().await.ok()?.text().await.ok()?;

        let release: GithubRelease = serde_json::from_str(&resp).ok()?;
        let latest = semver::Version::parse(release.name.trim_matches('v')).ok()?;

        Some(latest)
    }

    /// This is wrapper around `zeek::check` directly publishing diagnostics.
    async fn check(&self, uri: Uri, version: Option<i32>) {
        // If we have not client to publish to there is no need to run checks.
        let Some(client) = &self.client else {
            return;
        };

        let Some(file) = uri.to_file_path() else {
            return;
        };

        // Figure out a directory to run the check from. If there is any workspace folder we just
        // pick the first one (TODO: this might be incorrect if there are multiple folders given);
        // else use the directory the file is in.
        let workspace_folders = self.state.read().await.workspace_folders();
        let workspace_folder = workspace_folders.first().and_then(UriExt::to_file_path);

        let checks = if let Some(folder) = workspace_folder {
            zeek::check(&file, folder).await
        } else {
            let Some(file_dir) = file.parent() else {
                return;
            };
            zeek::check(&file, file_dir).await
        };

        let checks = match checks {
            Ok(xs) => xs,
            Err(e) => {
                error!("could not check file with 'zeek': {e}");
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

                let severity = Some(match c.kind {
                    zeek::ErrorKind::Error => DiagnosticSeverity::ERROR,
                    zeek::ErrorKind::Warning => DiagnosticSeverity::WARNING,
                });

                Diagnostic::new(
                    Range::new(position, position),
                    severity,
                    None,
                    Some("zeek".to_string()),
                    c.message,
                    None,
                    None,
                )
            })
            .collect();

        client.publish_diagnostics(uri, diags, version).await;
    }
}

impl LanguageServer for Backend {
    #[instrument]
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        let workspace_folders = params
            .workspace_folders
            .map_or_else(Vec::new, |xs| xs.into_iter().map(|x| x.uri).collect());

        {
            let mut state = self.state.write().await;
            state.set_workspace_folders(Arc::from(workspace_folders));
            state.set_capabilities(Arc::new(params.capabilities));
            state.set_initialization_options(Arc::new(
                params
                    .initialization_options
                    .and_then(|options| serde_json::from_value(options).ok())
                    .unwrap_or_else(InitializationOptions::new),
            ));
        }

        // Check prerequisites and set system prefixes.
        match zeek::prefixes(None).await {
            Ok(prefixes) => self.state.write().await.set_prefixes(Arc::from(prefixes)),
            Err(e) => {
                self.warn_message(format!(
                    "cannot detect Zeek prefixes, results will be incomplete or incorrect: {e}"
                ))
                .await;
            }
        }

        let initialization_options = self.state.read().await.initialization_options();
        let has_zeek_format = zeek::has_format().await;

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                workspace_symbol_provider: Some(OneOf::Left(true)),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec!["$".into(), ":".into()]),
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
                document_formatting_provider: Some(OneOf::Left(has_zeek_format)),
                document_range_formatting_provider: Some(OneOf::Left(has_zeek_format)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                inlay_hint_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(initialization_options.references)),
                rename_provider: Some(OneOf::Left(initialization_options.rename)),
                semantic_tokens_provider: if initialization_options.semantic_highlighting {
                    Some(SemanticTokensServerCapabilities::SemanticTokensOptions(
                        SemanticTokensOptions {
                            legend: semantic_tokens::legend(),
                            full: Some(SemanticTokensFullOptions::Bool(true)),
                            ..SemanticTokensOptions::default()
                        },
                    ))
                } else {
                    None
                },
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
        let initialization_options = self.state.read().await.initialization_options();

        // Check whether a newer release is available.
        if initialization_options.check_for_updates {
            if let Some(latest) = self.get_latest_release(None).await {
                let current =
                    Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or_else(|_| latest.clone());

                if current < latest {
                    self.info_message(format!(
                        "a newer release of zeek-language-server ({latest}) is available, currently running {current}"
                    ))
                    .await;
                }
            }
        }

        // Load all currently visible files. These are likely only files in system prefixes.
        if let Ok(files) = self.visible_files().await {
            let update = self.did_change_watched_files(DidChangeWatchedFilesParams {
                changes: files
                    .iter()
                    .map(|f| FileEvent::new(f.clone(), FileChangeType::CREATED))
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
        let progress_token = self.progress_begin("Indexing").await;

        self.progress(
            progress_token.clone(),
            Some("refreshing sources".to_string()),
        )
        .await;

        {
            let span = trace_span!("updating");
            let _enter = span.enter();

            let (updates, removals): (Vec<_>, Vec<_>) = params
                .changes
                .into_par_iter()
                .partition(|c| matches!(c.typ, FileChangeType::CREATED | FileChangeType::CHANGED));

            let removals = removals
                .into_par_iter()
                .map(|c| SourceUpdate::Remove(Arc::new(c.uri)));

            let updates = updates.into_iter().map(|c| {
                tokio::spawn(async move {
                    let source = match tokio::fs::read_to_string(c.uri.path().as_str()).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("failed to read '{}': {}", &c.uri.path(), e);
                            return None;
                        }
                    };

                    Some(SourceUpdate::Update(Arc::new(c.uri), source.into()))
                })
            });
            let updates = futures::future::join_all(updates).await;
            let updates = updates
                .into_par_iter()
                .flat_map(std::result::Result::ok)
                .flatten();

            let changes = removals.chain(updates).collect::<Vec<_>>();

            // Update files.
            self.state.write().await.update_sources(&changes);
        }

        // Preload expensive information. Ultimately we want to be able to load implicit
        // declarations quickly since they are on the critical part of getting the user to useful
        // completions right after server startup.
        //
        // We explicitly precompute per-file information here so we can parallelize this work.

        self.progress(progress_token.clone(), Some("declarations".to_string()))
            .await;
        let files = self.state.read().await.files();

        let preloaded_decls = {
            let span = trace_span!("preloading");
            let _enter = span.enter();

            let state = self.state.read().await;

            files
                .iter()
                .map(|f| {
                    let f = Arc::clone(f);
                    let db = state.snapshot();
                    tokio::spawn(async move {
                        let _x = db.decls(Arc::clone(&f));
                        let _x = db.loads(Arc::clone(&f));
                        let _x = db.loaded_files(f);
                    })
                })
                .collect::<Vec<_>>()
        };
        futures::future::join_all(preloaded_decls).await;

        // Reload implicit declarations.
        self.progress(progress_token.clone(), Some("implicit loads".to_string()))
            .await;
        let _implicit = self.state.read().await.implicit_decls();

        self.progress_end(progress_token).await;
    }

    #[instrument]
    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = Arc::new(params.text_document.uri.clone());

        // Update source.
        self.state
            .write()
            .await
            .update_sources(&[SourceUpdate::Update(
                Arc::clone(&uri),
                params.text_document.text.into(),
            )]);

        // Reload implicit declarations since their result depends on the list of known files and
        // is on the critical path for e.g., completion.
        let _implicit = self.state.read().await.implicit_decls();

        let file_changed = self.file_changed(uri).await;

        match file_changed {
            Err(e) => {
                error!("could not apply file change: {e}");
            }
            Ok(ParseResult::Ok) => {
                self.check(params.text_document.uri, Some(params.text_document.version))
                    .await;
            }
            Ok(ParseResult::HasDiagnostics) => {
                // Do not bother checking the file with zeek if it has parse errors.
            }
        }
    }

    #[instrument]
    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let Some(changes) = params.content_changes.first() else {
            error!("more than one change received even though we only advertize full update mode");
            return;
        };

        assert!(changes.range.is_none(), "unexpected diff mode");

        let uri = Arc::new(params.text_document.uri);

        // Update source.
        self.state
            .write()
            .await
            .update_sources(&[SourceUpdate::Update(
                Arc::clone(&uri),
                changes.text.as_str().into(),
            )]);

        // Diagnostics are already triggered from `file_changed`.
        if let Err(e) = self.file_changed(uri).await {
            error!("could not apply file change: {e}");
        }
    }

    #[instrument]
    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        self.check(params.text_document.uri, None).await;
    }

    #[instrument]
    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        // If a file is closed it means the full state of the document
        // is now on disk and we can run a check on it.
        self.check(params.text_document.uri, None).await;
    }

    #[instrument]
    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let params = params.text_document_position_params;

        let uri = Arc::new(params.text_document.uri);

        let state = self.state.read().await;

        let Some(source) = state.source(Arc::clone(&uri)) else {
            return Ok(None);
        };

        let tree = state.parse(Arc::clone(&uri));
        let Some(tree) = tree.as_ref() else {
            return Ok(None);
        };

        let node = tree.root_node();
        let position = params.position;
        let Some(node) = node.named_descendant_for_position(position) else {
            return Ok(None);
        };

        let text = node.utf8_text(source.as_bytes()).map_err(|e| {
            error!("could not get source text: {}", e);
            Error::internal_error()
        })?;

        let mut contents = Vec::new();

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
                        DeclKind::Index(_, _) => "indexing result",
                        DeclKind::Module => "module",
                        DeclKind::Builtin(_) => "builtin",
                    };

                    contents.push(MarkedString::String(format!(
                        "### {kind} `{id}`",
                        id = decl.fqid
                    )));

                    if let Some(typ) = state.typ(Arc::clone(decl)) {
                        contents.push(MarkedString::String(format!("Type: `{}`", typ.fqid)));
                    }

                    contents.push(MarkedString::String(decl.documentation.to_string()));
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
            "zeekygen_head_comment" | "zeekygen_prev_comment" | "zeekygen_next_comment" => {
                // If we are in a zeekygen comment try to recover an identifier under the cursor and use it as target.
                let try_update = |contents: &mut Vec<_>| {
                    let symbol = word_at_position(&source, position)?;

                    let mut x = fuzzy_search_symbol(&state, &symbol);
                    x.sort_by(|(r1, _), (r2, _)| r1.total_cmp(r2));

                    if let Some(docs) = fuzzy_search_symbol(&state, &symbol)
                        .iter()
                        // Filter out event implementations.
                        .filter(|(_, d)| !matches!(d.kind, DeclKind::EventDef(_)))
                        .sorted_by(|(r1, _), (r2, _)| r1.total_cmp(r2))
                        .next_back()
                        .map(|(_, d)| d.documentation.to_string())
                    {
                        contents.push(MarkedString::String(docs));
                    }
                    Some(())
                };
                try_update(&mut contents);
            }
            _ => {}
        }

        // In debug builds always debug AST nodes; in release mode honor the client config.
        #[cfg(all(debug_assertions, not(test)))]
        let debug_ast_nodes = true;
        #[cfg(not(all(debug_assertions, not(test))))]
        let debug_ast_nodes = self
            .state
            .read()
            .await
            .initialization_options()
            .debug_ast_nodes;

        if debug_ast_nodes {
            contents.push(MarkedString::LanguageString(LanguageString {
                value: node.to_sexp().to_string(),
                language: "lisp".into(),
            }));
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
        let uri = Arc::new(params.text_document.uri);

        let symbol = |d: &Decl| -> Option<DocumentSymbol> {
            let loc = d.loc.as_ref()?;

            #[allow(deprecated)]
            Some(DocumentSymbol {
                name: d.id.to_string(),
                range: loc.range,
                selection_range: loc.selection_range,
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
                            .filter_map(|f| {
                                let loc = &f.loc.as_ref()?;
                                Some(DocumentSymbol {
                                    name: f.id.to_string(),
                                    range: loc.range,
                                    selection_range: loc.selection_range,
                                    deprecated: None,
                                    children: None,
                                    kind: to_symbol_kind(&f.kind),
                                    tags: None,
                                    detail: None,
                                })
                            })
                            .collect(),
                    ),
                    _ => None,
                },
            })
        };

        let modules = {
            let db = self.state.read().await;

            // Even though a valid source file can only contain a single module, one can still make
            // declarations in other modules. Sort declarations by module so users get a clean view.
            // Then show declarations under their module, or at the top-level if they aren't exported
            // into a module.
            let decls = db.decls(uri);
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
                .chunk_by(|d| &d.module)
                .into_iter()
                .map(|(m, decls)| {
                    #[allow(deprecated)]
                    DocumentSymbol {
                        name: format!("{m}"),
                        kind: SymbolKind::NAMESPACE,
                        children: Some(decls.filter_map(symbol).collect()),

                        // FIXME(bbannier): Weird ranges.
                        range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                        selection_range: Range::new(Position::new(0, 0), Position::new(0, 0)),

                        deprecated: None,

                        detail: None,
                        tags: None,
                    }
                })
                .chain(decls_wo_mod.into_iter().filter_map(symbol))
                .collect()
        };

        Ok(Some(DocumentSymbolResponse::Nested(modules)))
    }

    #[instrument]
    async fn symbol(
        &self,
        params: WorkspaceSymbolParams,
    ) -> Result<Option<Vec<SymbolInformation>>> {
        let query = params.query.to_lowercase();

        let symbols = {
            let state = self.state.read().await;
            fuzzy_search_symbol(&state, &query)
                .into_iter()
                .filter_map(|(_, d)| {
                    let loc = d.loc.as_ref()?;

                    #[allow(deprecated)]
                    Some(SymbolInformation {
                        name: d.fqid.to_string(),
                        kind: to_symbol_kind(&d.kind),

                        location: Location::new(loc.uri.as_ref().clone(), loc.range),
                        container_name: Some(format!("{}", d.module)),

                        tags: None,
                        deprecated: None,
                    })
                })
                .collect()
        };

        Ok(Some(symbols))
    }

    #[instrument]
    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let state = self.state.read().await;
        Ok(complete(&state, params))
    }

    #[instrument]
    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let params = params.text_document_position_params;
        let uri = Arc::new(params.text_document.uri);
        let position = params.position;

        let state = self.state.read().await;

        let tree = state.parse(Arc::clone(&uri));
        let Some(tree) = tree.as_ref() else {
            return Ok(None);
        };
        let Some(node) = tree.root_node().named_descendant_for_position(position) else {
            return Ok(None);
        };
        let Some(source) = state.source(Arc::clone(&uri)) else {
            return Ok(None);
        };

        let location = {
            match node.kind() {
                "id" => state
                    .resolve(NodeLocation::from_node(uri, node))
                    .and_then(|d| {
                        let loc = &d.loc.as_ref()?;
                        Some(Location::new((*loc.uri).clone(), loc.range))
                    }),
                "file" => {
                    let Ok(text) = node.utf8_text(source.as_bytes()).map_err(|e| {
                        error!("could not get source text: {}", e);
                        Error::internal_error()
                    }) else {
                        return Ok(None);
                    };

                    let file = PathBuf::from(text);
                    load_to_file(
                        &file,
                        uri.as_ref(),
                        state.files().as_ref(),
                        state.prefixes().as_ref(),
                    )
                    .map(|uri| Location::new((*uri).clone(), Range::default()))
                }
                "zeekygen_head_comment" | "zeekygen_prev_comment" | "zeekygen_next_comment" => {
                    // If we are in a zeekygen comment try to recover an
                    // identifier under the cursor and use it as target.
                    let Some(symbol) = word_at_position(&source, position) else {
                        return Ok(None);
                    };
                    fuzzy_search_symbol(&state, &symbol)
                        .iter()
                        // Filter out event implementations.
                        .filter(|(_, d)| !matches!(d.kind, DeclKind::EventDef(_)))
                        .sorted_by(|(r1, _), (r2, _)| r1.total_cmp(r2))
                        .next_back()
                        .and_then(|(_, d)| d.loc.as_ref())
                        .map(|l| Location::new(l.uri.as_ref().clone(), l.range))
                }
                _ => None,
            }
        };

        Ok(location.map(GotoDefinitionResponse::Scalar))
    }

    #[instrument]
    async fn signature_help(&self, params: SignatureHelpParams) -> Result<Option<SignatureHelp>> {
        let uri = Arc::new(params.text_document_position_params.text_document.uri);
        let position = params.text_document_position_params.position;

        let state = self.state.read().await;

        let Some(source) = state.source(Arc::clone(&uri)) else {
            return Ok(None);
        };
        let Some(tree) = state.parse(Arc::clone(&uri)) else {
            return Ok(None);
        };

        // TODO(bbannier): We do not handle newlines between the function name and any ultimate parameter.
        let Some(line) = source.lines().nth(position.line as usize) else {
            return Ok(None);
        };

        let line = if u32::try_from(line.len() + 1).ok() > Some(position.character) {
            &line[..position.character as usize]
        } else {
            return Ok(None);
        };

        // Search backward in the line for '('. The identifier before that could be a function name.
        let Some(node) = line
            .chars()
            .rev()
            .enumerate()
            .filter(|(_, c)| !char::is_whitespace(*c))
            .skip_while(|(_, c)| c != &'(')
            .nth(1)
            .and_then(|(i, _)| {
                let character = u32::try_from(line.len() - i - 1).ok()?;

                tree.root_node().named_descendant_for_position(Position {
                    character,
                    ..position
                })
            })
        else {
            return Ok(None);
        };

        let active_parameter = u32::try_from(line.chars().filter(|c| c == &',').count()).ok();

        let Ok(id) = node.utf8_text(source.as_bytes()) else {
            return Ok(None);
        };

        let Some(f) = state.resolve_id(id.into(), NodeLocation::from_node(uri, node)) else {
            return Ok(None);
        };

        let (DeclKind::FuncDecl(signature)
        | DeclKind::FuncDef(signature)
        | DeclKind::EventDecl(signature)
        | DeclKind::EventDef(signature)
        | DeclKind::HookDecl(signature)
        | DeclKind::HookDef(signature)) = &f.kind
        else {
            return Ok(None);
        };

        // Recompute `tree` and `source` in the context of the function declaration.
        let Some(loc) = &f.loc else { return Ok(None) };
        let Some(tree) = state.parse(Arc::clone(&loc.uri)) else {
            return Ok(None);
        };
        let Some(source) = state.source(Arc::clone(&loc.uri)) else {
            return Ok(None);
        };

        let label = format!(
            "{}({})",
            f.id,
            signature
                .args
                .iter()
                .filter_map(|a| {
                    let loc = &a.loc.as_ref()?;
                    tree.root_node()
                        .named_descendant_for_point_range(loc.selection_range)?
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
                    label: ParameterLabel::Simple(a.id.to_string()),
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
                    ..FoldingRange::default()
                }]
            } else {
                Vec::new()
            };

            for child in n.named_children_not("nl") {
                folds.extend(compute_folds(child, true));
            }

            folds
        }

        let state = self.state.read().await;
        let tree = state.parse(Arc::new(params.text_document.uri));

        Ok(tree.map(|t| compute_folds(t.root_node(), false)))
    }

    #[instrument]
    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = Arc::new(params.text_document.uri);

        let state = self.state.read().await;

        let source = state.source(Arc::clone(&uri));

        let Some(source) = source else {
            return Ok(None);
        };

        let range = match state.parse(uri) {
            Some(t) => t.root_node().range(),
            None => return Ok(None),
        };

        let Ok(formatted) = zeek::format(&source).await else {
            // Swallow errors from zeek-format, we likely already emitted a diagnostic.
            return Ok(None);
        };

        Ok(Some(vec![TextEdit::new(range, formatted)]))
    }

    #[instrument]
    async fn range_formatting(
        &self,
        params: DocumentRangeFormattingParams,
    ) -> Result<Option<Vec<TextEdit>>> {
        let uri = Arc::new(params.text_document.uri);

        let source = self.state.read().await.source(Arc::clone(&uri));

        let Some(source) = source else {
            return Ok(None);
        };

        let start = params.range.start;
        let end = params.range.end;
        let num_lines = if start.line > end.line {
            return Ok(None);
        } else {
            end.line - start.line
        };

        let lines = source
            .lines()
            .skip(start.line as usize)
            .take(num_lines as usize)
            .join("\n");

        let Ok(formatted) = zeek::format(&lines).await else {
            // Swallow errors from zeek-format, we likely already emitted a diagnostic.
            return Ok(None);
        };

        Ok(Some(vec![TextEdit::new(params.range, formatted)]))
    }

    #[instrument]
    async fn goto_declaration(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDeclarationResponse>> {
        let params = params.text_document_position_params;
        let uri = Arc::new(params.text_document.uri);
        let position = params.position;

        let state = self.state.read().await;

        let tree = state.parse(Arc::clone(&uri));
        let Some(tree) = tree.as_ref() else {
            return Ok(None);
        };

        let Some(node) = tree.root_node().named_descendant_for_position(position) else {
            return Ok(None);
        };

        let Some(decl) = state.resolve(NodeLocation::from_node(Arc::clone(&uri), node)) else {
            return Ok(None);
        };

        let decl = {
            match &decl.kind {
                // We are done as we have found a declaration.
                DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_) => {
                    Some((*decl).clone())
                }
                // If we resolved to a definition, look for the declaration.
                DeclKind::EventDef(_) | DeclKind::FuncDef(_) | DeclKind::HookDef(_) => state
                    .decls(Arc::clone(&uri))
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
                    .cloned(),
                _ => None,
            }
        };

        Ok(decl.and_then(|d| {
            let loc = &d.loc.as_ref()?;
            Some(GotoDeclarationResponse::Scalar(Location::new(
                (*loc.uri).clone(),
                loc.range,
            )))
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

        let state = self.state.read().await;

        let tree = state.parse(Arc::clone(&uri));
        let Some(tree) = tree.as_ref() else {
            return Ok(None);
        };

        let Some(node) = tree.root_node().named_descendant_for_position(position) else {
            return Ok(None);
        };

        let Some(decl) = state.resolve(NodeLocation::from_node(uri, node)) else {
            return Ok(None);
        };

        if !matches!(
            &decl.kind,
            DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_)
        ) {
            return Ok(None);
        }

        let response = state
            .files()
            .iter()
            .flat_map(|f| {
                state
                    .decls(Arc::clone(f))
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .filter(|d| {
                matches!(
                    &d.kind,
                    DeclKind::EventDef(_) | DeclKind::FuncDef(_) | DeclKind::HookDef(_)
                )
            })
            .filter_map(|d| {
                let loc = &d.loc.as_ref()?;
                if d.id == decl.id {
                    Some(Location::new((*loc.uri).clone(), loc.range))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(Some(response.into()))
    }

    #[instrument]
    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        // For now we only work on the first diagnostic on something missing in the source.
        let Some(diag) = params
            .context
            .diagnostics
            .iter()
            .find(|d| d.code == Some(NumberOrString::Number(ERROR_CODE_IS_MISSING)))
        else {
            return Ok(None);
        };

        let uri = Arc::new(params.text_document.uri);
        let state = self.state.read().await;
        let Some(missing) = state.parse(Arc::clone(&uri)).and_then(|t| {
            t.root_node().errors().into_iter().find_map(|err| {
                // Filter out `MISSING` nodes at the diagnostic.
                if err.is_missing() && err.range() == diag.range {
                    // `kind` holds the fix for the `MISSING` error.
                    Some(err.kind().to_string())
                } else {
                    None
                }
            })
        }) else {
            return Ok(None);
        };

        let edit = Some(WorkspaceEdit::new(
            [(
                (*uri).clone(),
                vec![{ TextEdit::new(diag.range, missing.clone()) }],
            )]
            .into_iter()
            .collect(),
        ));

        Ok(Some(CodeActionResponse::from(vec![CodeAction {
            title: format!("Insert missing '{missing}'"),
            kind: Some(CodeActionKind::QUICKFIX),
            edit,
            ..CodeAction::default()
        }
        .into()])))
    }

    #[allow(clippy::too_many_lines)]
    #[instrument]
    async fn inlay_hint(&self, params: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        let uri = Arc::new(params.text_document.uri);
        let range = params.range;

        let mut hints = Vec::new();

        let state = self.state.read().await;

        let params = if state.initialization_options().inlay_hints_parameters {
            #[allow(clippy::redundant_clone)] // Used cloned iter for ownership with `tokio::spawn`
            state
                .function_calls(Arc::clone(&uri))
                .iter()
                .filter(|c| c.f.range.start >= range.start && c.f.range.end <= range.end)
                .cloned()
                .map(|c| {
                    let state = state.snapshot();
                    tokio::spawn(async move {
                        match &state.resolve(c.f.clone())?.kind {
                            DeclKind::FuncDef(s)
                            | DeclKind::FuncDecl(s)
                            | DeclKind::HookDef(s)
                            | DeclKind::HookDecl(s)
                            | DeclKind::EventDef(s)
                            | DeclKind::EventDecl(s) => Some(
                                c.args
                                    .into_iter()
                                    .zip(s.args.iter())
                                    .filter_map(|(p, a)| {
                                        // If the argument has the same name as the parameter do
                                        // not set an inlay hint.
                                        let uri = p.uri;
                                        let tree = state.parse(Arc::clone(&uri))?;
                                        let node = tree
                                            .root_node()
                                            .named_descendant_for_point_range(p.range)?;
                                        let source = state.source(uri)?;
                                        let maybe_id = node.utf8_text(source.as_bytes()).ok()?;
                                        if maybe_id == a.id {
                                            return None;
                                        }

                                        Some(InlayHint {
                                            position: p.range.start,
                                            label: InlayHintLabel::String(format!("{}:", a.id)),
                                            kind: Some(InlayHintKind::PARAMETER),
                                            text_edits: None,
                                            tooltip: Some(InlayHintTooltip::MarkupContent(
                                                MarkupContent {
                                                    kind: MarkupKind::Markdown,
                                                    value: a.documentation.to_string(),
                                                },
                                            )),
                                            padding_left: None,
                                            padding_right: Some(true),
                                            data: None,
                                        })
                                    })
                                    .collect::<Vec<_>>(),
                            ),
                            _ => None,
                        }
                    })
                })
                .collect::<Vec<_>>()
        } else {
            Vec::default()
        };

        let vars = if state.initialization_options().inlay_hints_variables {
            #[allow(clippy::redundant_clone)] // Used cloned iter for ownership with `tokio::spawn`
            state
                .untyped_var_decls(Arc::clone(&uri))
                .iter()
                .filter(|d| {
                    d.loc
                        .as_ref()
                        .is_some_and(|r| r.range.start >= range.start && r.range.end <= range.end)
                })
                .cloned()
                .map(|d| {
                    let state = state.snapshot();
                    tokio::spawn(async move {
                        let t = state.typ(Arc::new(d.clone()))?;
                        Some(InlayHint {
                            position: d.loc.as_ref().map(|l| l.selection_range.end)?,
                            label: InlayHintLabel::String(format!(": {}", t.id)),
                            kind: Some(InlayHintKind::TYPE),
                            text_edits: None,
                            tooltip: None,
                            padding_left: None,
                            padding_right: None,
                            data: None,
                        })
                    })
                })
                .collect::<Vec<_>>()
        } else {
            Vec::default()
        };

        let (params, vars) = futures::future::join(
            async {
                futures::future::join_all(params)
                    .await
                    .into_iter()
                    .filter_map(std::result::Result::ok)
                    .flatten()
                    .flatten()
            },
            async {
                futures::future::join_all(vars)
                    .await
                    .into_iter()
                    .filter_map(std::result::Result::ok)
                    .flatten()
            },
        )
        .await;

        hints.extend(params);
        hints.extend(vars);

        Ok(Some(hints))
    }

    #[instrument]
    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let uri = Arc::new(params.text_document_position.text_document.uri);
        let position = params.text_document_position.position;

        // TODO(bbannier): respect `params.context.include_declaration`.

        let state = self.state.read().await;

        let tree = state.parse(Arc::clone(&uri));
        let Some(tree) = tree.as_ref() else {
            return Ok(None);
        };
        let Some(node) = tree.root_node().named_descendant_for_position(position) else {
            return Ok(None);
        };
        let Some(decl) = state.resolve(NodeLocation::from_node(uri, node)) else {
            return Ok(None);
        };

        let references = references(&state, decl).await;

        Ok(Some(
            references
                .into_iter()
                .map(|l| Location::new(l.uri.as_ref().clone(), l.range))
                .collect::<Vec<_>>(),
        ))
    }

    #[instrument]
    async fn rename(&self, params: RenameParams) -> Result<Option<WorkspaceEdit>> {
        let uri = Arc::new(params.text_document_position.text_document.uri);
        let position = params.text_document_position.position;

        let state = self.state.read().await;

        let tree = state.parse(Arc::clone(&uri));
        let Some(tree) = tree.as_ref() else {
            return Ok(None);
        };
        let Some(node) = tree.root_node().named_descendant_for_position(position) else {
            return Ok(None);
        };
        let Some(decl) = state.resolve(NodeLocation::from_node(Arc::clone(&uri), node)) else {
            return Ok(None);
        };

        let references = references(&state, decl).await;

        let new_name = params.new_name;

        let changes = references
            .into_iter()
            .chunk_by(|r| (*r.uri).clone())
            .into_iter()
            .map(|(uri, g)| {
                let edits = g
                    // Send edits ordered from the back so we do not invalidate following positions.
                    .sorted_by_key(|l| l.range.start)
                    .rev()
                    .map(|l| TextEdit::new(l.range, new_name.clone()))
                    .collect();
                (uri, edits)
            })
            .collect();

        Ok(Some(WorkspaceEdit::new(changes)))
    }

    async fn semantic_tokens_full(
        &self,
        params: SemanticTokensParams,
    ) -> Result<Option<SemanticTokensResult>> {
        let uri = params.text_document.uri;

        let Some(source) = self.state.read().await.source(uri.into()) else {
            return Ok(None);
        };

        let legend = semantic_tokens::legend();
        semantic_tokens::highlight(&source, &legend)
            .map(|hl| Some(SemanticTokensResult::Tokens(hl)))
    }
}

fn word_at_position(source: &str, position: Position) -> Option<Str> {
    let line = source.lines().nth(usize::try_from(position.line).ok()?)?;
    let (a, b) = line.split_at(usize::try_from(position.character + 1).ok()?);
    let a = a.split_whitespace().last().unwrap_or_default();
    let b = b.split_whitespace().next().unwrap_or_default();

    Some(format!("{a}{b}").into())
}

fn fuzzy_search_symbol(db: &Database, symbol: &str) -> Vec<(f32, Decl)> {
    let files = db.files();
    files
        .iter()
        .flat_map(|uri| {
            db.decls(Arc::clone(uri))
                .iter()
                .filter_map(|d| {
                    let rank = rust_fuzzy_search::fuzzy_compare(symbol, &d.fqid.to_lowercase());
                    if rank > 0.0 {
                        Some((rank, d.clone()))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn to_symbol_kind(kind: &DeclKind) -> SymbolKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef | DeclKind::Index(_, _) => {
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
        DeclKind::Module => SymbolKind::MODULE,
        DeclKind::Builtin(_) => SymbolKind::KEY,
    }
}

pub async fn run() {
    let (service, socket) = LspService::new(|client| Backend {
        client: Some(client),
        ..Backend::default()
    });

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    Server::new(stdin, stdout, socket).serve(service).await;
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Custom `initializationOptions` clients can send.
pub struct InitializationOptions {
    #[serde(default = "InitializationOptions::_default_check_for_updates")]
    check_for_updates: bool,

    #[serde(default = "InitializationOptions::_default_inlay_hints_parameters")]
    inlay_hints_parameters: bool,

    #[serde(default = "InitializationOptions::_default_inlay_hints_variables")]
    inlay_hints_variables: bool,

    #[serde(default = "InitializationOptions::_default_references")]
    references: bool,

    #[serde(default = "InitializationOptions::_default_rename")]
    rename: bool,

    #[serde(default = "InitializationOptions::_semantic_highlighting")]
    semantic_highlighting: bool,

    #[serde(default = "InitializationOptions::_debug_ast_nodes")]
    debug_ast_nodes: bool,
}

impl InitializationOptions {
    const fn new() -> Self {
        Self {
            check_for_updates: true,
            inlay_hints_variables: true,
            inlay_hints_parameters: true,
            references: false,
            rename: false,
            semantic_highlighting: true,
            debug_ast_nodes: false,
        }
    }

    const fn _default_check_for_updates() -> bool {
        Self::new().check_for_updates
    }

    const fn _default_inlay_hints_parameters() -> bool {
        Self::new().inlay_hints_parameters
    }

    const fn _default_inlay_hints_variables() -> bool {
        Self::new().inlay_hints_variables
    }

    const fn _default_references() -> bool {
        Self::new().references
    }

    const fn _default_rename() -> bool {
        Self::new().rename
    }

    const fn _semantic_highlighting() -> bool {
        Self::new().semantic_highlighting
    }

    const fn _debug_ast_nodes() -> bool {
        Self::new().debug_ast_nodes
    }
}

const ERROR_CODE_IS_MISSING: i32 = 1;

/// Extracts all errors in a AST.
fn tree_diagnostics(tree: &query::Node) -> Vec<Diagnostic> {
    tree.errors()
        .into_iter()
        .map(|err| {
            let code = if err.is_missing() {
                Some(ERROR_CODE_IS_MISSING)
            } else {
                None
            }
            .map(NumberOrString::Number);

            Diagnostic::new(
                err.range(),
                Some(DiagnosticSeverity::WARNING),
                code,
                None,
                err.error().to_string(),
                None,
                None,
            )
        })
        .collect()
}

async fn references(db: &Database, decl: Arc<Decl>) -> FxHashSet<NodeLocation> {
    /// Helper to compute all sources reachable from a given file.
    fn all_sources(f: Arc<Uri>, db: &Database) -> FxHashSet<Arc<Uri>> {
        let mut loads = FxHashSet::default();
        loads.extend(db.implicit_loads().iter().cloned());
        loads.extend(db.loaded_files(f).iter().cloned());

        let mut recursive_loads = FxHashSet::default();
        for l in &loads {
            recursive_loads.extend(db.loaded_files_recursive(Arc::clone(l)).iter().cloned());
        }
        loads.extend(recursive_loads.into_iter());

        loads
    }

    let Some(decl_loc) = decl.loc.as_ref() else {
        return FxHashSet::default();
    };
    let decl_uri = &decl_loc.uri;

    let locs: Vec<_> = {
        let locs: Vec<_> = db
            .files()
            .iter()
            .filter(|f| {
                // If the file we look at does not load the file with the decl, no references to it
                // can exist.
                f == &decl_uri || all_sources(Arc::clone(f), db).contains(decl_uri)
            })
            .map(|f| {
                let db = db.snapshot();
                let decl = Arc::clone(&decl);
                let f = Arc::clone(f);
                tokio::spawn(async move {
                    Some(
                        db.ids(f)
                            .iter()
                            .filter_map(|loc| {
                                // Prefilter ids so that they at least somewhere contain the text
                                // of the decl.
                                let tree = db.parse(Arc::clone(&loc.uri))?;
                                let source = db.source(Arc::clone(&loc.uri))?;
                                let txt = tree
                                    .root_node()
                                    .named_descendant_for_point_range(loc.range)?
                                    .utf8_text(source.as_bytes())
                                    .ok()?;
                                if !txt.contains(decl.id.as_str()) {
                                    return None;
                                }

                                db.resolve(loc.clone()).and_then(|resolved| {
                                    if resolved != decl {
                                        return None;
                                    }

                                    Some(loc.clone())
                                })
                            })
                            .collect::<Vec<_>>(),
                    )
                })
            })
            .collect();
        futures::future::join_all(locs).await
    };

    locs.into_iter()
        .filter_map(std::result::Result::ok)
        .flatten()
        .flatten()
        .collect()
}

mod semantic_tokens {
    use itertools::Itertools;
    use tower_lsp_server::{
        jsonrpc::Error,
        lsp_types::{
            Position, Range, SemanticToken, SemanticTokenType, SemanticTokens, SemanticTokensLegend,
        },
    };
    use tracing::error;
    use tree_sitter_highlight::{Highlight, HighlightEvent};

    pub(crate) fn legend() -> SemanticTokensLegend {
        let token_types = highlights().map(SemanticTokenType::from).collect();

        SemanticTokensLegend {
            token_types,
            ..SemanticTokensLegend::default()
        }
    }

    fn highlights() -> impl Iterator<Item = &'static str> {
        tree_sitter_zeek::HIGHLIGHT_QUERY
            .lines()
            .flat_map(|line| line.split_whitespace())
            .filter_map(|xs| {
                let xs = xs.strip_prefix('@')?;
                Some(xs.strip_suffix(')').unwrap_or(xs))
            })
            .unique()
    }

    pub(crate) fn highlight(
        source: &str,
        legend: &SemanticTokensLegend,
    ) -> super::Result<SemanticTokens> {
        let mut zeek_config = tree_sitter_highlight::HighlightConfiguration::new(
            tree_sitter_zeek::language_zeek(),
            "zeek",
            tree_sitter_zeek::HIGHLIGHT_QUERY,
            "",
            "",
        )
        .map_err(|e| {
            error!("failed to construct highlighter configuration: {e}");
            Error::internal_error()
        })?;
        zeek_config.configure(&highlights().collect::<Vec<_>>());

        let line_index = line_index::LineIndex::new(source);

        let mut cur_ty = None;
        let mut cur_range = None;
        let mut data = Vec::new();

        for event in tree_sitter_highlight::Highlighter::new()
            .highlight(&zeek_config, source.as_bytes(), None, |_| None)
            .map_err(|e| {
                error!("failed to highlight source: {e}");
                Error::internal_error()
            })?
        {
            match event.map_err(|e| {
                error!("failed to highlight event: {e}");
                Error::internal_error()
            })? {
                HighlightEvent::HighlightStart(Highlight(idx)) => {
                    cur_ty = Some(idx);
                }
                HighlightEvent::Source { start, end } => {
                    let (Ok(start), Ok(end)) = (u32::try_from(start), u32::try_from(end)) else {
                        return Err(Error::internal_error());
                    };

                    let start_ = line_index.line_col(start.into());
                    let end_ = line_index.line_col(end.into());

                    cur_range = Some((
                        Range::new(
                            Position::new(start_.line, start_.col),
                            Position::new(end_.line, end_.col),
                        ),
                        end - start,
                    ));
                }
                HighlightEvent::HighlightEnd => {
                    cur_ty = None;
                    cur_range = None;
                }
            }

            if let (Some(cur_ty), Some(cur_range)) = (cur_ty, cur_range) {
                data.push((cur_ty, cur_range));
            }
        }

        let highlight_names: Vec<_> = highlights().collect();
        let data: Vec<_> = data
            .into_iter()
            .filter_map(|(ty, range)| {
                let name = highlight_names.get(ty)?;
                let ty = SemanticTokenType::from(*name);

                // Skip token types we didn't previously advertise.
                let token_type =
                    u32::try_from(legend.token_types.iter().position(|x| *x == ty)?).ok()?;

                Some((token_type, range))
            })
            .sorted_by(|a, b| Ord::cmp(&a.1 .0.start, &b.1 .0.start))
            .collect();

        let mut tokens = Vec::new();
        let mut prev: Option<(u32, Range)> = None;
        for (token_type, (range, length)) in data {
            let token = if let Some((_, prev_range)) = prev {
                let delta_line = range.start.line - prev_range.start.line;
                let delta_start =
                    range.start.character - u32::from(delta_line == 0) * prev_range.start.character;
                SemanticToken {
                    delta_line,
                    delta_start,
                    length,
                    token_type,
                    ..SemanticToken::default()
                }
            } else {
                SemanticToken {
                    delta_line: range.start.line,
                    delta_start: range.start.character,
                    length: range.end.character - range.start.character,
                    token_type,
                    ..SemanticToken::default()
                }
            };

            tokens.push(token);

            prev = Some((token_type, range));
        }

        Ok(SemanticTokens {
            data: tokens,
            ..SemanticTokens::default()
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]

    use std::{
        path::{Path, PathBuf},
        sync::Arc,
        u32,
    };

    use insta::assert_debug_snapshot;
    use semver::Version;
    use serde_json::json;
    use tower_lsp_server::{
        lsp_types::{
            ClientCapabilities, CodeActionContext, CodeActionParams, CompletionParams,
            CompletionResponse, DocumentSymbolParams, DocumentSymbolResponse, FormattingOptions,
            HoverParams, InlayHintParams, PartialResultParams, Position, Range, ReferenceContext,
            ReferenceParams, RenameParams, SemanticTokensParams, TextDocumentIdentifier,
            TextDocumentPositionParams, Uri, WorkDoneProgressParams, WorkspaceSymbolParams,
        },
        LanguageServer, UriExt,
    };
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    use crate::{
        ast::Ast,
        lsp::{self, tree_diagnostics},
        parse::Parse,
        zeek, Client,
    };

    use super::{Backend, SourceUpdate};

    #[derive(Default)]
    pub(crate) struct TestDatabase(pub(crate) lsp::Database);

    impl TestDatabase {
        pub(crate) fn add_file(&mut self, uri: Uri, source: impl AsRef<str>) {
            self.0
                .update_sources(&[SourceUpdate::Update(Arc::new(uri), source.as_ref().into())]);
        }

        pub(crate) fn add_prefix<P>(&mut self, prefix: P)
        where
            P: Into<PathBuf>,
        {
            let mut prefixes: Vec<_> = self.0.prefixes().into_iter().cloned().collect();
            prefixes.push(prefix.into());
            self.0.set_prefixes(Arc::from(prefixes.clone()));
        }

        pub(crate) fn snapshot(self) -> lsp::Database {
            self.0
        }
    }

    pub(crate) fn serve(database: TestDatabase) -> Backend {
        Backend {
            state: tokio::sync::RwLock::new(database.0),
            ..Backend::default()
        }
    }

    #[test]
    fn debug_database() {
        let db = TestDatabase::default();

        assert_eq!(format!("{:?}", db.0), "Database");
    }

    #[tokio::test]
    async fn symbol() {
        let mut db = TestDatabase::default();
        db.add_prefix("/p1");
        db.add_prefix("/p2");
        db.add_file(
            Uri::from_file_path("/p1/a.zeek").unwrap(),
            "module mod_a; global A = 1;",
        );
        db.add_file(
            Uri::from_file_path("/p2/b.zeek").unwrap(),
            "module mod_b; global B = 2;",
        );
        db.add_file(
            Uri::from_file_path("/x/x.zeek").unwrap(),
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
        let mut db = TestDatabase::default();
        db.add_prefix("/p1");
        db.add_prefix("/p2");
        db.add_file(
            Uri::from_file_path("/p1/a.zeek").unwrap(),
            "module mod_a; global A = 1;",
        );
        db.add_file(
            Uri::from_file_path("/p2/b.zeek").unwrap(),
            "module mod_b; global B = 2;",
        );

        let uri = Arc::new(Uri::from_file_path("/x/x.zeek").unwrap());
        db.add_file(
            (*uri).clone(),
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
                text_document_position: TextDocumentPositionParams::new(
                    TextDocumentIdentifier::new((*uri).clone()),
                    Position::new(6, 0),
                ),
                partial_result_params: PartialResultParams::default(),
                work_done_progress_params: WorkDoneProgressParams::default(),
                context: None,
            })
            .await;

        // Sort results for debug output diffing.
        let result = if let Ok(Some(CompletionResponse::Array(mut r))) = result {
            r.sort_by(|a, b| a.label.cmp(&b.label));
            r
        } else {
            unreachable!()
        };

        assert_debug_snapshot!(result);
    }

    #[tokio::test]
    async fn hover_variable() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
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
            text_document_position_params: TextDocumentPositionParams::new(
                TextDocumentIdentifier::new(uri),
                Position::new(3, 7),
            ),
            work_done_progress_params: WorkDoneProgressParams::default(),
        };

        assert_debug_snapshot!(server.hover(params).await);
    }

    #[tokio::test]
    async fn hover_definition() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
        export {
        ## Declaration.
        global foo: event();
        }

        ## Definition.
        event foo() {}

        ## Definition.
        event zeek_init() {}

        ## Declaration & definition.
        event bar() {}",
        );

        let prefix = Path::new("/prefix");
        db.add_prefix(prefix.to_str().unwrap());
        db.add_file(
            Uri::from_file_path(prefix.join(zeek::essential_input_files().first().unwrap()))
                .unwrap(),
            "
            ##Declaration.
            global zeek_init: event();",
        );

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .hover(HoverParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(7, 15),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .hover(HoverParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(10, 15),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .hover(HoverParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri),
                        Position::new(13, 15),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn hover_decl_in_func_parameters() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
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
            text_document_position_params: TextDocumentPositionParams::new(
                TextDocumentIdentifier::new(uri),
                Position::new(4, 4),
            ),
            work_done_progress_params: WorkDoneProgressParams::default(),
        };

        assert_debug_snapshot!(server.hover(params).await);
    }

    #[tokio::test]
    async fn hover_in_decl_fqid() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
export { const G = 42; }
module foo;
export { const X = 47; }
const Y = 11;

type R: record {};
global r: R;
        ",
        );
        let server = serve(db);

        assert_debug_snapshot!(
            server
                .hover(HoverParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(1, 15)
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default()
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .hover(HoverParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(3, 15)
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default()
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .hover(HoverParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(4, 6)
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default()
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .hover(HoverParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri),
                        Position::new(7, 7)
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default()
                })
                .await
        );
    }

    #[tokio::test]
    async fn hover_zeekygen() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
            function foo() {}

            ## ``foo``",
        );

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .hover(HoverParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(3, 18),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn signature_help() {
        let mut db = TestDatabase::default();
        let uri_x = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri_x.clone(),
            "module x;
global f: function(x: count, y: string): string;
local x = f(",
        );
        let uri_y = Uri::from_file_path("/y.zeek").unwrap();
        db.add_file(
            uri_y.clone(),
            "module y;
global f: function(x: count, y: string): string;
local x = f(1,2,3",
        );
        let uri_z = Uri::from_file_path("/z.zeek").unwrap();
        db.add_file(
            uri_z.clone(),
            "module z;
@load ./ext
local x = ext::f(",
        );
        db.add_file(
            Uri::from_file_path("/ext.zeek").unwrap(),
            "module ext;
export {
global f: function(x: count, y: string): string;
}",
        );

        let server = serve(db);

        let params = super::SignatureHelpParams {
            context: None,
            text_document_position_params: TextDocumentPositionParams::new(
                TextDocumentIdentifier::new(uri_x),
                Position::new(2, 12),
            ),
            work_done_progress_params: WorkDoneProgressParams::default(),
        };
        assert_debug_snapshot!(server.signature_help(params).await);

        let params = super::SignatureHelpParams {
            context: None,
            text_document_position_params: TextDocumentPositionParams::new(
                TextDocumentIdentifier::new(uri_y),
                Position::new(2, 16),
            ),
            work_done_progress_params: WorkDoneProgressParams::default(),
        };
        assert_debug_snapshot!(server.signature_help(params).await);

        let params = super::SignatureHelpParams {
            context: None,
            text_document_position_params: TextDocumentPositionParams::new(
                TextDocumentIdentifier::new(uri_z),
                Position::new(2, 17),
            ),
            work_done_progress_params: WorkDoneProgressParams::default(),
        };
        assert_debug_snapshot!(server.signature_help(params).await);
    }

    #[tokio::test]
    async fn goto_declaration() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "module x;
@load events.bif
global yeah: event(f:string);
event yeah(c:count) {}
event zeek_init() {}",
        );

        let uri_evts = Uri::from_file_path("/events.bif.zeek").unwrap();
        db.add_file(uri_evts, "global zeek_init: event();");

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .goto_declaration(super::GotoDefinitionParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
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
                        TextDocumentIdentifier::new(uri),
                        Position::new(4, 8),
                    ),
                    partial_result_params: PartialResultParams::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn goto_definition() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "module x;
@load events.bif
global yeah: event(f:string);
event yeah(c:count) {}
event zeek_init() {}",
        );

        let uri_evts = Uri::from_file_path("/events.bif.zeek").unwrap();
        db.add_file(uri_evts, "global zeek_init: event();");

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .goto_definition(super::GotoDefinitionParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(3, 8),
                    ),
                    partial_result_params: PartialResultParams::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .goto_definition(super::GotoDefinitionParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri),
                        Position::new(4, 8),
                    ),
                    partial_result_params: PartialResultParams::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn goto_definition_zeekygen() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "
            function foo() {}

            ## ``foo``",
        );

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .goto_definition(super::GotoDefinitionParams {
                    text_document_position_params: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(3, 18),
                    ),
                    partial_result_params: PartialResultParams::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn goto_implementation() {
        let mut db = TestDatabase::default();
        let uri_evts = Uri::from_file_path("/events.bif.zeek").unwrap();
        db.add_file(
            uri_evts.clone(),
            "export {
global zeek_init: event();",
        );

        let uri_x = Uri::from_file_path("/x.zeek").unwrap();
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
                        TextDocumentIdentifier::new(uri_evts),
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
                        TextDocumentIdentifier::new(uri_x),
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
        use super::DocumentFormattingParams;

        let mut db = TestDatabase::default();
        let uri_ok = Uri::from_file_path("/ok.zeek").unwrap();
        db.add_file(uri_ok.clone(), "event zeek_init(){}");

        let uri_invalid = Uri::from_file_path("/invalid.zeek").unwrap();
        db.add_file(uri_invalid.clone(), "event ssl");

        let server = serve(db);

        assert!(server
            .formatting(DocumentFormattingParams {
                text_document: TextDocumentIdentifier::new(uri_ok),
                options: FormattingOptions::default(),
                work_done_progress_params: WorkDoneProgressParams::default(),
            })
            .await
            .is_ok());

        assert_eq!(
            server
                .formatting(DocumentFormattingParams {
                    text_document: TextDocumentIdentifier::new(uri_invalid),
                    options: FormattingOptions::default(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await,
            Ok(None)
        );
    }

    #[ignore]
    #[tokio::test]
    async fn range_formatting() {
        use super::DocumentRangeFormattingParams;

        let mut db = TestDatabase::default();
        let uri_ok = Uri::from_file_path("/ok.zeek").unwrap();
        db.add_file(uri_ok.clone(), "module foo ;\n\nevent zeek_init(){}");

        let uri_invalid = Uri::from_file_path("/invalid.zeek").unwrap();
        db.add_file(uri_invalid.clone(), "event ssl");

        let server = serve(db);

        assert!(server
            .range_formatting(DocumentRangeFormattingParams {
                text_document: TextDocumentIdentifier::new(uri_ok),
                options: FormattingOptions::default(),
                range: Range::new(Position::new(0, 0), Position::new(1, 1)),
                work_done_progress_params: WorkDoneProgressParams::default(),
            })
            .await
            .is_ok());

        assert_eq!(
            server
                .range_formatting(DocumentRangeFormattingParams {
                    text_document: TextDocumentIdentifier::new(uri_invalid),
                    options: FormattingOptions::default(),
                    range: Range::new(Position::new(0, 0), Position::new(1, 1)),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn get_latest_release() {
        let server = serve(TestDatabase::default());

        {
            // Good response from server.
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name":"v0.1.2"})))
                .mount(&mock)
                .await;

            assert_eq!(
                server.get_latest_release(Some(&mock.uri())).await,
                Some(Version::new(0, 1, 2))
            );
        }

        {
            // Server unavailable/sending unexpected response.
            let mock = MockServer::start().await;

            assert_eq!(server.get_latest_release(Some(&mock.uri())).await, None);
        }
    }

    #[tokio::test]
    async fn document_symbol() {
        let mut db = TestDatabase::default();

        let uri_unknown = Uri::from_file_path("/unknown.zeek").unwrap();
        let uri = Uri::from_file_path("/x.zeek").unwrap();

        db.add_file(
            uri.clone(),
            "
            global x = 42;

            module foo;
            global y = 4711;
            ",
        );
        let server = serve(db);

        // Nothing reported for unknown files.
        assert_eq!(
            Ok(Some(DocumentSymbolResponse::Nested(vec![]))),
            server
                .document_symbol(DocumentSymbolParams {
                    text_document: TextDocumentIdentifier::new(uri_unknown),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                })
                .await
        );

        // Valid response for known file.
        assert_debug_snapshot!(
            server
                .document_symbol(DocumentSymbolParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn code_action() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        let source = "global x = 42";
        db.add_file((*uri).clone(), source);

        let context =
            db.0.parse(uri.clone())
                .map(|t| CodeActionContext {
                    diagnostics: tree_diagnostics(&t.root_node()),
                    ..CodeActionContext::default()
                })
                .unwrap();

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .code_action(CodeActionParams {
                    text_document: TextDocumentIdentifier::new((*uri).clone()),
                    range: Range::new(Position::new(0, 1), Position::new(0, 2)),
                    context,
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn inlay_hint_function_params() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        let source = r#"
        function f(x: count, y: string) {}
        f(123, "abc");

        function g(x: count): count { return x; }
        g(1) + g(1);
        global x: count;
        g(x); # No hint here.
        g(x + 1); # Hint here.
        "#;

        db.add_file((*uri).clone(), source);

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .inlay_hint(InlayHintParams {
                    text_document: TextDocumentIdentifier::new((*uri).clone()),
                    range: Range::new(Position::new(0, 0), Position::new(u32::MAX, 0)),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn inlay_hint_decls() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        let source = r"
const x: count = 0;
global x: count = 0;
option x: bool = T;

const x = 0;
global x = 0;
option x = T;
        ";

        db.add_file((*uri).clone(), source);

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .inlay_hint(InlayHintParams {
                    text_document: TextDocumentIdentifier::new((*uri).clone()),
                    range: Range::new(Position::new(5, 0), Position::new(7, 0)),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn inlay_hint_client_config() {
        let default = lsp::InitializationOptions::new();
        let opts = vec![
            lsp::InitializationOptions {
                inlay_hints_variables: false,
                inlay_hints_parameters: false,
                ..default
            },
            lsp::InitializationOptions {
                inlay_hints_variables: true,
                inlay_hints_parameters: false,
                ..default
            },
            lsp::InitializationOptions {
                inlay_hints_variables: false,
                inlay_hints_parameters: true,
                ..default
            },
            lsp::InitializationOptions {
                inlay_hints_variables: true,
                inlay_hints_parameters: true,
                ..default
            },
        ];

        for options in opts {
            let mut db = TestDatabase::default();
            let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());
            db.0.set_initialization_options(Arc::new(options));

            let source = "
global f: function(x: count);
f(1);
const x = 1;
        ";

            db.add_file((*uri).clone(), source);

            let server = serve(db);

            assert_debug_snapshot!(
                server
                    .inlay_hint(InlayHintParams {
                        text_document: TextDocumentIdentifier::new((*uri).clone()),
                        range: Range::new(Position::new(0, 0), Position::new(5, 0)),
                        work_done_progress_params: WorkDoneProgressParams::default(),
                    })
                    .await
            );
        }
    }

    #[test]
    fn deserialize_initialization_options() {
        use lsp::InitializationOptions;
        use serde_json::json;

        assert_eq!(
            InitializationOptions::new(),
            InitializationOptions {
                check_for_updates: true,
                inlay_hints_variables: true,
                inlay_hints_parameters: true,
                references: false,
                rename: false,
                semantic_highlighting: true,
                debug_ast_nodes: false,
            }
        );

        assert_eq!(
            serde_json::from_value::<InitializationOptions>(json!({})).unwrap(),
            InitializationOptions::new()
        );

        assert_eq!(
            serde_json::from_value::<InitializationOptions>(json!({"check_for_updates": false}))
                .unwrap(),
            InitializationOptions {
                check_for_updates: false,
                ..InitializationOptions::new()
            }
        );

        assert_eq!(
            serde_json::from_value::<InitializationOptions>(
                json!({"inlay_hints_parameters": false})
            )
            .unwrap(),
            InitializationOptions {
                inlay_hints_parameters: false,
                ..InitializationOptions::new()
            }
        );

        assert_eq!(
            serde_json::from_value::<InitializationOptions>(
                json!({"inlay_hints_variables": false})
            )
            .unwrap(),
            InitializationOptions {
                inlay_hints_variables: false,
                ..InitializationOptions::new()
            }
        );

        assert_eq!(
            serde_json::from_value::<InitializationOptions>(json!({"references": true})).unwrap(),
            InitializationOptions {
                references: true,
                ..InitializationOptions::new()
            }
        );

        assert_eq!(
            serde_json::from_value::<InitializationOptions>(json!({"rename": true})).unwrap(),
            InitializationOptions {
                rename: true,
                ..InitializationOptions::new()
            }
        );

        assert_eq!(
            serde_json::from_value::<InitializationOptions>(json!({"semantic_highlighting": true}))
                .unwrap(),
            InitializationOptions {
                semantic_highlighting: true,
                ..InitializationOptions::new()
            }
        );

        assert_eq!(
            serde_json::from_value::<InitializationOptions>(json!({"debug_ast_nodes": true}))
                .unwrap(),
            InitializationOptions {
                debug_ast_nodes: true,
                ..InitializationOptions::new()
            }
        );
    }

    #[tokio::test]
    async fn references() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        let source = r#"
@load ./strings
module foo;
export {
const x = 123;
}
const y = x;
const z = x;
levenshtein_distance("", "");
            "#;

        db.add_file((*uri).clone(), source);
        db.add_file(
            Uri::from_file_path("/strings.zeek").unwrap(),
            "function levenshtein_distance(a: string, b: string): count { return 0; }",
        );

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .references(ReferenceParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new((*uri).clone()),
                        Position::new(8, 1), // On `levenshtein_distance`.
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: ReferenceContext {
                        include_declaration: true,
                    },
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .references(ReferenceParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new((*uri).clone()),
                        Position::new(7, 6), // On `z`.
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: ReferenceContext {
                        include_declaration: true,
                    },
                })
                .await
        );

        assert_debug_snapshot!(
            server
                .references(ReferenceParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new((*uri).clone()),
                        Position::new(4, 6), // On first `x`.
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: ReferenceContext {
                        include_declaration: true,
                    },
                })
                .await
        );
    }

    #[tokio::test]
    async fn rename() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Uri::from_file_path("/x.zeek").unwrap());

        let source = r"
@load ./strings
module foo;
export {
const x = 123;
}
const y = x;
const z = x;
            ";

        db.add_file((*uri).clone(), source);
        db.add_file(
            Uri::from_file_path("/strings.zeek").unwrap(),
            "function levenshtein_distance(a: string, b: string): count { return 0; }",
        );

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .rename(RenameParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new((*uri).clone()),
                        Position::new(7, 10),
                    ),
                    new_name: "ABC".into(),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn semantic_tokens_full() {
        let mut db = TestDatabase::default();
        let uri = Uri::from_file_path("/x.zeek").unwrap();

        let source = r"
        # foo
        function foo() {}
        function bar() {} function baz() {}
        ";

        db.add_file(uri.clone(), source);
        db.0.set_capabilities(Arc::new(ClientCapabilities::default()));

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .semantic_tokens_full(SemanticTokensParams {
                    text_document: TextDocumentIdentifier::new(uri),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                })
                .await
        );
    }
}
