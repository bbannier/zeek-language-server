use crate::{
    ast::{load_to_file, Ast},
    complete::complete,
    parse::Parse,
    query::{self, Decl, DeclKind, ModuleId, NodeLocation, Query},
    zeek, Client, Files, Str,
};
use itertools::Itertools;
use rayon::prelude::*;
use salsa::{ParallelDatabase, Snapshot};
use semver::Version;
use serde::Deserialize;
use std::{fmt::Debug, path::PathBuf, sync::Arc};
use tower_lsp::{
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
        InlayHint, InlayHintKind, InlayHintLabel, InlayHintParams, InlayHintTooltip, Location,
        MarkedString, MarkupContent, MarkupKind, MessageType, NumberOrString, OneOf,
        ParameterInformation, ParameterLabel, Position, ProgressParams, ProgressParamsValue,
        ProgressToken, Range, ServerCapabilities, ServerInfo, SignatureHelp, SignatureHelpOptions,
        SignatureHelpParams, SignatureInformation, SymbolInformation, SymbolKind,
        TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Url, WorkDoneProgress,
        WorkDoneProgressBegin, WorkDoneProgressCreateParams, WorkDoneProgressEnd,
        WorkDoneProgressReport, WorkspaceEdit, WorkspaceSymbolParams,
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
pub struct Database {
    storage: salsa::Storage<Self>,
}

pub enum SourceUpdate {
    Remove(Arc<Url>),
    Update(Arc<Url>, Str),
}

impl Database {
    pub fn update_sources(&mut self, updates: &[SourceUpdate]) {
        let mut files = self.files();
        let files = Arc::make_mut(&mut files);

        let mut needs_files_update = false;

        for u in updates {
            match u {
                SourceUpdate::Update(uri, source) => {
                    self.set_unsafe_source(uri.clone(), source.clone());

                    if !files.contains(uri) {
                        files.insert(uri.clone());
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
            self.set_files(Arc::new(files.clone()));
        }
    }

    fn file_changed(&self, uri: Arc<Url>) {
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
        db.set_client_options(Arc::new(Options::new()));

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
    pub client: Option<tower_lsp::Client>,
    state: tokio::sync::Mutex<Database>,
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

    pub async fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(Snapshot<Database>) -> R,
    {
        let db = self.state.lock().await.snapshot();
        f(db)
    }

    pub async fn with_state_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Database) -> R,
    {
        let mut db = self.state.lock().await;
        f(&mut db)
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
            .await
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

    async fn file_changed(&self, uri: Arc<Url>) -> Result<ParseResult> {
        if let Some(client) = &self.client {
            let diags = self
                .with_state(|state| {
                    state.file_changed(uri.clone());

                    let Some(tree) = state.parse(uri.clone()) else {
                        return Vec::new();
                    };

                    tree_diagnostics(&tree.root_node())
                })
                .await;

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

    pub async fn visible_files(&self) -> Result<Vec<Url>> {
        let system_files = zeek::system_files()
            .await
            .map_err(|e| {
                error!("could not read system files: {e}");
                Error::internal_error()
            })?
            .into_par_iter()
            .filter_map(|f| Url::from_file_path(f.path).ok());

        let workspace_folders = self.with_state(|s| s.workspace_folders()).await;

        let workspace_files = workspace_folders
            .par_iter()
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

    /// This wrapper around `zeek::check` directly publishing diagnostics.
    async fn check(&self, uri: Url, version: Option<i32>) {
        // If we have not client to publish to there is no need to run checks.
        let Some(client) = &self.client else {
            return;
        };

        let Ok(file) = uri.to_file_path() else {
            return;
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
            .await;

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
                self.warn_message(e).await;
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

        client.publish_diagnostics(uri, diags, version).await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    #[instrument]
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        let workspace_folders = params
            .workspace_folders
            .map_or_else(Vec::new, |xs| xs.into_iter().map(|x| x.uri).collect());

        self.with_state_mut(move |state| {
            state.set_workspace_folders(Arc::new(workspace_folders));
            state.set_capabilities(Arc::new(params.capabilities));
            state.set_client_options(Arc::new(
                params
                    .initialization_options
                    .and_then(|options| serde_json::from_value(options).ok())
                    .unwrap_or_else(Options::new),
            ));
        })
        .await;

        // Check prerequistes and set system prefixes.
        match zeek::prefixes(None).await {
            Ok(prefixes) => {
                self.with_state_mut(move |state| {
                    state.set_prefixes(Arc::new(prefixes));
                })
                .await;
            }
            Err(e) => {
                self.warn_message(format!(
                    "cannot detect Zeek prefixes, results will be incomplete or incorrect: {e}"
                ))
                .await;
            }
        }

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
                document_formatting_provider: Some(OneOf::Left(has_zeek_format)),
                document_range_formatting_provider: Some(OneOf::Left(has_zeek_format)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                inlay_hint_provider: Some(OneOf::Left(true)),
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
        // Check whether a newer release is available.
        if self
            .with_state(|s| s.client_options().check_for_updates)
            .await
        {
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
        let progress_token = self.progress_begin("Indexing").await;

        self.progress(
            progress_token.clone(),
            Some("refresing sources".to_string()),
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
                    let source = match tokio::fs::read_to_string(c.uri.path()).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("failed to read '{}': {}", &c.uri, e);
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
            self.with_state_mut(|s| s.update_sources(&changes)).await;
        }

        // Preload expensive information. Ultimately we want to be able to load implicit
        // declarations quickly since they are on the critical part of getting the user to useful
        // completions right after server startup.
        //
        // We explicitly precompute per-file information here so we can parallelize this work.

        self.progress(progress_token.clone(), Some("declarations".to_string()))
            .await;
        let files = self.with_state(|s| (*s.files()).clone()).await;

        {
            let preloaded_decls = self
                .with_state(|state| {
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
                                let _x = db.loaded_files(f);
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .await;
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
        let uri = Arc::new(params.text_document.uri.clone());

        // Update source.
        self.with_state_mut(|state| {
            state.update_sources(&[SourceUpdate::Update(
                uri.clone(),
                params.text_document.text.into(),
            )]);
        })
        .await;

        // Reload implicit declarations since their result depends on the list of known files and
        // is on the critical path for e.g., completion.
        let _implicit = self.with_state(|s| s.implicit_decls());

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
        };
    }

    #[instrument]
    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let Some(changes) = params.content_changes.get(0) else {
            error!("more than one change received even though we only advertize full update mode");
            return;
        };

        assert!(changes.range.is_none(), "unexpected diff mode");

        let uri = Arc::new(params.text_document.uri);

        // Update source.
        self.with_state_mut(|state| {
            state.update_sources(&[SourceUpdate::Update(
                uri.clone(),
                changes.text.as_str().into(),
            )]);
        })
        .await;

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

        self.with_state(move |state| {
            let Some(source) = state.source(uri.clone()) else {
                return Ok(None);
            };

            let tree = state.parse(uri.clone());
            let Some(tree) = tree.as_ref() else {
                return Ok(None);
            };

            let node = tree.root_node();
            let Some(node) = node.named_descendant_for_position(params.position) else {
                return Ok(None);
            };

            let text = node.utf8_text(source.as_bytes()).map_err(|e| {
                error!("could not get source text: {}", e);
                Error::internal_error()
            })?;

            let mut contents = vec![
                #[cfg(all(debug_assertions, not(test)))]
                MarkedString::LanguageString(tower_lsp::lsp_types::LanguageString {
                    value: text.into(),
                    language: "zeek".into(),
                }),
                #[cfg(all(debug_assertions, not(test)))]
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
                            id = decl.fqid
                        )));

                        if let Some(typ) = state.typ(decl.clone()) {
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
                _ => {}
            }

            let hover = Hover {
                contents: HoverContents::Array(contents),
                range: Some(node.range()),
            };

            Ok(Some(hover))
        })
        .await
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

        let modules = self
            .with_state(move |state| {
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
            })
            .await;

        Ok(Some(DocumentSymbolResponse::Nested(modules)))
    }

    #[instrument]
    async fn symbol(
        &self,
        params: WorkspaceSymbolParams,
    ) -> Result<Option<Vec<SymbolInformation>>> {
        let query = params.query.to_lowercase();

        let symbols = self
            .with_state(|state| {
                let files = state.files();
                files
                    .iter()
                    .flat_map(|uri| {
                        state
                            .decls(uri.clone())
                            .iter()
                            .filter(|d| {
                                rust_fuzzy_search::fuzzy_compare(&query, &d.fqid.to_lowercase())
                                    > 0.0
                            })
                            .filter_map(|d| {
                                let url: &Url = uri;
                                let loc = &d.loc.as_ref()?;

                                #[allow(deprecated)]
                                Some(SymbolInformation {
                                    name: d.fqid.to_string(),
                                    kind: to_symbol_kind(&d.kind),

                                    location: Location::new(url.clone(), loc.range),
                                    container_name: Some(format!("{}", &d.module)),

                                    tags: None,
                                    deprecated: None,
                                })
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
            .await;

        Ok(Some(symbols))
    }

    #[instrument]
    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        Ok(self.with_state(move |state| complete(&state, params)).await)
    }

    #[instrument]
    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let params = params.text_document_position_params;
        let uri = Arc::new(params.text_document.uri);
        let position = params.position;

        let location = self
            .with_state(|state| {
                let tree = state.parse(uri.clone());
                let tree = tree.as_ref()?;
                let node = tree.root_node().named_descendant_for_position(position)?;
                let source = state.source(uri.clone())?;

                match node.kind() {
                    "id" => state
                        .resolve(NodeLocation::from_node(uri, node))
                        .and_then(|d| {
                            let loc = &d.loc.as_ref()?;
                            Some(Location::new((*loc.uri).clone(), loc.range))
                        }),
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
                        .map(|uri| Location::new((*uri).clone(), Range::default()))
                    }
                    _ => None,
                }
            })
            .await;

        Ok(location.map(GotoDefinitionResponse::Scalar))
    }

    #[instrument]
    async fn signature_help(&self, params: SignatureHelpParams) -> Result<Option<SignatureHelp>> {
        let uri = Arc::new(params.text_document_position_params.text_document.uri);
        let position = params.text_document_position_params.position;

        self.with_state(move |state| {
            let Some(source) = state.source(uri.clone()) else {
                return Ok(None);
            };
            let Some(tree) = state.parse(uri.clone()) else {
                return Ok(None);
            };

            // TODO(bbannier): We do not handle newlines between the function name and any ultimate parameter.
            let Some(line) = source.lines().nth(position.line as usize) else {
                return Ok(None);
            };

            #[allow(clippy::cast_possible_truncation)]
            let line = if (line.len() + 1) as u32 > position.character {
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
                    #[allow(clippy::cast_possible_truncation)]
                    let character = (line.len() - i - 1) as u32;
                    tree.root_node().named_descendant_for_position(Position {
                        character,
                        ..position
                    })
                })
            else {
                return Ok(None);
            };

            #[allow(clippy::cast_possible_truncation)]
            let active_parameter = Some(line.chars().filter(|c| c == &',').count() as u32);

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
            let Some(tree) = state.parse(loc.uri.clone()) else {
                return Ok(None);
            };
            let Some(source) = state.source(loc.uri.clone()) else {
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
        })
        .await
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

        let tree = self
            .with_state(|state| state.parse(Arc::new(params.text_document.uri)))
            .await;

        Ok(tree.map(|t| compute_folds(t.root_node(), false)))
    }

    #[instrument]
    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = Arc::new(params.text_document.uri);

        let source = self.with_state(|state| state.source(uri.clone())).await;

        let Some(source) = source else {
            return Ok(None);
        };

        let range = match self.with_state(|state| state.parse(uri)).await {
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

        let source = self.with_state(|state| state.source(uri.clone())).await;

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

        let decl = self
            .with_state(|state| {
                let tree = state.parse(uri.clone());
                let tree = tree.as_ref()?;
                let node = tree.root_node().named_descendant_for_position(position)?;

                let decl = state.resolve(NodeLocation::from_node(uri.clone(), node))?;

                match &decl.kind {
                    // We are done as we have found a declaration.
                    DeclKind::EventDecl(_) | DeclKind::FuncDecl(_) | DeclKind::HookDecl(_) => {
                        Some((*decl).clone())
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
                                DeclKind::EventDecl(_)
                                    | DeclKind::FuncDecl(_)
                                    | DeclKind::HookDecl(_)
                            )
                        })
                        .find(|&d| d.id == decl.id)
                        .map(Clone::clone),
                    _ => None,
                }
            })
            .await;

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

        let response = self
            .with_state(|state| {
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
                            let loc = &d.loc.as_ref()?;
                            if d.id == decl.id {
                                Some(Location::new((*loc.uri).clone(), loc.range))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .await;

        Ok(response.map(GotoImplementationResponse::from))
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
        let Some(missing) = self
            .with_state(|state| {
                state.parse(uri.clone()).and_then(|t| {
                    t.root_node().errors().into_iter().find_map(|err| {
                        // Filter out `MISSING` nodes at the diagnostic.
                        if err.is_missing() && err.range() == diag.range {
                            // `kind` holds the fix for the `MISSING` error.
                            Some(err.kind().to_string())
                        } else {
                            None
                        }
                    })
                })
            })
            .await
        else {
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

    async fn inlay_hint(&self, params: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        let uri = Arc::new(params.text_document.uri);

        let mut hints = Vec::new();

        let function_params: Vec<_> = self
            .with_state(|state| {
                if !state.client_options().inlay_hints_parameters {
                    return Vec::default();
                }

                let possible_call_ranges = state.function_calls(uri.clone());
                possible_call_ranges
                    .iter()
                    .filter_map(|c| match &state.resolve(c.f.clone())?.kind {
                        DeclKind::FuncDef(s)
                        | DeclKind::FuncDecl(s)
                        | DeclKind::HookDef(s)
                        | DeclKind::HookDecl(s)
                        | DeclKind::EventDef(s)
                        | DeclKind::EventDecl(s) => Some(
                            c.args
                                .iter()
                                .zip(s.args.iter())
                                .map(|(p, a)| InlayHint {
                                    position: p.range.start,
                                    label: InlayHintLabel::String(format!("{}:", a.id)),
                                    kind: Some(InlayHintKind::PARAMETER),
                                    text_edits: None,
                                    tooltip: Some(InlayHintTooltip::MarkupContent(MarkupContent {
                                        kind: MarkupKind::Markdown,
                                        value: a.documentation.to_string(),
                                    })),
                                    padding_left: None,
                                    padding_right: Some(true),
                                    data: None,
                                })
                                .collect::<Vec<_>>(),
                        ),
                        _ => None,
                    })
                    .flatten()
                    .collect()
            })
            .await;

        let decls: Vec<_> = self
            .with_state(|state| {
                if !state.client_options().inlay_hints_variables {
                    return Vec::default();
                }

                let decls = state.untyped_var_decls(uri.clone());
                decls
                    .iter()
                    .filter_map(|d| {
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
                    .collect()
            })
            .await;

        hints.extend(function_params);
        hints.extend(decls);

        Ok(Some(hints))
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
        ..Backend::default()
    });
    Server::new(stdin, stdout, socket).serve(service).await;
}

#[derive(Deserialize, Debug, Clone, Copy)]
/// Custom `initializationOptions` clients can send.
pub struct Options {
    #[serde(default = "Options::_default_check_for_updates")]
    check_for_updates: bool,

    #[serde(default = "Options::_default_inlay_hints_parameters")]
    inlay_hints_parameters: bool,

    #[serde(default = "Options::_default_inlay_hints_variables")]
    inlay_hints_variables: bool,
}

impl Options {
    const fn new() -> Self {
        Self {
            check_for_updates: true,
            inlay_hints_variables: true,
            inlay_hints_parameters: true,
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
}

#[cfg(test)]
pub(crate) mod test {
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
    };

    use insta::assert_debug_snapshot;
    use salsa::{ParallelDatabase, Snapshot};
    use semver::Version;
    use serde_json::json;
    use tower_lsp::{
        lsp_types::{
            CompletionParams, CompletionResponse, DocumentSymbolParams, DocumentSymbolResponse,
            FormattingOptions, HoverParams, InitializeParams, InlayHintParams, PartialResultParams,
            Position, Range, TextDocumentIdentifier, TextDocumentPositionParams, Url,
            WorkDoneProgressParams, WorkspaceSymbolParams,
        },
        LanguageServer,
    };
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    use crate::{ast::Ast, lsp, parse::Parse, zeek, Client};

    use super::{Backend, SourceUpdate};

    #[derive(Default)]
    pub(crate) struct TestDatabase(pub(crate) lsp::Database);

    impl TestDatabase {
        pub(crate) fn add_file(&mut self, uri: Url, source: impl AsRef<str>) {
            self.0
                .update_sources(&[SourceUpdate::Update(Arc::new(uri), source.as_ref().into())]);
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
            state: tokio::sync::Mutex::new(database.0),
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
            Url::from_file_path("/p1/a.zeek").unwrap(),
            "module mod_a; global A = 1;",
        );
        db.add_file(
            Url::from_file_path("/p2/b.zeek").unwrap(),
            "module mod_b; global B = 2;",
        );
        db.add_file(
            Url::from_file_path("/x/x.zeek").unwrap(),
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
            Url::from_file_path("/p1/a.zeek").unwrap(),
            "module mod_a; global A = 1;",
        );
        db.add_file(
            Url::from_file_path("/p2/b.zeek").unwrap(),
            "module mod_b; global B = 2;",
        );

        let uri = Arc::new(Url::from_file_path("/x/x.zeek").unwrap());
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
        let mut db = TestDatabase::default();
        let uri = Url::from_file_path("/x.zeek").unwrap();
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
        let uri = Url::from_file_path("/x.zeek").unwrap();
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
            Url::from_file_path(prefix.join(zeek::essential_input_files().first().unwrap()))
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
        let uri = Url::from_file_path("/x.zeek").unwrap();
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
        let uri = Url::from_file_path("/x.zeek").unwrap();
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
    async fn signature_help() {
        let mut db = TestDatabase::default();
        let uri_x = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri_x.clone(),
            "module x;
global f: function(x: count, y: string): string;
local x = f(",
        );
        let uri_y = Url::from_file_path("/y.zeek").unwrap();
        db.add_file(
            uri_y.clone(),
            "module y;
global f: function(x: count, y: string): string;
local x = f(1,2,3",
        );
        let uri_z = Url::from_file_path("/z.zeek").unwrap();
        db.add_file(
            uri_z.clone(),
            "module z;
@load ./ext
local x = ext::f(",
        );
        db.add_file(
            Url::from_file_path("/ext.zeek").unwrap(),
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
        let uri = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "module x;
@load events.bif
global yeah: event(f:string);
event yeah(c:count) {}
event zeek_init() {}",
        );

        let uri_evts = Url::from_file_path("/events.bif.zeek").unwrap();
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
        let uri = Url::from_file_path("/x.zeek").unwrap();
        db.add_file(
            uri.clone(),
            "module x;
@load events.bif
global yeah: event(f:string);
event yeah(c:count) {}
event zeek_init() {}",
        );

        let uri_evts = Url::from_file_path("/events.bif.zeek").unwrap();
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
    async fn goto_implementation() {
        let mut db = TestDatabase::default();
        let uri_evts = Url::from_file_path("/events.bif.zeek").unwrap();
        db.add_file(
            uri_evts.clone(),
            "export {
global zeek_init: event();",
        );

        let uri_x = Url::from_file_path("/x.zeek").unwrap();
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
        let uri_ok = Url::from_file_path("/ok.zeek").unwrap();
        db.add_file(uri_ok.clone(), "event zeek_init(){}");

        let uri_invalid = Url::from_file_path("/invalid.zeek").unwrap();
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
        let uri_ok = Url::from_file_path("/ok.zeek").unwrap();
        db.add_file(uri_ok.clone(), "module foo ;\n\nevent zeek_init(){}");

        let uri_invalid = Url::from_file_path("/invalid.zeek").unwrap();
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
        let _ = server.initialize(InitializeParams::default()).await;

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

        let uri_unknown = Url::from_file_path("/unknown.zeek").unwrap();
        let uri = Url::from_file_path("/x.zeek").unwrap();

        db.add_file(uri.clone(), "global x = 42;");
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
        use super::{tree_diagnostics, CodeActionParams};
        use tower_lsp::lsp_types::CodeActionContext;

        let mut db = TestDatabase::default();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());

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
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());

        let source = r#"
        function f(x: count, y: string) {}
        f(123, "abc");

        function g(x: count): count { return x; }
        g(1) + g(1);
        "#;

        db.add_file((*uri).clone(), source);

        let server = serve(db);

        assert_debug_snapshot!(
            server
                .inlay_hint(InlayHintParams {
                    text_document: TextDocumentIdentifier::new((*uri).clone()),
                    range: Range::new(Position::new(0, 0), Position::new(3, 0)),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                })
                .await
        );
    }

    #[tokio::test]
    async fn inlay_hint_decls() {
        let mut db = TestDatabase::default();
        let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());

        let source = r#"
const x: count = 0;
global x: count = 0;
option x: bool = T;

const x = 0;
global x = 0;
option x = T;
        "#;

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

    #[tokio::test]
    async fn inlay_hint_client_config() {
        let default = lsp::Options::new();
        let opts = vec![
            lsp::Options {
                inlay_hints_variables: false,
                inlay_hints_parameters: false,
                ..default
            },
            lsp::Options {
                inlay_hints_variables: true,
                inlay_hints_parameters: false,
                ..default
            },
            lsp::Options {
                inlay_hints_variables: false,
                inlay_hints_parameters: true,
                ..default
            },
            lsp::Options {
                inlay_hints_variables: true,
                inlay_hints_parameters: true,
                ..default
            },
        ];

        for options in opts {
            let mut db = TestDatabase::default();
            let uri = Arc::new(Url::from_file_path("/x.zeek").unwrap());
            db.0.set_client_options(Arc::new(options));

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
                err.error(),
                None,
                None,
            )
        })
        .collect()
}
