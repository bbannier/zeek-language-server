use crate::{
    ast::{self, load_to_file, Ast},
    parse::Parse,
    query::{self, Decl, DeclKind, Query},
    zeek, Files,
};
use itertools::Itertools;
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
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};
use tracing::{error, instrument, warn};

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

                state.file_changed(uri.clone());
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

            state.file_changed(uri);
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
            state.file_changed(uri);
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

        let node = match tree.named_descendant_for_position(params.position) {
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
                if let Some(decl) = ast::resolve(&state, node, None, uri) {
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
            node = match node.prev_sibling() {
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
            if let Some(r) = ast::resolve(&state, node, None, uri.clone()) {
                let decl = ast::typ(&state, &r);

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
                .filter(|d| d.kind != DeclKind::Event)
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
        let node = match tree.named_descendant_for_position(position) {
            Some(n) => n,
            None => return Ok(None),
        };
        let source = state.source(uri.clone());

        let text = node.utf8_text(source.as_bytes()).map_err(|e| {
            error!("could not get source text: {}", e);
            Error::new(ErrorCode::InternalError)
        })?;

        let location = match node.kind() {
            "id" => ast::resolve(&state, node, None, uri)
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

fn to_symbol_kind(kind: &DeclKind) -> SymbolKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef => SymbolKind::VARIABLE,
        DeclKind::Option => SymbolKind::PROPERTY,
        DeclKind::Const => SymbolKind::CONSTANT,
        DeclKind::RedefEnum => SymbolKind::ENUM,
        DeclKind::RedefRecord => SymbolKind::INTERFACE,
        DeclKind::Type(_) => SymbolKind::CLASS,
        DeclKind::FuncDecl | DeclKind::FuncDef => SymbolKind::FUNCTION,
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
        DeclKind::FuncDecl | DeclKind::FuncDef => CompletionItemKind::FUNCTION,
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
pub(crate) mod test {
    use std::{
        collections::BTreeSet,
        path::PathBuf,
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
}
