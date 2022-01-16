use {
    crate::{
        parse::Parse,
        query::{self, decls, default_module_name, Decl, DeclKind},
        to_range, zeek, ID,
    },
    log::warn,
    std::{
        collections::HashSet,
        fmt::Debug,
        sync::{Arc, Mutex},
    },
    tower_lsp::{
        jsonrpc::{Error, ErrorCode, Result},
        lsp_types::{
            CompletionItem, CompletionItemKind, CompletionOptions, CompletionParams,
            CompletionResponse, CreateFilesParams, DidChangeTextDocumentParams,
            DidOpenTextDocumentParams, DocumentSymbol, DocumentSymbolParams,
            DocumentSymbolResponse, FileCreate, Hover, HoverContents, HoverParams,
            HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams,
            MarkedString, MessageType, OneOf, ServerCapabilities, SymbolKind,
            TextDocumentIdentifier, TextDocumentSyncCapability, TextDocumentSyncKind, Url,
            VersionedTextDocumentIdentifier,
        },
        Client, LanguageServer, LspService, Server,
    },
    tracing::instrument,
};

#[salsa::database(crate::parse::ParseStorage)]
#[derive(Default)]
pub struct Database {
    storage: salsa::Storage<Self>,
}

impl salsa::Database for Database {}

impl Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database").finish()
    }
}

#[derive(Debug, Default)]
struct State {
    files: HashSet<ID>,
    db: Database,
}

impl State {
    #[must_use]
    pub fn get_file(&self, id: &TextDocumentIdentifier) -> Option<ID> {
        self.files
            .iter()
            .filter(|f| f.uri == id.uri)
            .max_by_key(|f| f.version)
            .map(Clone::clone)
    }
}

#[derive(Debug)]
struct Backend {
    client: Client,
    state: Mutex<State>,
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    #[instrument]
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::Full,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec!["$".into(), "?".into()]),
                    ..CompletionOptions::default()
                }),
                ..ServerCapabilities::default()
            },
            ..InitializeResult::default()
        })
    }

    #[instrument]
    async fn initialized(&self, _: InitializedParams) {
        // discover_system_files;
        self.client
            .log_message(MessageType::Info, "server initialized!")
            .await;

        match zeek::system_files().await {
            Ok(files) => {
                self.did_create_files(CreateFilesParams {
                    files: files
                        .into_iter()
                        .filter_map(|f| {
                            Some(FileCreate {
                                uri: f.path.into_os_string().into_string().ok()?,
                            })
                        })
                        .collect(),
                })
                .await;
            }
            Err(e) => {
                self.client.log_message(MessageType::Error, e).await;
            }
        }
    }

    #[instrument]
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    #[instrument]
    async fn did_create_files(&self, params: CreateFilesParams) {
        let _process = params
            .files
            .iter()
            .filter_map(|f| {
                let uri = if let Ok(uri) = Url::from_file_path(&f.uri) {
                    uri
                } else {
                    warn!(
                        "ignoring {} since its path cannot be converted to an URI",
                        &f.uri
                    );
                    return None;
                };

                let version = 0;
                let id: ID = VersionedTextDocumentIdentifier::new(uri, version).into();

                let source = match std::fs::read_to_string(&f.uri) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("failed to read '{}': {}", &f.uri, e);
                        return None;
                    }
                };

                if let Ok(state) = self.state.lock().as_deref_mut() {
                    state.files.insert(id.clone());
                    state.db.set_source(id.clone(), std::sync::Arc::new(source));
                    let _parse = state.db.parse(id);
                };

                Some(())
            })
            .collect::<Vec<_>>();
    }

    #[instrument]
    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let id: ID = VersionedTextDocumentIdentifier::new(
            params.text_document.uri,
            params.text_document.version,
        )
        .into();

        if let Ok(state) = self.state.lock().as_deref_mut() {
            state.files.insert(id.clone());
            state
                .db
                .set_source(id, std::sync::Arc::new(params.text_document.text));
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

        let id: ID = params.text_document.into();
        let source = changes.text.to_string();

        if let Ok(state) = self.state.lock().as_deref_mut() {
            state.db.set_source(id.clone(), Arc::new(source));
            state.files.insert(id);
            // FIXME(bbannier): implement gc of old versions.
        }
    }

    #[instrument]
    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let params = &params.text_document_position_params;

        let state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorCode::InternalError))?;

        let doc_id = match state.get_file(&params.text_document) {
            Some(id) => id,
            None => {
                return Err(Error::new(ErrorCode::InvalidParams));
            }
        };

        // TODO(bbannier): This is more of a demo and debugging tool for now. Eventually this
        // should return some nice rendering of the hovered node.

        let tree = state.db.parse(doc_id);
        let tree = match tree.as_ref() {
            Some(t) => t,
            None => return Ok(None),
        };

        let node = match tree.named_descendant_for_position(&params.position) {
            Some(n) => n,
            None => return Ok(None),
        };

        let hover = Hover {
            contents: HoverContents::Scalar(MarkedString::String(node.to_sexp())),
            range: to_range(node.range()).ok(),
        };

        Ok(Some(hover))
    }

    #[instrument]
    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let (source, tree) = {
            let state = self
                .state
                .lock()
                .map_err(|_| Error::new(ErrorCode::InternalError))?;

            let doc_id = match state.get_file(&params.text_document) {
                Some(id) => id,
                None => return Ok(None),
            };

            (state.db.source(doc_id.clone()), state.db.parse(doc_id))
        };
        let tree = match tree.as_ref() {
            Some(t) => t,
            None => return Ok(None),
        };

        let module = query::module(tree.root_node(), &source);

        let symbol = |d: Decl| -> DocumentSymbol {
            #[allow(deprecated)]
            DocumentSymbol {
                name: d.id,
                range: d.range,
                selection_range: d.selection_range,
                kind: to_symbol_kind(d.kind),
                deprecated: None,
                detail: None,
                tags: None,
                children: None,
            }
        };

        let range = to_range(tree.root_node().range())
            .map_err(|_| Error::new(ErrorCode::ContentModified))?;

        Ok(Some(
            #[allow(deprecated)]
            DocumentSymbolResponse::Nested(vec![DocumentSymbol {
                name: module
                    .id
                    .unwrap_or_else(|| {
                        default_module_name(&params.text_document.uri).unwrap_or("<invalid>")
                    })
                    .into(),
                kind: SymbolKind::Module,
                range,
                selection_range: range,
                deprecated: None,

                detail: None,
                tags: None,
                children: Some(module.decls.into_iter().map(symbol).collect()),
            }]),
        ))
    }

    #[instrument]
    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let position = params.text_document_position;

        let (source, tree) = {
            let state = self
                .state
                .lock()
                .map_err(|_| Error::new(ErrorCode::InternalError))?;

            let doc_id = match state.get_file(&position.text_document) {
                Some(id) => id,
                None => return Ok(None),
            };

            (state.db.source(doc_id.clone()), state.db.parse(doc_id))
        };

        let tree = match tree.as_ref() {
            Some(t) => t,
            None => return Ok(None),
        };

        let node = match tree.descendant_for_position(&position.position) {
            Some(n) => n,
            None => return Ok(None),
        };

        let items: Vec<_> = {
            let mut items = Vec::new();
            let mut node = node;
            loop {
                items.append(&mut decls(node, &source));
                node = match node.parent() {
                    Some(n) => n,
                    None => break,
                };
            }
            items
                .into_iter()
                .map(|i| CompletionItem {
                    label: i.id,
                    kind: Some(to_completion_item_kind(i.kind)),
                    ..CompletionItem::default()
                })
                .collect()
        };

        Ok(Some(CompletionResponse::from(items)))
    }
}

fn to_symbol_kind(kind: DeclKind) -> SymbolKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef => SymbolKind::Variable,
        DeclKind::Option => SymbolKind::Property,
        DeclKind::Const => SymbolKind::Constant,
        DeclKind::RedefEnum => SymbolKind::Enum,
        DeclKind::RedefRecord => SymbolKind::Interface,
        DeclKind::Type => SymbolKind::Class,
        DeclKind::Func => SymbolKind::Function,
        DeclKind::Hook => SymbolKind::Operator,
        DeclKind::Event => SymbolKind::Event,
    }
}

fn to_completion_item_kind(kind: DeclKind) -> CompletionItemKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef => CompletionItemKind::Variable,
        DeclKind::Option => CompletionItemKind::Property,
        DeclKind::Const => CompletionItemKind::Constant,
        DeclKind::RedefEnum => CompletionItemKind::Enum,
        DeclKind::RedefRecord => CompletionItemKind::Interface,
        DeclKind::Type => CompletionItemKind::Class,
        DeclKind::Func => CompletionItemKind::Function,
        DeclKind::Hook => CompletionItemKind::Operator,
        DeclKind::Event => CompletionItemKind::Event,
    }
}

pub async fn run() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, messages) = LspService::new(|client| Backend {
        client,
        state: Mutex::default(),
    });
    Server::new(stdin, stdout)
        .interleave(messages)
        .serve(service)
        .await;
}
