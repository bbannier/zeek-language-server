use tower_lsp::jsonrpc::Error;

use {
    crate::{parse::Parse, ID},
    std::{
        collections::HashSet,
        fmt::Debug,
        sync::{Arc, Mutex},
    },
    tower_lsp::{
        jsonrpc::{ErrorCode, Result},
        lsp_types::{
            DidChangeTextDocumentParams, DidOpenTextDocumentParams, Hover, HoverContents,
            HoverParams, HoverProviderCapability, InitializeParams, InitializeResult,
            InitializedParams, MarkedString, MessageType, Position, Range, ServerCapabilities,
            TextDocumentIdentifier, TextDocumentSyncCapability, TextDocumentSyncKind,
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
                ..ServerCapabilities::default()
            },
            ..InitializeResult::default()
        })
    }

    #[instrument]
    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::Info, "server initialized!")
            .await;
    }

    #[instrument]
    async fn shutdown(&self) -> Result<()> {
        Ok(())
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

        return;
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

        let offset = |x: usize| u32::try_from(x).map_err(|_| Error::new(ErrorCode::InternalError));

        let hover = Hover {
            contents: HoverContents::Scalar(MarkedString::String(node.to_sexp())),
            range: Some(Range::new(
                Position::new(
                    offset(node.start_position().row)?,
                    offset(node.start_position().column)?,
                ),
                Position::new(
                    offset(node.end_position().row)?,
                    offset(node.end_position().column)?,
                ),
            )),
        };

        Ok(Some(hover))
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
