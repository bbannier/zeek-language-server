use lsp_types::{Hover, MarkedString, Position, Range};

use {
    crate::{parse::Parse, ID},
    crossbeam_channel::select,
    eyre::{eyre, Result},
    log::{debug, info},
    lsp_server::{Connection, IoThreads, Message, Notification, Request, RequestId, Response},
    lsp_types::{
        notification, request, HoverContents, HoverParams, HoverProviderCapability,
        InitializeParams, ServerCapabilities, TextDocumentIdentifier, TextDocumentSyncCapability,
        TextDocumentSyncKind, VersionedTextDocumentIdentifier,
    },
    std::{collections::HashSet, fmt::Debug, sync::Arc},
    tracing::instrument,
};

pub struct LanguageServer {
    initialize_params: Option<InitializeParams>,
    connection: Connection,
    _io_threads: IoThreads,
    files: HashSet<ID>,
    db: Database,
}

impl Debug for LanguageServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LanguageServer").finish()
    }
}

impl Default for LanguageServer {
    fn default() -> Self {
        let (connection, io_threads) = Connection::stdio();

        LanguageServer {
            connection,
            _io_threads: io_threads,
            initialize_params: None,
            files: HashSet::default(),
            db: Database::default(),
        }
    }
}

fn event(receiver: &crossbeam_channel::Receiver<Message>) -> Result<Message> {
    select! {recv(receiver) -> msg => match msg {
        Ok(msg) => {
            debug!("received {:?}", &msg);
            Ok(msg)
        },
        Err(_) => Err(eyre!("client exited without shutdown")),
    }}
}

fn send_response<T>(sender: &crossbeam_channel::Sender<Message>, msg: T) -> Result<()>
where
    T: Into<Message> + std::fmt::Debug,
{
    debug!("sending {:?}", msg);
    sender.send(msg.into()).map_err(Into::into)
}

mod cast {
    use {
        lsp_server::{Notification, Request, RequestId},
        lsp_types::{notification, request},
    };

    pub fn request<R>(req: Request) -> std::result::Result<(RequestId, R::Params), Request>
    where
        R: request::Request,
        R::Params: serde::de::DeserializeOwned,
    {
        req.extract(R::METHOD)
    }

    pub fn notification<N>(not: Notification) -> std::result::Result<N::Params, Notification>
    where
        N: notification::Notification,
        N::Params: serde::de::DeserializeOwned,
    {
        not.extract(N::METHOD)
    }
}

impl LanguageServer {
    #[instrument]
    fn init(&mut self) -> Result<()> {
        if self.initialize_params.is_some() {
            debug!("server already initialized");
            return Ok(());
        }

        let server_capabilities = ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
            hover_provider: Some(HoverProviderCapability::Simple(true)),
            ..ServerCapabilities::default()
        };

        let initialize_params = self
            .connection
            .initialize(serde_json::to_value(server_capabilities)?)?;

        self.initialize_params = serde_json::from_value(initialize_params)?;

        debug!("server initialized: {:?}", &self.initialize_params);

        Ok(())
    }

    pub fn get_file(&self, id: &TextDocumentIdentifier) -> Option<ID> {
        self.files
            .iter()
            .filter(|f| f.uri == id.uri)
            .max_by_key(|f| f.version)
            .map(Clone::clone)
    }

    #[instrument]
    #[allow(clippy::needless_return)]
    fn handle_request(&self, req: Request) -> Result<()> {
        info!("handling request: {:?}", req);

        match cast::request::<request::HoverRequest>(req) {
            Ok((id, params)) => {
                return self.hover(id, &params);
            }
            Err(req) => req,
        };

        todo!()
    }

    #[instrument]
    #[allow(clippy::needless_return)]
    fn handle_notification(&mut self, not: Notification) {
        info!("handling notification: {:?}", not);

        let not = match cast::notification::<notification::DidOpenTextDocument>(not) {
            Ok(params) => {
                let id: ID = VersionedTextDocumentIdentifier::new(
                    params.text_document.uri,
                    params.text_document.version,
                )
                .into();

                self.files.insert(id.clone());
                self.db
                    .set_source(id, std::sync::Arc::new(params.text_document.text));

                return;
            }
            Err(not) => not,
        };
        match cast::notification::<notification::DidChangeTextDocument>(not) {
            Ok(params) => {
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

                self.db.set_source(id.clone(), Arc::new(source));
                self.files.insert(id);
                // FIXME(bbannier): implement gc of old versions.

                return;
            }
            Err(not) => not,
        };
        // TODO(bbannier): trigger diagnostics run with `zeek --parse-only` on `didSave`.
    }

    #[instrument]
    fn hover(&self, id: RequestId, params: &HoverParams) -> Result<()> {
        let params = &params.text_document_position_params;

        let doc_id = match self.get_file(&params.text_document) {
            Some(id) => id,
            None => {
                return send_response(
                    &self.connection.sender,
                    Response::new_err(id, 0, "unknown file".to_string()),
                );
            }
        };

        // TODO(bbannier): This is more of a demo and debugging tool for now. Eventually this
        // should return some nice rendering of the hovered node.

        let tree = self.db.parse(doc_id);
        let tree = match tree.as_ref() {
            Some(t) => t,
            None => {
                return send_response(
                    &self.connection.sender,
                    Response::new_err(id, 0, "empty parse result".to_string()),
                );
            }
        };

        let node = match tree.named_descendant_for_position(&params.position) {
            Some(n) => n,
            None => {
                return send_response(
                    &self.connection.sender,
                    Response::new_err(id, 0, "no node at position".to_string()),
                )
            }
        };

        let hover = Hover {
            contents: HoverContents::Scalar(MarkedString::String(node.to_sexp())),
            range: Some(Range::new(
                Position::new(
                    u32::try_from(node.start_position().row)?,
                    u32::try_from(node.start_position().column)?,
                ),
                Position::new(
                    u32::try_from(node.end_position().row)?,
                    u32::try_from(node.end_position().column)?,
                ),
            )),
        };

        info!("{:?}", hover);
        send_response(&self.connection.sender, Response::new_ok(id, hover))
    }

    #[instrument]
    pub async fn run(&mut self) -> Result<()> {
        self.init()?;

        loop {
            tokio::select! {
                event = async { event(&self.connection.receiver)} => {
                    let event = event?;
                    match event {
                        Message::Request(req) => {
                            if self.connection.handle_shutdown(&req)? {
                                break;
                            }

                            self.handle_request(req)?;
                        }
                        Message::Notification(not) => {
                            self.handle_notification(not);
                        }
                        Message::Response(_)=>{}
                    }
                }
            }
        }

        Ok(())
    }
}

#[salsa::database(crate::parse::ParseStorage)]
#[derive(Default)]
pub struct Database {
    storage: salsa::Storage<Self>,
}

impl salsa::Database for Database {}
