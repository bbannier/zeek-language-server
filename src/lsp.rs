use {
    crate::{parse::Parse, ID},
    crossbeam_channel::select,
    eyre::{eyre, Result},
    log::{debug, info},
    lsp_server::{Connection, IoThreads, Message, Notification, Request},
    lsp_types::{
        notification, InitializeParams, ServerCapabilities, TextDocumentSyncCapability,
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

mod cast {
    use {
        lsp_server::{Notification, Request, RequestId},
        lsp_types::{notification, request},
    };

    pub fn _request<R>(req: Request) -> std::result::Result<(RequestId, R::Params), Request>
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
            ..ServerCapabilities::default()
        };

        let initialize_params = self
            .connection
            .initialize(serde_json::to_value(server_capabilities)?)?;

        self.initialize_params = serde_json::from_value(initialize_params)?;

        debug!("server initialized: {:?}", &self.initialize_params);

        Ok(())
    }

    #[instrument]
    fn handle_request(&self, req: &Request) -> Result<()> {
        info!("handling request: {:?}", req);

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

                            self.handle_request(&req)?;
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
