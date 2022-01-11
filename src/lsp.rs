use lsp_types::{TextDocumentSyncCapability, TextDocumentSyncKind};

use {
    crossbeam_channel::select,
    eyre::{eyre, Result},
    log::{debug, info},
    lsp_server::{Connection, IoThreads, Message, Notification, Request},
    lsp_types::InitializeParams,
    lsp_types::ServerCapabilities,
    std::fmt::Debug,
    tracing::instrument,
};

pub struct LanguageServer {
    initialize_params: Option<InitializeParams>,
    connection: Connection,
    _io_threads: IoThreads,
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

impl LanguageServer {
    #[instrument]
    fn init(&mut self) -> Result<()> {
        if self.initialize_params.is_some() {
            debug!("server already initialized");
            return Ok(());
        }

        let server_capabilities = ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)), // FIXME(bbannier): switch to incremental mode.
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
    fn handle_notification(&self, not: &Notification) -> Result<()> {
        info!("handling notification: {:?}", not);

        todo!();
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
                            self.handle_notification(&not)?;
                        }
                        Message::Response(_)=>{}
                    }
                }
            }
        }

        Ok(())
    }
}
