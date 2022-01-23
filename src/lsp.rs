use {
    crate::{
        parse::Parse,
        query::{self, Decl, DeclKind, Query},
        to_range, zeek, Files,
    },
    itertools::Itertools,
    log::{error, warn},
    std::{
        collections::HashSet,
        fmt::Debug,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    },
    tower_lsp::{
        jsonrpc::{Error, ErrorCode, Result},
        lsp_types::{
            CompletionItem, CompletionItemKind, CompletionOptions, CompletionParams,
            CompletionResponse, CreateFilesParams, DidChangeTextDocumentParams,
            DidOpenTextDocumentParams, DocumentSymbol, DocumentSymbolParams,
            DocumentSymbolResponse, Documentation, FileCreate, Hover, HoverContents, HoverParams,
            HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams,
            LanguageString, Location, MarkedString, MessageType, OneOf, Position, Range,
            ServerCapabilities, SymbolInformation, SymbolKind, TextDocumentSyncCapability,
            TextDocumentSyncKind, Url, WorkspaceSymbolParams,
        },
        Client, LanguageServer, LspService, Server,
    },
    tracing::instrument,
};

#[salsa::database(
    crate::parse::ParseStorage,
    crate::query::QueryStorage,
    ServerStateStorage,
    crate::FilesStorage
)]
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

#[salsa::query_group(ServerStateStorage)]
pub trait ServerState: Parse + Files {
    #[salsa::input]
    fn prefixes(&self) -> Arc<Vec<PathBuf>>;

    #[salsa::input]
    fn files(&self) -> Arc<HashSet<Arc<Url>>>;

    #[must_use]
    fn loaded_files(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;

    #[must_use]
    fn loaded_files_recursive(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;
}

fn loaded_files(db: &dyn ServerState, uri: Arc<Url>) -> Arc<Vec<Arc<Url>>> {
    let file_dir = uri
        .to_file_path()
        .ok()
        .and_then(|f| f.parent().map(Path::to_path_buf));

    let files = db.files();

    let prefixes = db.prefixes();

    let loads: Vec<_> = db.loads(uri).iter().map(PathBuf::from).collect();

    let mut loaded_files = Vec::new();

    for load in &loads {
        let f = file_dir
            .iter()
            .chain(prefixes.iter())
            .map(|prefix| {
                // Files in the given prefix.
                let files: Vec<_> = files
                    .iter()
                    .filter_map(|f| {
                        if let Ok(p) = f.to_file_path().ok()?.strip_prefix(prefix) {
                            Some((f, p.to_path_buf()))
                        } else {
                            None
                        }
                    })
                    .collect();

                // File known w/ extension.
                let known_exactly = files.iter().find(|(_, p)| p.ends_with(load));

                // File known w/o extension.
                let known_no_ext = files
                    .iter()
                    .find(|(_, p)| p.ends_with(load.with_extension("zeek")));

                // Load is directory with `__load__.zeek`.
                let known_directory = files
                    .iter()
                    .find(|(_, p)| p.ends_with(load.join("__load__.zeek")));

                known_exactly
                    .or(known_no_ext)
                    .or(known_directory)
                    .map(|(f, _)| (*f).clone())
            })
            .flatten()
            .next();

        if let Some(f) = f {
            loaded_files.push(f);
        }
    }

    Arc::new(loaded_files)
}

fn loaded_files_recursive(db: &dyn ServerState, url: Arc<Url>) -> Arc<Vec<Arc<Url>>> {
    let mut files = db.loaded_files(url).as_ref().clone();

    loop {
        let mut new_files = Vec::new();

        for f in &files {
            for load in db.loaded_files(f.clone()).as_ref() {
                if !files.iter().any(|f| f.as_ref() == load.as_ref()) {
                    new_files.push(load.clone());
                }
            }
        }

        if new_files.is_empty() {
            break;
        }

        for n in new_files {
            files.push(n);
        }
    }

    Arc::new(files)
}

#[derive(Debug, Default)]
struct State {
    db: Database,
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
        if let Ok(prefixes) = zeek::prefixes().await {
            if let Ok(mut state) = self.state.lock() {
                // Set up prefixes for normalization of system files.
                state.db.set_prefixes(Arc::new(prefixes));

                state.db.set_files(Arc::new(HashSet::new()));
            }
        }

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

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::Full,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                workspace_symbol_provider: Some(OneOf::Left(true)),
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
        self.client
            .log_message(MessageType::Info, "server initialized!")
            .await;
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

                let source = match std::fs::read_to_string(&f.uri) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("failed to read '{}': {}", &f.uri, e);
                        return None;
                    }
                };

                if let Ok(mut state) = self.state.lock() {
                    let uri = Arc::new(uri);

                    state.db.set_source(uri.clone(), Arc::new(source));

                    let mut files = state.db.files();
                    let files = Arc::make_mut(&mut files);
                    files.insert(uri);
                    state.db.set_files(Arc::new(files.clone()));
                };

                Some(())
            })
            .collect::<Vec<_>>();
    }

    #[instrument]
    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let source = params.text_document.text;

        if let Ok(mut state) = self.state.lock() {
            let uri = Arc::new(uri);

            state.db.set_source(uri.clone(), Arc::new(source));

            let mut files = state.db.files();
            let files = Arc::make_mut(&mut files);
            files.insert(uri);
            state.db.set_files(Arc::new(files.clone()));
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

        let uri = params.text_document.uri;

        let source = changes.text.to_string();

        if let Ok(mut state) = self.state.lock() {
            let uri = Arc::new(uri);
            state.db.set_source(uri.clone(), Arc::new(source));

            let mut files = state.db.files();
            let files = Arc::make_mut(&mut files);
            files.insert(uri);
            state.db.set_files(Arc::new(files.clone()));
        }
    }

    #[instrument]
    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let params = &params.text_document_position_params;

        let uri = Arc::new(params.text_document.uri.clone());

        let state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorCode::InternalError))?;

        // TODO(bbannier): This is more of a demo and debugging tool for now. Eventually this
        // should return some nice rendering of the hovered node.

        let source = state.db.source(uri.clone());

        let tree = state.db.parse(uri);
        let tree = match tree.as_ref() {
            Some(t) => t,
            None => return Ok(None),
        };

        let node = match tree.named_descendant_for_position(&params.position) {
            Some(n) => n,
            None => return Ok(None),
        };

        let text = node.utf8_text(source.as_bytes()).map_err(|e| {
            error!("could not get source text: {}", e);
            Error::new(ErrorCode::InternalError)
        })?;

        let mut contents = vec![
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

        if node.kind() == "id" {
            let id = text;
            if let Some(decl) = query::decl_at(id, node, &source) {
                contents.push(MarkedString::String(decl.documentation));
            }
        }

        let hover = Hover {
            contents: HoverContents::Array(contents),
            range: to_range(node.range()).ok(),
        };

        Ok(Some(hover))
    }

    #[instrument]
    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorCode::InternalError))?;

        let uri = Arc::new(params.text_document.uri);

        let symbol = |d: &Decl| -> DocumentSymbol {
            #[allow(deprecated)]
            DocumentSymbol {
                name: d.id.clone(),
                range: d.range,
                selection_range: d.selection_range,
                kind: to_symbol_kind(d.kind),
                deprecated: None,
                detail: None,
                tags: None,
                children: None,
            }
        };

        let modules = state
            .db
            .decls(uri)
            .iter()
            .group_by(|d| &d.module)
            .into_iter()
            .map(|(m, decls)| {
                #[allow(deprecated)]
                DocumentSymbol {
                    name: format!("{}", m),
                    kind: SymbolKind::Module,
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
    async fn symbol(&self, _: WorkspaceSymbolParams) -> Result<Option<Vec<SymbolInformation>>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorCode::InternalError))?;

        let files = state.db.files();
        let symbols = files.iter().flat_map(|uri| {
            state
                .db
                .decls(uri.clone())
                .iter()
                .map(|d| {
                    let url: &Url = &**uri;

                    #[allow(deprecated)]
                    SymbolInformation {
                        name: format!("{}::{}", &d.module, &d.id),
                        kind: to_symbol_kind(d.kind),

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

        let state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorCode::InternalError))?;

        let source = state.db.source(uri.clone());

        let tree = match state.db.parse(uri.clone()) {
            Some(t) => t,
            None => return Ok(None),
        };

        let node = match tree.descendant_for_position(&position.position) {
            Some(n) => n,
            None => return Ok(None),
        };

        let items: Vec<_> = {
            let mut items = HashSet::new();
            let mut node = node;
            loop {
                for d in query::decls_(node, &source) {
                    items.insert(d);
                }

                node = match node.parent() {
                    Some(n) => n,
                    None => break,
                };
            }

            items.into_iter().map(to_completion_item).collect()
        };

        // TODO: Add an decls found in implicitly or explicitly loaded modules.

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

fn to_completion_item(d: Decl) -> CompletionItem {
    CompletionItem {
        label: format!("{}::{}", d.module, d.id),
        kind: Some(to_completion_item_kind(d.kind)),
        documentation: Some(Documentation::String(d.documentation)),
        ..CompletionItem::default()
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

#[cfg(test)]
mod test {
    use std::{collections::HashSet, path::PathBuf, str::FromStr, sync::Arc};

    use insta::assert_debug_snapshot;
    use tower_lsp::lsp_types::Url;

    use crate::{lsp, Files};

    use super::ServerState;

    struct TestDatabase(lsp::Database);

    impl TestDatabase {
        fn new() -> Self {
            let mut db = lsp::Database::default();
            db.set_files(Arc::new(HashSet::new()));
            db.set_prefixes(Arc::new(Vec::new()));

            Self(db)
        }

        fn add_file(&mut self, uri: Arc<Url>, source: &str) {
            self.0.set_source(uri.clone(), Arc::new(source.to_string()));

            let mut files = self.0.files();
            let files = Arc::make_mut(&mut files);
            files.insert(uri);
            self.0.set_files(Arc::new(files.clone()));
        }

        fn add_prefix(&mut self, prefix: PathBuf) {
            let mut prefixes = self.0.prefixes();
            let prefixes = Arc::make_mut(&mut prefixes);
            prefixes.push(prefix);
            self.0.set_prefixes(Arc::new(prefixes.clone()));
        }
    }

    #[test]
    fn loaded_files() {
        let mut db = TestDatabase::new();

        // Prefix file both in file directory and in prefix. This should appear exactly once.
        let pre1 = PathBuf::from_str("/tmp/p").unwrap();
        let p1 = Arc::new(Url::from_file_path(pre1.join("p1/p1.zeek")).unwrap());
        db.add_prefix(pre1);
        db.add_file(p1.clone(), "");

        // Prefix file in external directory.
        let pre2 = PathBuf::from_str("/p").unwrap();
        let p2 = Arc::new(Url::from_file_path(pre2.join("p2/p2.zeek")).unwrap());
        db.add_prefix(pre2);
        db.add_file(p2.clone(), "");

        let foo = Arc::new(Url::from_file_path("/tmp/foo.zeek").unwrap());
        db.add_file(
            foo.clone(),
            "@load foo;
             @load foo.zeek;
             @load p1/p1;
             @load p2/p2;",
        );

        assert_debug_snapshot!(db.0.loaded_files(foo));
    }

    #[test]
    fn loaded_files_recursive() {
        let mut db = TestDatabase::new();

        let a = Arc::new(Url::from_file_path("/tmp/a.zeek").unwrap());
        db.add_file(a.clone(), "@load b; @load d;");

        let b = Arc::new(Url::from_file_path("/tmp/b.zeek").unwrap());
        db.add_file(b.clone(), "@load c;");

        let c = Arc::new(Url::from_file_path("/tmp/c.zeek").unwrap());
        db.add_file(c.clone(), "@load d;");

        let d = Arc::new(Url::from_file_path("/tmp/d.zeek").unwrap());
        db.add_file(d.clone(), "");

        assert_debug_snapshot!(db.0.loaded_files_recursive(a));
    }
}
