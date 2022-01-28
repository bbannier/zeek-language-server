use crate::{
    parse::Parse,
    query::{self, Decl, DeclKind, Query},
    to_range, zeek, Files,
};
use itertools::Itertools;
use log::{error, warn};
use lspower::{
    jsonrpc::{Error, ErrorCode, Result},
    lsp::{
        CompletionItem, CompletionItemKind, CompletionOptions, CompletionParams,
        CompletionResponse, DidChangeTextDocumentParams, DidChangeWatchedFilesParams,
        DidOpenTextDocumentParams, DocumentSymbol, DocumentSymbolParams, DocumentSymbolResponse,
        Documentation, FileChangeType, FileEvent, Hover, HoverContents, HoverParams,
        HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams,
        LanguageString, Location, MarkedString, MessageType, OneOf, Position, Range,
        ServerCapabilities, SymbolInformation, SymbolKind, TextDocumentSyncCapability,
        TextDocumentSyncKind, Url, WorkspaceSymbolParams,
    },
    Client, LanguageServer, LspService, Server,
};
use std::{
    collections::{BTreeSet, HashSet},
    fmt::Debug,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use tracing::instrument;

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
pub trait ServerState: Files + Parse + Query {
    #[salsa::input]
    fn prefixes(&self) -> Arc<Vec<PathBuf>>;

    #[salsa::input]
    fn files(&self) -> Arc<BTreeSet<Arc<Url>>>;

    #[must_use]
    fn loaded_files(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;

    #[must_use]
    fn loaded_files_recursive(&self, url: Arc<Url>) -> Arc<Vec<Arc<Url>>>;

    #[must_use]
    fn loaded_decls(&self, url: Arc<Url>) -> Arc<Vec<Decl>>;

    #[must_use]
    fn implicit_decls(&self) -> Arc<Vec<Decl>>;
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
        let f = file_dir.iter().chain(prefixes.iter()).find_map(|prefix| {
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
        });

        if let Some(f) = f {
            loaded_files.push(f);
        }
    }

    Arc::new(loaded_files)
}

#[instrument(skip(db))]
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

#[instrument(skip(db))]
fn loaded_decls(db: &dyn ServerState, url: Arc<Url>) -> Arc<Vec<Decl>> {
    let mut decls = Vec::new();

    for load in db.loaded_files_recursive(url).as_ref() {
        for decl in db.decls(load.clone()).iter() {
            decls.push(decl.clone());
        }
    }

    Arc::new(decls)
}

#[instrument(skip(db))]
fn implicit_decls(db: &dyn ServerState) -> Arc<Vec<Decl>> {
    let implicit_load = zeek::init_script_filename();

    let mut implicit_file = None;
    // This loop looks horrible, but is okay since this function will be cached most of the time
    // (unless global state changes).
    for f in db.files().iter() {
        let path = match f.to_file_path() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if !path.ends_with(&implicit_load) {
            continue;
        }

        for p in db.prefixes().iter() {
            if path.strip_prefix(p).is_ok() {
                implicit_file = Some(f.clone());
                break;
            }
        }
    }

    let implicit_load = match implicit_file {
        Some(f) => f,
        None => return Arc::new(Vec::new()), // TODO(bbannier): this could also be an error.
    };

    db.loaded_decls(implicit_load)
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

    fn state(&self) -> Result<MutexGuard<Database>> {
        self.state
            .lock()
            .map_err(|_| Error::new(ErrorCode::InternalError))
    }
}

#[lspower::async_trait]
impl LanguageServer for Backend {
    #[instrument]
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        if let Ok(mut state) = self.state() {
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

        if let Ok(mut state) = self.state() {
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
        let files = params.changes.into_iter().filter_map(|c| match c.typ {
            FileChangeType::CREATED => Some(c.uri),
            _ => None,
        });

        let _progress = files
            .map(|uri| {
                let source = match std::fs::read_to_string(uri.path()) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("failed to read '{}': {}", &uri, e);
                        return None;
                    }
                };

                if let Ok(mut state) = self.state() {
                    let uri = Arc::new(uri);

                    state.set_source(uri.clone(), Arc::new(source));

                    let mut files = state.files();
                    let files = Arc::make_mut(&mut files);
                    files.insert(uri);
                    state.set_files(Arc::new(files.clone()));
                };

                Some(())
            })
            .collect::<Vec<_>>();
    }

    #[instrument]
    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let source = params.text_document.text;

        if let Ok(mut state) = self.state() {
            let uri = Arc::new(uri);

            state.set_source(uri.clone(), Arc::new(source));

            let mut files = state.files();
            let files = Arc::make_mut(&mut files);
            files.insert(uri);
            state.set_files(Arc::new(files.clone()));
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

        if let Ok(mut state) = self.state() {
            let uri = Arc::new(uri);
            state.set_source(uri, Arc::new(source));
        }
    }

    #[instrument]
    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let params = &params.text_document_position_params;

        let uri = Arc::new(params.text_document.uri.clone());

        let state = self.state()?;

        // TODO(bbannier): This is more of a demo and debugging tool for now. Eventually this
        // should return some nice rendering of the hovered node.

        let source = state.source(uri.clone());

        let tree = state.parse(uri.clone());
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
            if let Some(decl) = query::decl_at(id, node, uri, &source) {
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
        let state = self.state()?;

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

        let state = self.state()?;

        let source = state.source(uri.clone());

        let tree = match state.parse(uri.clone()) {
            Some(t) => t,
            None => return Ok(None),
        };

        let node = match tree.descendant_for_position(&position.position) {
            Some(n) => n,
            None => return Ok(None),
        };

        let text_at_completion = node
            .utf8_text(source.as_bytes())
            // This shouldn't happen; if we cannot get the node text there is some UTF-8 error.
            .map_err(|_| Error::new(ErrorCode::InternalError))?
            .lines()
            .next()
            .map(str::trim)
            .map(|t| {
                eprintln!("completing {} with text: {}", node.kind(), t);
                t
            });

        let items: Vec<_> = {
            let mut items = HashSet::new();
            let mut node = node;

            loop {
                for d in query::decls_(node, uri.clone(), &source) {
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
                        rust_fuzzy_search::fuzzy_compare(
                            &text.to_lowercase(),
                            &i.fqid.to_lowercase(),
                        ) > 0.0
                    } else {
                        true
                    }
                });

            items
                .iter()
                .chain(other_decls)
                .filter(|d| d.kind != DeclKind::Event)
                .unique()
                .map(to_completion_item)
                .collect()
        };

        Ok(Some(CompletionResponse::from(items)))
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

fn to_symbol_kind(kind: DeclKind) -> SymbolKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef => SymbolKind::VARIABLE,
        DeclKind::Option => SymbolKind::PROPERTY,
        DeclKind::Const => SymbolKind::CONSTANT,
        DeclKind::RedefEnum => SymbolKind::ENUM,
        DeclKind::RedefRecord => SymbolKind::INTERFACE,
        DeclKind::Type => SymbolKind::CLASS,
        DeclKind::Func => SymbolKind::FUNCTION,
        DeclKind::Hook => SymbolKind::OPERATOR,
        DeclKind::Event => SymbolKind::EVENT,
    }
}

fn to_completion_item(d: &Decl) -> CompletionItem {
    CompletionItem {
        label: d.fqid.clone(),
        kind: Some(to_completion_item_kind(d.kind)),
        documentation: Some(Documentation::String(d.documentation.clone())),
        ..CompletionItem::default()
    }
}

fn to_completion_item_kind(kind: DeclKind) -> CompletionItemKind {
    match kind {
        DeclKind::Global | DeclKind::Variable | DeclKind::Redef => CompletionItemKind::VARIABLE,
        DeclKind::Option => CompletionItemKind::PROPERTY,
        DeclKind::Const => CompletionItemKind::CONSTANT,
        DeclKind::RedefEnum => CompletionItemKind::ENUM,
        DeclKind::RedefRecord => CompletionItemKind::INTERFACE,
        DeclKind::Type => CompletionItemKind::CLASS,
        DeclKind::Func => CompletionItemKind::FUNCTION,
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
mod test {
    use std::{
        collections::BTreeSet,
        path::PathBuf,
        str::FromStr,
        sync::{Arc, Mutex},
    };

    use insta::assert_debug_snapshot;
    use lspower::{
        lsp::{
            CompletionParams, PartialResultParams, Position, TextDocumentIdentifier,
            TextDocumentPositionParams, Url, WorkDoneProgressParams, WorkspaceSymbolParams,
        },
        LanguageServer,
    };

    use crate::{lsp, Files};

    use super::{Backend, ServerState};

    struct TestDatabase(lsp::Database);

    impl TestDatabase {
        fn new() -> Self {
            let mut db = lsp::Database::default();
            db.set_files(Arc::new(BTreeSet::new()));
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

        fn add_prefix<P>(&mut self, prefix: P)
        where
            P: Into<PathBuf>,
        {
            let mut prefixes = self.0.prefixes();
            let prefixes = Arc::make_mut(&mut prefixes);
            prefixes.push(prefix.into());
            self.0.set_prefixes(Arc::new(prefixes.clone()));
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
            "@load foo\n
             @load foo.zeek\n
             @load p1/p1\n
             @load p2/p2",
        );

        assert_debug_snapshot!(db.0.loaded_files(foo));
    }

    #[test]
    fn loaded_files_recursive() {
        let mut db = TestDatabase::new();

        let a = Arc::new(Url::from_file_path("/tmp/a.zeek").unwrap());
        db.add_file(
            a.clone(),
            "@load b\n
             @load d;",
        );

        let b = Arc::new(Url::from_file_path("/tmp/b.zeek").unwrap());
        db.add_file(b.clone(), "@load c");

        let c = Arc::new(Url::from_file_path("/tmp/c.zeek").unwrap());
        db.add_file(c.clone(), "@load d");

        let d = Arc::new(Url::from_file_path("/tmp/d.zeek").unwrap());
        db.add_file(d.clone(), "");

        assert_debug_snapshot!(db.0.loaded_files_recursive(a));
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
}
