use {
    crate::{
        parse::{query_to, Parse},
        ID,
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
            DidChangeTextDocumentParams, DidOpenTextDocumentParams, DocumentSymbol,
            DocumentSymbolParams, DocumentSymbolResponse, Hover, HoverContents, HoverParams,
            HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams,
            MarkedString, MessageType, OneOf, Position, Range, ServerCapabilities, SymbolKind,
            TextDocumentIdentifier, TextDocumentSyncCapability, TextDocumentSyncKind,
            VersionedTextDocumentIdentifier,
        },
        Client, LanguageServer, LspService, Server,
    },
    tracing::instrument,
    tree_sitter::QueryCapture,
};

fn to_offset(x: usize) -> Result<u32> {
    u32::try_from(x).map_err(|_| Error::new(ErrorCode::InternalError))
}

fn to_position(p: tree_sitter::Point) -> Result<Position> {
    Ok(Position::new(to_offset(p.row)?, to_offset(p.column)?))
}

fn to_range(r: tree_sitter::Range) -> Result<Range> {
    Ok(Range::new(
        to_position(r.start_point)?,
        to_position(r.end_point)?,
    ))
}

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

        let document = |c: &QueryCapture| {
            let node = c.node;

            let kind = match node.kind() {
                "module_decl" => SymbolKind::Module,
                "const_decl" => SymbolKind::Constant,
                "global_decl" | "redef_decl" => SymbolKind::Variable,
                "redef_enum_decl" => SymbolKind::Enum,
                "redef_record_decl" => SymbolKind::Interface,
                "option_decl" => SymbolKind::Property,
                "type_decl" => SymbolKind::Class,
                "event_decl" => SymbolKind::Event,
                "func_decl" | "hook_decl" => SymbolKind::Function,
                "export_decl" | "preproc" => {
                    // These nodes are no interesting decls.
                    return None;
                }
                _ => {
                    warn!("unsupported node kind {}", node.kind());
                    return None;
                }
            };

            let detail = None;
            let tags = None;
            let deprecated = None;
            let children = None;

            let range = to_range(node.range()).ok()?;

            // Concrete decls always have an explicit `id`. Since we
            // return early for other nodes above this always succeeds.
            let id = node.child_by_field_name("id")?;

            let selection_range = to_range(id.range()).ok()?;
            let name = id.utf8_text(source.as_bytes()).ok()?.into();

            #[allow(deprecated)]
            Some(DocumentSymbol {
                name,
                detail,
                kind,
                tags,
                deprecated,
                range,
                selection_range,
                children,
            })
        };

        // The module node.
        let module = query_to(
            tree.root_node(),
            &source,
            "(decl (module_decl (id))@d)",
            document,
        )
        .into_iter()
        // Add a generated module symbol so we always have one, even if the user did not write an
        // explicit module_decl.
        .chain(std::iter::once({
            let range =
                to_range(tree.root_node().range()).expect("source file should have some range");

            let name = params
                .text_document
                .uri
                // Assume that text documents refer to file paths.
                .path_segments()
                // The last path component would be the file name.
                .and_then(Iterator::last)
                // Assume that implicit module names only exist for files name like `mod.zeek`, and
                // e.g., multiple `.` are not allowed.
                .and_then(|s| s.split('.').next())
                // If we still cannot extract a name at least provide _something_.
                .unwrap_or("<invalid>")
                .into();

            #[allow(deprecated)]
            DocumentSymbol {
                name,
                kind: SymbolKind::Module,

                children: None,
                detail: None,
                tags: None,
                deprecated: None,

                range,
                selection_range: range,
            }
        }))
        // Valid Zeek code should have at most one module_decl.
        .nth(0)
        .map(|m| {
            // All non-module nodes. This will execute at most once here.
            // FIXME(bbannier): This currently handles decls wrapped in preproc, test that.
            let children = query_to(tree.root_node(), &source, "(decl (_ (id))@d)", document)
                .into_iter()
                .filter(|s| s.kind != SymbolKind::Module)
                .map(|mut n| {
                    // Symbol names can be declared with a module prefix. Remove the prefix.
                    if let Some(name) = n.name.strip_prefix(&format!("{}::", m.name)) {
                        n.name = name.into();
                    }
                    n
                })
                .collect::<Vec<_>>();

            DocumentSymbol {
                children: Some(children),
                ..m
            }
        })
        .expect("module information should always be generated");

        Ok(Some(DocumentSymbolResponse::from(vec![module])))
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
