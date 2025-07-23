use criterion::criterion_main;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        // By default tokio creates too many worker threads for
        // running under valgrind in Codspeed, limit them.
        .max_blocking_threads(64)
        .enable_io()
        .build()
        .expect("could not build runtime")
}

mod server {
    use criterion::{Criterion, criterion_group};
    use tower_lsp_server::{
        LanguageServer, UriExt,
        lsp_types::{
            CompletionContext, CompletionParams, CompletionTriggerKind,
            DidChangeWatchedFilesParams, DidOpenTextDocumentParams, FileChangeType, FileEvent,
            InitializeParams, InitializedParams, PartialResultParams, Position, ReferenceContext,
            ReferenceParams, TextDocumentIdentifier, TextDocumentItem, TextDocumentPositionParams,
            Uri, WorkDoneProgressParams,
        },
    };
    use zeek_language_server::lsp::Backend;

    pub async fn initial_index() {
        let db = Backend::default();
        let _ = db.initialize(InitializeParams::default()).await;
        // NOTE: Do not call `initialized` as that triggers preloading.
        // db.initialized(InitializedParams {}).await;

        db.did_change_watched_files(DidChangeWatchedFilesParams {
            changes: db
                .visible_files()
                .await
                .unwrap()
                .into_iter()
                .map(|f| FileEvent::new(f, FileChangeType::CREATED))
                .collect(),
        })
        .await;
    }

    pub async fn visible_files() {
        let db = Backend::default();
        let _ = db.initialize(InitializeParams::default()).await;

        db.visible_files().await.unwrap();
    }

    fn bench_completion(c: &mut Criterion) {
        pub async fn completion(db: &Backend, uri: Uri) {
            let _ = db
                .completion(CompletionParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri),
                        Position::new(0, 2),
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: Some(CompletionContext {
                        trigger_kind: CompletionTriggerKind::INVOKED,
                        trigger_character: None,
                    }),
                })
                .await;
        }

        let runtime = super::runtime();

        let (db, uri) = runtime.block_on(async {
            let db = Backend::default();
            let _ = db.initialize(InitializeParams::default()).await;

            // This triggers indexing.
            db.initialized(InitializedParams {}).await;

            let uri = Uri::from_file_path("/x.zeek").unwrap();

            db.did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem::new(
                    uri.clone(),
                    "zeek".to_string(),
                    0,
                    "mk".to_string(),
                ),
            })
            .await;

            (db, uri)
        });

        c.bench_function("server::completion", |b| {
            b.to_async(&runtime).iter(|| completion(&db, uri.clone()));
        });
    }

    fn bench_reference(c: &mut Criterion) {
        let runtime = super::runtime();

        let (db, uri) = runtime.block_on(async {
            let db = Backend::default();
            let _ = db.initialize(InitializeParams::default()).await;

            // This triggers indexing.
            db.initialized(InitializedParams {}).await;

            let uri = Uri::from_file_path("/x.zeek").unwrap();

            db.did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem::new(
                    uri.clone(),
                    "zeek".to_string(),
                    0,
                    r#"
module foo;
export {
const x = 123;
}
const y = x;
const z = x;
levenshtein_distance("", "");
"#
                    .to_string(),
                ),
            })
            .await;

            (db, uri)
        });

        // FIXME(bbannier): these benchmarks are somewhat pointless since we cannot invalidate the cache.

        c.bench_function("server::reference::levenshtein_distance", |b| {
            b.to_async(&runtime).iter(|| async {
                db.references(ReferenceParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(7, 0), // On `levenshtein_distance`.
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: ReferenceContext {
                        include_declaration: true,
                    },
                })
                .await
            });
        });

        c.bench_function("server::reference::unexported_var", |b| {
            b.to_async(&runtime).iter(|| async {
                db.references(ReferenceParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(6, 6), // On `z`.
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: ReferenceContext {
                        include_declaration: true,
                    },
                })
                .await
            });
        });

        c.bench_function("server::reference::exported_var", |b| {
            b.to_async(&runtime).iter(|| async {
                db.references(ReferenceParams {
                    text_document_position: TextDocumentPositionParams::new(
                        TextDocumentIdentifier::new(uri.clone()),
                        Position::new(3, 6), // On first `x`.
                    ),
                    work_done_progress_params: WorkDoneProgressParams::default(),
                    partial_result_params: PartialResultParams::default(),
                    context: ReferenceContext {
                        include_declaration: true,
                    },
                })
                .await
                .unwrap();
            });
        });
    }

    fn bench(c: &mut Criterion) {
        let runtime = super::runtime();

        c.bench_function("server::initial_index", |b| {
            b.to_async(&runtime).iter(initial_index);
        });

        c.bench_function("server::visible_files", |b| {
            b.to_async(&runtime).iter(visible_files);
        });
    }

    criterion_group!(server, bench, bench_completion, bench_reference);
}

mod zeek {
    use criterion::{Criterion, criterion_group};
    use zeek_language_server::zeek;

    async fn system_files() {
        let _: Vec<_> = zeek::system_files().await.unwrap().collect();
    }

    async fn prefixes() {
        let _: Vec<_> = zeek::prefixes(None).await.unwrap().collect();
    }

    pub fn bench(c: &mut Criterion) {
        let runtime = super::runtime();

        c.bench_function("zeek::system_files", |b| {
            b.to_async(&runtime).iter(system_files);
        });

        c.bench_function("zeek::prefixes", |b| {
            b.to_async(&runtime).iter(prefixes);
        });
    }
    criterion_group!(zeek, bench);
}

criterion_main!(server::server, zeek::zeek);
