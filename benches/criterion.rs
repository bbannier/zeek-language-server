use criterion::criterion_main;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .build()
        .expect("could not build runtime")
}

mod server {
    use criterion::{criterion_group, Criterion};
    use reqwest::Url;
    use serde_json::json;
    use tower_lsp::{
        lsp_types::{
            CompletionContext, CompletionParams, CompletionTriggerKind,
            DidChangeWatchedFilesParams, DidOpenTextDocumentParams, FileChangeType, FileEvent,
            InitializeParams, InitializedParams, PartialResultParams, Position,
            TextDocumentIdentifier, TextDocumentItem, TextDocumentPositionParams,
            WorkDoneProgressParams,
        },
        LanguageServer,
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
        pub async fn completion(db: &Backend, uri: Url) {
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
            let _ = db
                .initialize(InitializeParams {
                    initialization_options: Some(json!({"check_for_updates": false})),
                    ..InitializeParams::default()
                })
                .await;

            // This triggers indexing.
            db.initialized(InitializedParams {}).await;

            let uri = Url::from_file_path("/x.zeek").unwrap();

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
            b.to_async(&runtime).iter(|| completion(&db, uri.clone()))
        });
    }

    fn bench(c: &mut Criterion) {
        let runtime = super::runtime();

        c.bench_function("server::initial_index", |b| {
            b.to_async(&runtime).iter(|| initial_index());
        });

        c.bench_function("server::visible_files", |b| {
            b.to_async(&runtime).iter(|| visible_files())
        });
    }

    criterion_group!(server, bench, bench_completion);
}

mod zeek {
    use criterion::{criterion_group, Criterion};
    use zeek_language_server::zeek;

    async fn system_files() {
        zeek::system_files().await.unwrap();
    }

    async fn prefixes() {
        zeek::prefixes(None).await.unwrap();
    }

    pub fn bench(c: &mut Criterion) {
        let runtime = super::runtime();

        c.bench_function("zeek::system_files", |b| {
            b.to_async(&runtime).iter(|| system_files());
        });

        c.bench_function("zeek::prefixes", |b| {
            b.to_async(&runtime).iter(|| prefixes());
        });
    }
    criterion_group!(zeek, bench);
}

criterion_main!(server::server, zeek::zeek);
