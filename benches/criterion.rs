use criterion::{criterion_group, criterion_main, Criterion};

mod server {
    use tower_lsp::{
        lsp_types::{DidChangeWatchedFilesParams, FileChangeType, FileEvent, InitializeParams},
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
}

mod zeek {
    use zeek_language_server::zeek;

    pub async fn system_files() {
        zeek::system_files().await.unwrap();
    }

    pub async fn prefixes() {
        zeek::prefixes(None).await.unwrap();
    }
}

fn bench(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("server::initial_index", |b| {
        b.to_async(&runtime).iter(|| server::initial_index());
    });

    c.bench_function("server::visible_files", |b| {
        b.to_async(&runtime).iter(|| server::visible_files())
    });

    c.bench_function("zeek::system_files", |b| {
        b.to_async(&runtime).iter(|| zeek::system_files());
    });

    c.bench_function("zeek::prefixes", |b| {
        b.to_async(&runtime).iter(|| zeek::prefixes());
    });
}

criterion_group!(benches, bench);

criterion_main!(benches);
