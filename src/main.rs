use {
    clap::Parser,
    eyre::Result,
    std::path::PathBuf,
    tracing::info,
    tracing_appender::non_blocking::WorkerGuard,
    tracing_subscriber::{layer::SubscriberExt, prelude::*, util::SubscriberInitExt},
    zeek_language_server::lsp::run,
};

#[cfg(feature = "telemetry")]
use {
    opentelemetry::{KeyValue, trace::TracerProvider},
    opentelemetry_otlp::WithExportConfig,
    opentelemetry_sdk::Resource,
    opentelemetry_semantic_conventions::resource::SERVICE_NAME,
};

#[derive(Parser, Debug)]
#[clap(about, version)]
struct Args {
    /// OTLP gRPC collection endpoint.
    #[cfg(feature = "telemetry")]
    #[clap(short, long, default_value = "http://127.0.0.1:4317")]
    collector_endpoint: String,

    /// Minimal level of events to log.
    ///
    /// Valid levels are: trace, debug, info, warn, error.
    #[clap(short, long, value_enum, default_value = "error")]
    filter: tracing::Level,

    /// Emit a trace log to the given directory.
    #[clap(long)]
    trace: Option<PathBuf>,
}

#[allow(clippy::unnecessary_wraps)]
fn init_logging(args: &Args) -> Result<Vec<WorkerGuard>> {
    let mut guards = Vec::new();

    let (stderr_writer, stderr_guard) = tracing_appender::non_blocking(std::io::stderr());

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(stderr_writer.with_max_level(args.filter))
        .with_ansi(false)
        .with_target(false)
        .with_file(true);

    let registry = tracing_subscriber::registry().with(stderr_layer);
    guards.push(stderr_guard);

    let trace_file = env!("CARGO_PKG_NAME");

    let (trace_layer, trace_guard) = if let Some(trace_dir) = &args.trace {
        let (trace_writer, trace_guard) =
            tracing_appender::non_blocking(tracing_appender::rolling::never(trace_dir, trace_file));
        let trace_layer = tracing_subscriber::fmt::layer()
            .with_writer(trace_writer.with_max_level(tracing::Level::TRACE))
            .with_ansi(false)
            .with_target(false)
            .with_file(true);

        (Some(trace_layer), Some(trace_guard))
    } else {
        (None, None)
    };
    let registry = registry.with(trace_layer);
    guards.extend(trace_guard);

    #[cfg(feature = "telemetry")]
    let registry = registry.with({
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_resource(
                Resource::builder()
                    .with_attributes([KeyValue::new(SERVICE_NAME, env!("CARGO_BIN_NAME"))])
                    .build(),
            )
            .with_batch_exporter(
                opentelemetry_otlp::SpanExporter::builder()
                    .with_tonic()
                    .with_endpoint(&args.collector_endpoint)
                    .build()?,
            )
            .build();
        tracing_opentelemetry::layer().with_tracer(provider.tracer(""))
    });

    registry.init();

    Ok(guards)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let _guard = init_logging(&args)?;

    info!("starting Zeek language server");

    run().await;

    Ok(())
}
