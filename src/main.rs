use {
    clap::Parser,
    eyre::Result,
    tracing::info,
    tracing_appender::non_blocking::WorkerGuard,
    tracing_subscriber::{layer::SubscriberExt, prelude::*},
    zeek_language_server::lsp::run,
};

#[cfg(feature = "telemetry")]
use {
    opentelemetry::KeyValue,
    opentelemetry_otlp::WithExportConfig,
    opentelemetry_sdk::{trace, Resource},
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
}

fn init_logging(args: &Args) -> Result<WorkerGuard> {
    let (writer, guard) = tracing_appender::non_blocking(std::io::stderr());

    let fmt = tracing_subscriber::fmt::layer()
        .with_writer(writer.with_max_level(args.filter))
        .with_ansi(false)
        .with_target(false)
        .with_file(true);

    {
        let registry = tracing_subscriber::registry().with(fmt);

        #[cfg(feature = "telemetry")]
        let registry = registry.with(
            tracing_opentelemetry::layer().with_tracer(
                opentelemetry_otlp::new_pipeline()
                    .tracing()
                    .with_exporter(
                        opentelemetry_otlp::new_exporter()
                            .tonic()
                            .with_endpoint(&args.collector_endpoint),
                    )
                    .with_trace_config(trace::config().with_resource(Resource::new(vec![
                        KeyValue::new("service.name", env!("CARGO_BIN_NAME")),
                    ])))
                    .install_batch(opentelemetry_sdk::runtime::Tokio)?,
            ),
        );

        registry.init();
    }

    Ok(guard)
}

#[tokio::main]
async fn main() -> Result<()> {
    #[allow(unused)]
    let args = Args::parse();

    let _guard = init_logging(&args)?;

    info!("starting Zeek language server");

    run().await;

    Ok(())
}
