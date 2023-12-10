use clap::Parser;

use {
    eyre::Result,
    tracing::info,
    tracing_appender::non_blocking::WorkerGuard,
    tracing_subscriber::{layer::SubscriberExt, prelude::*},
    zeek_language_server::lsp::run,
};

#[derive(Parser, Debug)]
#[clap(about, version)]
struct Args {
    /// Jaeger endpoint collecting tracing spans in jaeger.thrift format.
    #[cfg(feature = "telemetry")]
    #[clap(short, long, default_value = "http://127.0.0.1:14268/api/traces")]
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
        let tracer = opentelemetry_jaeger::new_collector_pipeline()
            .with_endpoint(&args.collector_endpoint)
            .with_service_name(env!("CARGO_BIN_NAME"))
            .with_reqwest()
            .install_batch(opentelemetry::runtime::Tokio)?;

        #[cfg(feature = "telemetry")]
        let registry = registry.with(tracing_opentelemetry::layer().with_tracer(tracer));

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
