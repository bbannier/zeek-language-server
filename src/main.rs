#[cfg(feature = "telemetry")]
use {
    clap::Parser,
    tracing_subscriber::{layer::SubscriberExt, prelude::*},
};

use {eyre::Result, tracing::info, zeek_language_server::lsp::run};

#[cfg(feature = "telemetry")]
#[derive(Parser, Debug)]
#[clap(about, version)]
struct Args {
    #[clap(short, long, default_value = "http://127.0.0.1:14268/api/traces")]
    collector_endpoint: String,
}

#[cfg(feature = "telemetry")]
fn init_logging(args: &Args) -> Result<()> {
    let tracer = opentelemetry_jaeger::new_pipeline()
        .with_collector_endpoint(&args.collector_endpoint)
        .with_service_name(env!("CARGO_BIN_NAME"))
        .install_batch(opentelemetry::runtime::Tokio)?;

    tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "telemetry")]
    init_logging(&Args::parse())?;

    info!("starting Zeek language server");

    run().await;

    Ok(())
}
