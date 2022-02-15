#[cfg(feature = "telemetry")]
use {
    clap::Parser,
    tracing_subscriber::{layer::SubscriberExt, prelude::*},
};

#[cfg(feature = "profiling")]
use pyroscope::PyroscopeAgent;

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
    #[cfg(feature = "profiling")]
    let mut agent = PyroscopeAgent::builder("http://localhost:4040", "myapp").build()?;
    #[cfg(feature = "profiling")]
    agent.start();

    #[cfg(feature = "telemetry")]
    init_logging(&Args::parse())?;

    info!("starting Zeek language server");

    run().await;

    #[cfg(feature = "profiling")]
    agent.stop();

    Ok(())
}
