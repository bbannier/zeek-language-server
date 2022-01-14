use {
    clap::Parser,
    clap_verbosity_flag::Verbosity,
    eyre::{eyre, Result},
    std::path::PathBuf,
    tracing::info,
    tracing_log::LogTracer,
    tracing_subscriber::{layer::SubscriberExt, Registry},
    zeek_lsp::lsp::run,
};

#[derive(Parser, Debug)]
#[clap(about, version)]
struct Args {
    #[clap(short, long, default_value = "/tmp")]
    log_directory: PathBuf,

    #[clap(flatten)]
    verbose: Verbosity,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Args::parse();

    let log_file =
        tracing_appender::rolling::never(&opts.log_directory, "zeek-language-server.log");
    let (log_writer, _guard) = tracing_appender::non_blocking(log_file);

    LogTracer::init_with_filter(
        opts.verbose
            .log_level()
            .ok_or_else(|| eyre!("invalid logging level"))?
            .to_level_filter(),
    )?;

    tracing::subscriber::set_global_default(
        Registry::default().with(tracing_subscriber::fmt::layer().with_writer(log_writer)),
    )?;

    info!("starting Zeek language server");

    run().await;

    Ok(())
}
