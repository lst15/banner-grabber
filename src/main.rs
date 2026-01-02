#[cfg(feature = "cli")]
use banner_grabber::cli::Cli;
#[cfg(feature = "cli")]
use banner_grabber::core::engine::Engine;
#[cfg(feature = "cli")]
use banner_grabber::core::output::OutputChannel;
#[cfg(feature = "cli")]
use clap::Parser;
#[cfg(feature = "cli")]
use tracing_subscriber::EnvFilter;

#[cfg(feature = "cli")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();
    let cfg = cli.into_config()?;

    let sink = OutputChannel::new(cfg.output.clone())?;
    let mut engine = Engine::new(cfg, sink)?;
    engine.run().await?;

    Ok(())
}

#[cfg(not(feature = "cli"))]
fn main() {
    eprintln!("CLI support is disabled. Enable the `cli` feature to build the binary.");
}
