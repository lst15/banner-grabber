mod cli;
mod engine;
mod input;
mod model;
mod output;
mod probe;
mod util;

use clap::Parser;
use cli::Cli;
use engine::Engine;
use output::OutputSink;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();
    let cfg = cli.into_config()?;

    let sink = OutputSink::new(cfg.output.clone())?;
    let mut engine = Engine::new(cfg, sink)?;
    engine.run().await?;

    Ok(())
}
