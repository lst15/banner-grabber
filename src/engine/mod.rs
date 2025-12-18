pub mod pipeline;
pub mod rate;
pub mod reader;

use crate::model::Config;
use crate::output::OutputSink;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use pipeline::{DefaultProcessor, TargetProcessor};
use rate::RateLimiter;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::instrument;

pub struct Engine {
    cfg: std::sync::Arc<Config>,
    sink: OutputSink,
    limiter: RateLimiter,
    sem: std::sync::Arc<Semaphore>,
    processor: std::sync::Arc<dyn TargetProcessor>,
}

impl Engine {
    pub fn new(cfg: Config, sink: OutputSink) -> anyhow::Result<Self> {
        Self::with_processor(cfg, sink, std::sync::Arc::new(DefaultProcessor))
    }

    pub fn with_processor(
        cfg: Config,
        sink: OutputSink,
        processor: std::sync::Arc<dyn TargetProcessor>,
    ) -> anyhow::Result<Self> {
        let cfg = std::sync::Arc::new(cfg);
        Ok(Self {
            limiter: RateLimiter::new(cfg.rate),
            sem: std::sync::Arc::new(Semaphore::new(cfg.concurrency)),
            cfg,
            sink,
            processor,
        })
    }

    #[instrument(skip(self))]
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let (mut stream, sources) = crate::input::stream_targets(self.cfg.as_ref()).await?;
        let mut tasks = FuturesUnordered::new();

        while let Some(target) = stream.next().await {
            self.limiter.acquire().await;
            let permit = self.sem.clone().acquire_owned().await?;
            let cfg = self.cfg.clone();
            let sink = self.sink.clone();
            let processor = self.processor.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let res = timeout(
                    cfg.overall_timeout,
                    processor.process_target(target.clone(), cfg.clone()),
                )
                .await;
                match res {
                    Ok(Ok(outcome)) => sink.emit(outcome).await,
                    Ok(Err(err)) => {
                        sink.emit_error(target, err.to_string()).await;
                    }
                    Err(_) => sink.emit_error(target, "overall timeout".to_string()).await,
                }
            }));
        }

        while tasks.next().await.is_some() {}
        sources.wait().await
    }
}
