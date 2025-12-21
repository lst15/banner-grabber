pub mod pipeline;
pub mod rate;
pub mod reader;

use crate::model::Config;
use crate::output::OutputChannel;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use pipeline::{DefaultProcessor, TargetProcessor};
use rate::RateLimiter;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::instrument;

pub struct Engine {
    cfg: std::sync::Arc<Config>,
    sink: OutputChannel,
    limiter: RateLimiter,
    sem: std::sync::Arc<Semaphore>,
    processor: std::sync::Arc<dyn TargetProcessor>,
}

impl Engine {
    pub fn new(cfg: Config, sink: OutputChannel) -> anyhow::Result<Self> {
        Self::with_processor(cfg, sink, std::sync::Arc::new(DefaultProcessor))
    }

    pub fn with_processor(
        cfg: Config,
        sink: OutputChannel,
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
        let mut stream = crate::input::stream_targets(self.cfg.as_ref())?;
        let mut tasks = FuturesUnordered::new();

        while let Some(next) = stream.next().await {
            let target = match next {
                Ok(target) => target,
                Err(err) => return Err(err),
            };
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
                    Ok(Ok(outcome)) => sink.emit(outcome).await?,
                    Ok(Err(err)) => {
                        sink.emit_error(target, &cfg.protocol, err.to_string())
                            .await?
                    }
                    Err(_) => {
                        sink.emit_error(target, &cfg.protocol, "overall timeout".to_string())
                            .await?
                    }
                }
                Ok::<_, anyhow::Error>(())
            }));
        }

        while let Some(joined) = tasks.next().await {
            joined??;
        }
        self.sink.shutdown().await?;
        Ok(())
    }
}
