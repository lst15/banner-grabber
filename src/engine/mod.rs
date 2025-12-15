pub mod rate;
pub mod reader;

use crate::model::{Config, Fingerprint, ScanOutcome, Status, TcpMeta};
use crate::output::OutputSink;
use crate::probe::{probe_for_target, ProbeRequest};
use crate::util::now_millis;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use rate::RateLimiter;
use reader::BannerReader;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, instrument};

pub struct Engine {
    cfg: Config,
    sink: OutputSink,
    limiter: RateLimiter,
    sem: std::sync::Arc<Semaphore>,
}

impl Engine {
    pub fn new(cfg: Config, sink: OutputSink) -> anyhow::Result<Self> {
        Ok(Self {
            limiter: RateLimiter::new(cfg.rate),
            sem: std::sync::Arc::new(Semaphore::new(cfg.concurrency)),
            cfg,
            sink,
        })
    }

    #[instrument(skip(self))]
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut stream = crate::input::stream_targets(&self.cfg)?;
        let mut tasks = FuturesUnordered::new();

        while let Some(target) = stream.next().await {
            self.limiter.acquire().await;
            let permit = self.sem.clone().acquire_owned().await?;
            let cfg = self.cfg.clone();
            let sink = self.sink.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let res = timeout(cfg.overall_timeout, process_target(target.clone(), &cfg)).await;
                match res {
                    Ok(Ok(outcome)) => sink.emit(outcome).await,
                    Ok(Err(err)) => {
                        sink.emit_error(target, err.to_string()).await;
                    }
                    Err(_) => sink.emit_error(target, "overall timeout".to_string()).await,
                }
            }));

            self.limiter.sleep_jitter().await;
        }

        while tasks.next().await.is_some() {}
        Ok(())
    }
}

async fn process_target(target: crate::model::Target, cfg: &Config) -> anyhow::Result<ScanOutcome> {
    let start = now_millis();
    let tcp_start = now_millis();
    let connect_result = timeout(cfg.connect_timeout, TcpStream::connect(target.resolved)).await;

    let (mut stream, tcp_meta, status) = match connect_result {
        Ok(Ok(stream)) => {
            let elapsed = now_millis() - tcp_start;
            (
                stream,
                TcpMeta {
                    connect_ms: Some(elapsed),
                    error: None,
                },
                Status::Open,
            )
        }
        Ok(Err(err)) => {
            return Err(err.into());
        }
        Err(_) => {
            let meta = TcpMeta {
                connect_ms: None,
                error: Some("connect timeout".into()),
            };
            return Ok(empty_outcome(target, Status::Timeout, meta));
        }
    };

    let mut reader = BannerReader::new(cfg.max_bytes);

    let probe_req = ProbeRequest {
        target: target.clone(),
        mode: cfg.mode,
    };
    let probe = probe_for_target(&probe_req);

    let mut banner_bytes = Vec::new();
    if let Some(probe) = probe {
        probe.execute(&mut stream, &mut banner_bytes, cfg).await?;
    } else {
        match timeout(cfg.read_timeout, reader.read(&mut stream, None)).await {
            Ok(Ok(bytes)) => banner_bytes = bytes,
            Ok(Err(err)) => return Err(err),
            Err(_) => return Ok(empty_outcome(target, Status::Timeout, tcp_meta)),
        }
    }

    if banner_bytes.is_empty() {
        match timeout(cfg.read_timeout, reader.read(&mut stream, None)).await {
            Ok(Ok(bytes)) => banner_bytes = bytes,
            Ok(Err(err)) => return Err(err),
            Err(_) => return Ok(empty_outcome(target, Status::Timeout, tcp_meta)),
        }
    }

    let fingerprint = crate::probe::fingerprint(&banner_bytes);
    let banner = reader.render(banner_bytes);
    let total = now_millis() - start;
    debug!(target = %target.resolved, ms = total, "processed target");

    Ok(ScanOutcome {
        target: target.view(),
        status,
        tcp: tcp_meta,
        banner,
        fingerprint,
    })
}

fn empty_outcome(target: crate::model::Target, status: Status, tcp: TcpMeta) -> ScanOutcome {
    ScanOutcome {
        target: target.view(),
        status,
        tcp,
        banner: crate::model::Banner {
            raw_hex: String::new(),
            printable: String::new(),
            truncated: false,
        },
        fingerprint: Fingerprint {
            protocol: None,
            score: 0.0,
            fields: Default::default(),
        },
    }
}
