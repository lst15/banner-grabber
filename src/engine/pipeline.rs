use crate::model::{Config, Fingerprint, ScanOutcome, Status, TcpMeta};
use crate::probe::{probe_for_target, ProbeRequest};
use crate::util::now_millis;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use super::reader::BannerReader;

#[async_trait]
pub trait TargetProcessor: Send + Sync {
    async fn process_target(
        &self,
        target: crate::model::Target,
        cfg: std::sync::Arc<Config>,
    ) -> anyhow::Result<ScanOutcome>;
}

#[derive(Clone, Debug, Default)]
pub struct DefaultProcessor;

#[async_trait]
impl TargetProcessor for DefaultProcessor {
    async fn process_target(
        &self,
        target: crate::model::Target,
        cfg: std::sync::Arc<Config>,
    ) -> anyhow::Result<ScanOutcome> {
        let start = now_millis();
        let tcp_start = now_millis();
        let connect_result =
            timeout(cfg.connect_timeout, TcpStream::connect(target.resolved)).await;

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
            probe
                .execute(&mut stream, &mut banner_bytes, cfg.as_ref())
                .await?;
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
