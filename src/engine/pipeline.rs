use crate::client::{client_for_target, ClientRequest};
use crate::model::{Config, Diagnostics, ReadStopReason, ScanMode, ScanOutcome, Status, TcpMeta};
use crate::probe::{probe_for_target, ProbeRequest};
use crate::util::now_millis;
use async_trait::async_trait;
use std::time::Duration;
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
        let connect_timeout = adjusted_connect_timeout(cfg.as_ref(), &target);
        let connect_result = timeout(connect_timeout, TcpStream::connect(target.resolved)).await;

        let (mut stream, tcp_meta) = match connect_result {
            Ok(Ok(stream)) => {
                let elapsed = now_millis() - tcp_start;
                (
                    stream,
                    TcpMeta {
                        connect_ms: Some(elapsed),
                        error: None,
                    },
                )
            }
            Ok(Err(err)) => {
                return Ok(outcome_with_context(
                    target,
                    Status::Error,
                    TcpMeta {
                        connect_ms: None,
                        error: Some(err.to_string()),
                    },
                    ReadStopReason::NotStarted,
                    Vec::new(),
                    Some(Diagnostics {
                        stage: "connect".into(),
                        message: err.to_string(),
                    }),
                    cfg.max_bytes,
                    cfg.read_timeout,
                ));
            }
            Err(_) => {
                return Ok(outcome_with_context(
                    target,
                    Status::Timeout,
                    TcpMeta {
                        connect_ms: None,
                        error: Some("connect timeout".into()),
                    },
                    ReadStopReason::Timeout,
                    Vec::new(),
                    Some(Diagnostics {
                        stage: "connect".into(),
                        message: "connect timeout".into(),
                    }),
                    cfg.max_bytes,
                    cfg.read_timeout,
                ));
            }
        };
        let status = Status::Open;

        let client_req = ClientRequest {
            target: target.clone(),
            mode: cfg.mode,
        };
        let client = client_for_target(&client_req);
        let probe_req = ProbeRequest {
            target: target.clone(),
            mode: cfg.mode,
        };
        let probe = probe_for_target(&probe_req);

        let mut reader = BannerReader::new(cfg.max_bytes, cfg.read_timeout);
        let read_result = if let Some(client) = client {
            match client.execute(&mut stream, cfg.as_ref()).await {
                Ok(result) => result,
                Err(err) => {
                    return Ok(outcome_with_context(
                        target,
                        Status::Error,
                        tcp_meta,
                        ReadStopReason::NotStarted,
                        Vec::new(),
                        Some(Diagnostics {
                            stage: format!("client:{}", client.name()),
                            message: err.to_string(),
                        }),
                        cfg.max_bytes,
                        cfg.read_timeout,
                    ))
                }
            }
        } else if let Some(probe) = probe {
            match probe.execute(&mut stream, cfg.as_ref()).await {
                Ok(result) => result,
                Err(err) => {
                    return Ok(outcome_with_context(
                        target,
                        Status::Error,
                        tcp_meta,
                        ReadStopReason::NotStarted,
                        Vec::new(),
                        Some(Diagnostics {
                            stage: "probe".into(),
                            message: err.to_string(),
                        }),
                        cfg.max_bytes,
                        cfg.read_timeout,
                    ))
                }
            }
        } else {
            match reader.read(&mut stream, None).await {
                Ok(result) => result,
                Err(err) => {
                    return Ok(outcome_with_context(
                        target,
                        Status::Error,
                        tcp_meta,
                        ReadStopReason::NotStarted,
                        Vec::new(),
                        Some(Diagnostics {
                            stage: "banner-read".into(),
                            message: err.to_string(),
                        }),
                        cfg.max_bytes,
                        cfg.read_timeout,
                    ))
                }
            }
        };

        let fingerprint = crate::probe::fingerprint(&read_result);
        let banner = reader.render(read_result);
        let total = now_millis() - start;
        debug!(target = %target.resolved, ms = total, "processed target");

        Ok(ScanOutcome {
            target: target.view(),
            status,
            tcp: tcp_meta,
            banner,
            fingerprint,
            diagnostics: None,
        })
    }
}

fn adjusted_connect_timeout(cfg: &Config, target: &crate::model::Target) -> Duration {
    if matches!(cfg.mode, ScanMode::Active) && target.resolved.port() == 21 {
        // FTP servers are often slower to finish the TCP handshake due to
        // connection tracking and banner throttling. Give them extra time so
        // we don't misclassify healthy endpoints as timeouts in active mode.
        return cfg.connect_timeout.saturating_mul(4);
    }

    cfg.connect_timeout
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{OutputConfig, OutputFormat, Target, TargetSpec};

    fn dummy_cfg(mode: ScanMode, connect_timeout: Duration) -> Config {
        Config {
            target: None,
            input: None,
            port_filter: None,
            concurrency: 1,
            rate: 1,
            connect_timeout,
            read_timeout: Duration::from_secs(1),
            overall_timeout: Duration::from_secs(5),
            max_bytes: 64,
            mode,
            output: OutputConfig {
                format: OutputFormat::Jsonl,
            },
        }
    }

    fn ftp_target() -> Target {
        Target {
            original: TargetSpec {
                host: "example.com".into(),
                port: 21,
            },
            resolved: "198.51.100.10:21".parse().unwrap(),
        }
    }

    #[test]
    fn extends_timeout_for_active_ftp() {
        let cfg = dummy_cfg(ScanMode::Active, Duration::from_secs(1));
        let timeout = adjusted_connect_timeout(&cfg, &ftp_target());
        assert_eq!(timeout, Duration::from_secs(4));
    }

    #[test]
    fn leaves_timeout_unchanged_for_other_modes_and_ports() {
        let cfg = dummy_cfg(ScanMode::Passive, Duration::from_secs(1));
        let timeout = adjusted_connect_timeout(&cfg, &ftp_target());
        assert_eq!(timeout, Duration::from_secs(1));

        let mut active_non_ftp = ftp_target();
        active_non_ftp.resolved.set_port(22);
        let cfg_active = dummy_cfg(ScanMode::Active, Duration::from_secs(1));
        let timeout_active = adjusted_connect_timeout(&cfg_active, &active_non_ftp);
        assert_eq!(timeout_active, Duration::from_secs(1));
    }
}

fn outcome_with_context(
    target: crate::model::Target,
    status: Status,
    tcp: TcpMeta,
    reason: ReadStopReason,
    bytes: Vec<u8>,
    diagnostics: Option<Diagnostics>,
    max_bytes: usize,
    idle_timeout: Duration,
) -> ScanOutcome {
    let read_result = super::reader::ReadResult {
        truncated: matches!(reason, ReadStopReason::SizeLimit) || bytes.len() >= max_bytes,
        bytes,
        reason: reason.clone(),
    };
    let banner = BannerReader::new(max_bytes, idle_timeout).render(read_result.clone());
    let fingerprint = crate::probe::fingerprint(&read_result);
    ScanOutcome {
        target: target.view(),
        status,
        tcp,
        banner,
        fingerprint,
        diagnostics,
    }
}
