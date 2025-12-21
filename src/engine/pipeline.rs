use crate::clients::{client_for_target, udp_client_for_target, ClientRequest};
use crate::model::{
    Config, Diagnostics, Fingerprint, Protocol, ReadStopReason, ScanMode, ScanOutcome, Status,
    TcpMeta,
};
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

        let client_req = ClientRequest {
            target: target.clone(),
            mode: cfg.mode,
            protocol: cfg.protocol.clone(),
        };
        if let Some(outcome) = handle_udp_path(target.clone(), cfg.as_ref(), &client_req).await? {
            return Ok(outcome);
        }

        let (mut stream, tcp_meta) =
            match connect_tcp(target.clone(), cfg.as_ref(), connect_timeout, tcp_start).await? {
                Ok(connection) => connection,
                Err(outcome) => return Ok(outcome),
            };

        let probe_req = ProbeRequest {
            target: target.clone(),
            mode: cfg.mode,
            protocol: cfg.protocol.clone(),
        };

        let read_result = match execute_stream_pipeline(
            &mut stream,
            target.clone(),
            cfg.as_ref(),
            &client_req,
            &probe_req,
            &tcp_meta,
        )
        .await
        {
            Ok(result) => result,
            Err(outcome) => return Ok(outcome),
        };

        let fingerprint = Fingerprint::from_protocol(&cfg.protocol);
        let banner = BannerReader::new(cfg.max_bytes, cfg.read_timeout).render(read_result);
        let total = now_millis() - start;
        debug!(target = %target.resolved, ms = total, "processed target");

        Ok(ScanOutcome {
            target: target.view(),
            status: Status::Open,
            tcp: tcp_meta,
            banner,
            fingerprint,
            diagnostics: None,
        })
    }
}

async fn handle_udp_path(
    target: crate::model::Target,
    cfg: &Config,
    client_req: &ClientRequest,
) -> anyhow::Result<Option<ScanOutcome>> {
    if let Some(udp_client) = udp_client_for_target(client_req) {
        let udp_start = now_millis();

        let read_result = match udp_client.execute(&target, cfg).await {
            Ok(result) => result,
            Err(err) => {
                return Ok(Some(outcome_with_context(
                    target,
                    Status::Error,
                    TcpMeta {
                        connect_ms: Some(now_millis() - udp_start),
                        error: Some(err.to_string()),
                    },
                    ReadStopReason::NotStarted,
                    Vec::new(),
                    Some(Diagnostics {
                        stage: format!("clients:{}", udp_client.name()),
                        message: err.to_string(),
                    }),
                    cfg.max_bytes,
                    cfg.read_timeout,
                    &cfg.protocol,
                )))
            }
        };

        let status = if matches!(read_result.reason, ReadStopReason::Timeout) {
            Status::Timeout
        } else {
            Status::Open
        };
        let banner = BannerReader::new(cfg.max_bytes, cfg.read_timeout).render(read_result.clone());
        let fingerprint = Fingerprint::from_protocol(&cfg.protocol);
        let elapsed = now_millis() - udp_start;

        return Ok(Some(ScanOutcome {
            target: target.view(),
            status,
            tcp: TcpMeta {
                connect_ms: Some(elapsed),
                error: None,
            },
            banner,
            fingerprint,
            diagnostics: None,
        }));
    }

    Ok(None)
}

async fn connect_tcp(
    target: crate::model::Target,
    cfg: &Config,
    connect_timeout: Duration,
    tcp_start: u128,
) -> anyhow::Result<Result<(TcpStream, TcpMeta), ScanOutcome>> {
    let connect_result = timeout(connect_timeout, TcpStream::connect(target.resolved)).await;

    let connection = match connect_result {
        Ok(Ok(stream)) => {
            let elapsed = now_millis() - tcp_start;
            Ok((
                stream,
                TcpMeta {
                    connect_ms: Some(elapsed),
                    error: None,
                },
            ))
        }
        Ok(Err(err)) => Err(outcome_with_context(
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
            &cfg.protocol,
        )),
        Err(_) => Err(outcome_with_context(
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
            &cfg.protocol,
        )),
    };

    Ok(connection)
}

async fn execute_stream_pipeline(
    stream: &mut TcpStream,
    target: crate::model::Target,
    cfg: &Config,
    client_req: &ClientRequest,
    probe_req: &ProbeRequest,
    tcp_meta: &TcpMeta,
) -> Result<super::reader::ReadResult, ScanOutcome> {
    let client = client_for_target(client_req);
    let probe = probe_for_target(probe_req);

    if let Some(client) = client {
        match client.execute(stream, cfg).await {
            Ok(result) => Ok(result),
            Err(err) => Err(outcome_with_context(
                target,
                Status::Error,
                tcp_meta.clone(),
                ReadStopReason::NotStarted,
                Vec::new(),
                Some(Diagnostics {
                    stage: format!("clients:{}", client.name()),
                    message: err.to_string(),
                }),
                cfg.max_bytes,
                cfg.read_timeout,
                &cfg.protocol,
            )),
        }
    } else if let Some(probe) = probe {
        match probe.execute(stream, cfg).await {
            Ok(result) => Ok(result),
            Err(err) => Err(outcome_with_context(
                target,
                Status::Error,
                tcp_meta.clone(),
                ReadStopReason::NotStarted,
                Vec::new(),
                Some(Diagnostics {
                    stage: "probe".into(),
                    message: err.to_string(),
                }),
                cfg.max_bytes,
                cfg.read_timeout,
                &cfg.protocol,
            )),
        }
    } else {
        let mut reader = BannerReader::new(cfg.max_bytes, cfg.read_timeout);
        match reader.read(stream, None).await {
            Ok(result) => Ok(result),
            Err(err) => Err(outcome_with_context(
                target,
                Status::Error,
                tcp_meta.clone(),
                ReadStopReason::NotStarted,
                Vec::new(),
                Some(Diagnostics {
                    stage: "banner-read".into(),
                    message: err.to_string(),
                }),
                cfg.max_bytes,
                cfg.read_timeout,
                &cfg.protocol,
            )),
        }
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
    use crate::model::{OutputConfig, OutputFormat, Protocol, Target, TargetSpec};

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
            protocol: Protocol::Http,
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
    protocol: &Protocol,
) -> ScanOutcome {
    let read_result = super::reader::ReadResult {
        truncated: matches!(reason, ReadStopReason::SizeLimit) || bytes.len() >= max_bytes,
        bytes,
        reason: reason.clone(),
    };
    let banner = BannerReader::new(max_bytes, idle_timeout).render(read_result.clone());
    let fingerprint = Fingerprint::from_protocol(protocol);
    ScanOutcome {
        target: target.view(),
        status,
        tcp,
        banner,
        fingerprint,
        diagnostics,
    }
}
