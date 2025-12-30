use crate::clients::{client_for_target, udp_client_for_target, ClientRequest};
use crate::model::{
    Config, Diagnostics, Fingerprint, Protocol, ReadStopReason, ScanMode, ScanOutcome, Status,
    TcpMeta,
};
use crate::probe::{probe_for_target, ProbeRequest};
use crate::util::now_millis;
use async_trait::async_trait;
use headless_chrome::Browser;
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
        config: std::sync::Arc<Config>,
    ) -> anyhow::Result<ScanOutcome>;
}

#[derive(Clone, Debug, Default)]
pub struct DefaultProcessor;

#[async_trait]
impl TargetProcessor for DefaultProcessor {
    async fn process_target(
        &self,
        target: crate::model::Target,
        config: std::sync::Arc<Config>,
    ) -> anyhow::Result<ScanOutcome> {
        let start = now_millis();

        if config.webdriver && matches!(config.protocol, Protocol::Http | Protocol::Https) {
            return Ok(process_webdriver_target(
                target,
                config.as_ref(),
                start,
            )
            .await);
        }

        let tcp_start = now_millis();
        let connect_timeout = adjusted_connect_timeout(config.as_ref(), &target);

        let client_request = ClientRequest {
            target: target.clone(),
            mode: config.mode,
            protocol: config.protocol.clone(),
        };
        if let Some(outcome) =
            attempt_udp_scan(target.clone(), config.as_ref(), &client_request).await?
        {
            return Ok(outcome);
        }

        let (stream, tcp_meta) =
            match connect_tcp(target.clone(), config.as_ref(), connect_timeout, tcp_start).await? {
                Ok(connection) => connection,
                Err(outcome) => return Ok(outcome),
            };

        let probe_request = ProbeRequest {
            target: target.clone(),
            mode: config.mode,
            protocol: config.protocol.clone(),
        };

        let read_result = match process_tcp_stream(
            stream,
            target.clone(),
            config.as_ref(),
            &client_request,
            &probe_request,
            &tcp_meta,
        )
        .await
        {
            Ok(result) => result,
            Err(outcome) => return Ok(outcome),
        };

        let fingerprint = Fingerprint::from_protocol(&config.protocol);
        let banner = BannerReader::new(config.max_bytes, config.read_timeout).render(read_result);
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

async fn attempt_udp_scan(
    target: crate::model::Target,
    config: &Config,
    client_request: &ClientRequest,
) -> anyhow::Result<Option<ScanOutcome>> {
    if let Some(udp_client) = udp_client_for_target(client_request) {
        let udp_start = now_millis();

        let read_result = match udp_client.execute(&target, config).await {
            Ok(result) => result,
            Err(err) => {
                return Ok(Some(build_outcome_with_context(
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
                    config.max_bytes,
                    config.read_timeout,
                    &config.protocol,
                )))
            }
        };

        let status = if matches!(read_result.reason, ReadStopReason::Timeout) {
            Status::Timeout
        } else {
            Status::Open
        };
        let banner =
            BannerReader::new(config.max_bytes, config.read_timeout).render(read_result.clone());
        let fingerprint = Fingerprint::from_protocol(&config.protocol);
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
    config: &Config,
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
        Ok(Err(err)) => Err(build_outcome_with_context(
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
            config.max_bytes,
            config.read_timeout,
            &config.protocol,
        )),
        Err(_) => Err(build_outcome_with_context(
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
            config.max_bytes,
            config.read_timeout,
            &config.protocol,
        )),
    };

    Ok(connection)
}

async fn process_tcp_stream(
    stream: TcpStream,
    target: crate::model::Target,
    config: &Config,
    client_request: &ClientRequest,
    probe_request: &ProbeRequest,
    tcp_meta: &TcpMeta,
) -> Result<super::reader::ReadResult, ScanOutcome> {
    let client = client_for_target(client_request);
    let probe = probe_for_target(probe_request);

    if let Some(client) = client {
        let mut stream = stream;
        match client.execute(&mut stream, config).await {
            Ok(result) => Ok(result),
            Err(err) => Err(build_outcome_with_context(
                target,
                Status::Error,
                tcp_meta.clone(),
                ReadStopReason::NotStarted,
                Vec::new(),
                Some(Diagnostics {
                    stage: format!("clients:{}", client.name()),
                    message: err.to_string(),
                }),
                config.max_bytes,
                config.read_timeout,
                &config.protocol,
            )),
        }
    } else if let Some(probe) = probe {
        match probe.execute(stream, config, &target).await {
            Ok(result) => Ok(result),
            Err(err) => Err(build_outcome_with_context(
                target,
                Status::Error,
                tcp_meta.clone(),
                ReadStopReason::NotStarted,
                Vec::new(),
                Some(Diagnostics {
                    stage: "probe".into(),
                    message: err.to_string(),
                }),
                config.max_bytes,
                config.read_timeout,
                &config.protocol,
            )),
        }
    } else {
        let mut stream = stream;
        let mut reader = BannerReader::new(config.max_bytes, config.read_timeout);
        match reader.read(&mut stream, None).await {
            Ok(result) => Ok(result),
            Err(err) => Err(build_outcome_with_context(
                target,
                Status::Error,
                tcp_meta.clone(),
                ReadStopReason::NotStarted,
                Vec::new(),
                Some(Diagnostics {
                    stage: "banner-read".into(),
                    message: err.to_string(),
                }),
                config.max_bytes,
                config.read_timeout,
                &config.protocol,
            )),
        }
    }
}

fn adjusted_connect_timeout(config: &Config, target: &crate::model::Target) -> Duration {
    if matches!(config.mode, ScanMode::Active) && target.resolved.port() == 21 {
        // FTP servers are often slower to finish the TCP handshake due to
        // connection tracking and banner throttling. Give them extra time so
        // we don't misclassify healthy endpoints as timeouts in active mode.
        return config.connect_timeout.saturating_mul(4);
    }

    config.connect_timeout
}

async fn process_webdriver_target(
    target: crate::model::Target,
    config: &Config,
    start: u128,
) -> ScanOutcome {
    let url = webdriver_url(&target, &config.protocol);
    let elapsed_start = now_millis();
    let result = fetch_with_webdriver(url, config.max_bytes, config.overall_timeout).await;
    let elapsed = now_millis().saturating_sub(elapsed_start);
    match result {
        Ok(read_result) => {
            let banner = BannerReader::new(config.max_bytes, config.read_timeout).render(read_result);
            let fingerprint = Fingerprint::from_protocol(&config.protocol);
            let total = now_millis() - start;
            debug!(target = %target.resolved, ms = total, "processed target");
            ScanOutcome {
                target: target.view(),
                status: Status::Open,
                tcp: TcpMeta {
                    connect_ms: Some(elapsed),
                    error: None,
                },
                banner,
                fingerprint,
                diagnostics: None,
            }
        }
        Err(failure) => build_outcome_with_context(
            target,
            failure.status,
            TcpMeta {
                connect_ms: Some(elapsed),
                error: Some(failure.message.clone()),
            },
            failure.reason,
            Vec::new(),
            Some(Diagnostics {
                stage: "webdriver".into(),
                message: failure.message,
            }),
            config.max_bytes,
            config.read_timeout,
            &config.protocol,
        ),
    }
}

fn webdriver_url(target: &crate::model::Target, protocol: &Protocol) -> String {
    let host = if target.original.host.is_empty() {
        target.resolved.ip().to_string()
    } else {
        target.original.host.clone()
    };
    let scheme = match protocol {
        Protocol::Http => "http",
        Protocol::Https => "https",
        _ => "http",
    };
    format!("{scheme}://{host}:{}/", target.resolved.port())
}

struct WebdriverFailure {
    status: Status,
    reason: ReadStopReason,
    message: String,
}

async fn fetch_with_webdriver(
    url: String,
    max_bytes: usize,
    timeout_duration: Duration,
) -> Result<super::reader::ReadResult, WebdriverFailure> {
    let handle = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let browser = Browser::default()?;
        let tab = browser.new_tab()?;
        tab.navigate_to(&url)?;
        tab.wait_until_navigated()?;
        let content = tab.get_content()?;
        Ok(content.into_bytes())
    });

    let joined = match timeout(timeout_duration, handle).await {
        Ok(joined) => joined,
        Err(_) => {
            return Err(WebdriverFailure {
                status: Status::Timeout,
                reason: ReadStopReason::Timeout,
                message: "webdriver timeout".into(),
            })
        }
    };

    let bytes = match joined {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(err)) => {
            return Err(WebdriverFailure {
                status: Status::Error,
                reason: ReadStopReason::NotStarted,
                message: err.to_string(),
            })
        }
        Err(err) => {
            return Err(WebdriverFailure {
                status: Status::Error,
                reason: ReadStopReason::NotStarted,
                message: err.to_string(),
            })
        }
    };

    let truncated = bytes.len() > max_bytes;
    let bytes = if truncated {
        bytes[..max_bytes].to_vec()
    } else {
        bytes
    };
    let reason = if truncated {
        ReadStopReason::SizeLimit
    } else {
        ReadStopReason::ConnectionClosed
    };

    Ok(super::reader::ReadResult {
        bytes,
        reason,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{OutputConfig, OutputFormat, Protocol, Target, TargetSpec};

    fn baseline_config(mode: ScanMode, connect_timeout: Duration) -> Config {
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
            webdriver: false,
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
        let config = baseline_config(ScanMode::Active, Duration::from_secs(1));
        let timeout = adjusted_connect_timeout(&config, &ftp_target());
        assert_eq!(timeout, Duration::from_secs(4));
    }

    #[test]
    fn leaves_timeout_unchanged_for_other_modes_and_ports() {
        let config = baseline_config(ScanMode::Passive, Duration::from_secs(1));
        let timeout = adjusted_connect_timeout(&config, &ftp_target());
        assert_eq!(timeout, Duration::from_secs(1));

        let mut active_non_ftp = ftp_target();
        active_non_ftp.resolved.set_port(22);
        let active_config = baseline_config(ScanMode::Active, Duration::from_secs(1));
        let timeout_active = adjusted_connect_timeout(&active_config, &active_non_ftp);
        assert_eq!(timeout_active, Duration::from_secs(1));
    }
}

fn build_outcome_with_context(
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
