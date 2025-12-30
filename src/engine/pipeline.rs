use crate::clients::{client_for_target, udp_client_for_target};
use crate::model::{
    Config, Diagnostics, Fingerprint, ProcessingRequest, Protocol, ReadStopReason, ScanOutcome,
    Status, TcpMeta,
};
use crate::probe::probe_for_target;
use crate::util::now_millis;
use crate::webdriver;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::debug;

use super::rate::RateLimiter;
use super::reader::BannerReader;

#[async_trait]
pub trait TargetProcessor: Send + Sync {
    async fn process_target(
        &self,
        target: crate::model::Target,
        config: std::sync::Arc<Config>,
    ) -> anyhow::Result<ScanOutcome>;
}

#[derive(Clone, Debug)]
pub struct DefaultProcessor {
    webdriver_pool: Option<Arc<WebdriverPool>>,
}

impl Default for DefaultProcessor {
    fn default() -> Self {
        Self {
            webdriver_pool: None,
        }
    }
}

impl DefaultProcessor {
    pub fn new(config: &Config) -> Self {
        let webdriver_pool = if config.webdriver {
            Some(Arc::new(WebdriverPool::new(
                config.webdriver_rate,
                config.webdriver_concurrency,
                config.webdriver_timeout,
            )))
        } else {
            None
        };
        Self { webdriver_pool }
    }
}

#[async_trait]
impl TargetProcessor for DefaultProcessor {
    async fn process_target(
        &self,
        target: crate::model::Target,
        config: std::sync::Arc<Config>,
    ) -> anyhow::Result<ScanOutcome> {
        let start = now_millis();
        let tcp_start = now_millis();
        let connect_timeout = crate::model::adjusted_connect_timeout(
            config.connect_timeout,
            config.mode,
            target.resolved.port(),
        );

        let request = ProcessingRequest {
            target: target.clone(),
            mode: config.mode,
            protocol: config.protocol.clone(),
        };
        if let Some(outcome) = attempt_udp_scan(target.clone(), config.as_ref(), &request).await? {
            return Ok(outcome);
        }

        let (stream, tcp_meta) =
            match connect_tcp(target.clone(), config.as_ref(), connect_timeout, tcp_start).await? {
                Ok(connection) => connection,
                Err(outcome) => return Ok(outcome),
            };

        let read_result =
            match process_tcp_stream(stream, target.clone(), config.as_ref(), &request, &tcp_meta)
                .await
            {
                Ok(result) => result,
                Err(outcome) => return Ok(outcome),
            };

        let (webdriver_body, diagnostics) = if config.webdriver {
            if let Some(pool) = &self.webdriver_pool {
                match pool.fetch(&target, &config.protocol).await {
                    Ok(body) => (Some(body), None),
                    Err(err) => (
                        None,
                        Some(Diagnostics {
                            stage: "webdriver".into(),
                            message: err.to_string(),
                        }),
                    ),
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };
        let total = now_millis() - start;
        debug!(target = %target.resolved, ms = total, "processed target");

        Ok(build_outcome_from_read_result(
            target,
            Status::Open,
            tcp_meta,
            read_result,
            diagnostics,
            config.max_bytes,
            config.read_timeout,
            &config.protocol,
            webdriver_body,
        ))
    }
}

async fn attempt_udp_scan(
    target: crate::model::Target,
    config: &Config,
    request: &ProcessingRequest,
) -> anyhow::Result<Option<ScanOutcome>> {
    if let Some(udp_client) = udp_client_for_target(request) {
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
        let elapsed = now_millis() - udp_start;

        return Ok(Some(build_outcome_from_read_result(
            target,
            status,
            TcpMeta {
                connect_ms: Some(elapsed),
                error: None,
            },
            read_result,
            None,
            config.max_bytes,
            config.read_timeout,
            &config.protocol,
            None,
        )));
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
    request: &ProcessingRequest,
    tcp_meta: &TcpMeta,
) -> Result<super::reader::ReadResult, ScanOutcome> {
    let client = client_for_target(request);
    let probe = probe_for_target(request);

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
    build_outcome_from_read_result(
        target,
        status,
        tcp,
        read_result,
        diagnostics,
        max_bytes,
        idle_timeout,
        protocol,
        None,
    )
}

fn build_outcome_from_read_result(
    target: crate::model::Target,
    status: Status,
    tcp: TcpMeta,
    read_result: super::reader::ReadResult,
    diagnostics: Option<Diagnostics>,
    max_bytes: usize,
    idle_timeout: Duration,
    protocol: &Protocol,
    webdriver: Option<String>,
) -> ScanOutcome {
    let banner = BannerReader::new(max_bytes, idle_timeout).render(read_result);
    let fingerprint = Fingerprint::from_protocol(protocol);
    ScanOutcome {
        target: target.view(),
        status,
        tcp,
        banner,
        webdriver,
        fingerprint,
        diagnostics,
    }
}

#[derive(Debug)]
struct WebdriverPool {
    limiter: RateLimiter,
    semaphore: Arc<Semaphore>,
    timeout: Duration,
}

impl WebdriverPool {
    fn new(rate: u32, concurrency: usize, timeout: Duration) -> Self {
        Self {
            limiter: RateLimiter::new(rate),
            semaphore: Arc::new(Semaphore::new(concurrency)),
            timeout,
        }
    }

    async fn fetch(
        &self,
        target: &crate::model::Target,
        protocol: &Protocol,
    ) -> anyhow::Result<String> {
        self.limiter.acquire().await;
        let _permit = self.semaphore.clone().acquire_owned().await?;
        webdriver::fetch_rendered_body(target, protocol, self.timeout).await
    }
}
