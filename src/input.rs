use crate::model::{Target, TargetSpec};
use anyhow::Context;
use futures::{stream::FuturesUnordered, StreamExt};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::lookup_host;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;

const FILE_RESOLUTION_CONCURRENCY: usize = 64;

pub async fn stream_targets(
    cfg: &crate::model::Config,
) -> anyhow::Result<(ReceiverStream<Target>, TargetSources)> {
    let (tx, rx) = mpsc::channel(256);
    let mut handles = Vec::new();

    if let Some(spec) = cfg.target.clone() {
        let tx = tx.clone();
        handles.push(tokio::spawn(
            async move { resolve_and_send(spec, tx).await },
        ));
    }

    if let Some(path) = cfg.input.clone() {
        let tx = tx.clone();
        handles.push(tokio::spawn(async move { read_file(path, tx).await }));
    }

    drop(tx);
    Ok((ReceiverStream::new(rx), TargetSources { handles }))
}

pub struct TargetSources {
    handles: Vec<JoinHandle<anyhow::Result<()>>>,
}

impl TargetSources {
    pub async fn wait(self) -> anyhow::Result<()> {
        let mut first_error: Option<anyhow::Error> = None;
        for handle in self.handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Err(join_err) => {
                    if first_error.is_none() {
                        first_error = Some(join_err.into());
                    }
                }
            }
        }

        if let Some(err) = first_error {
            Err(err)
        } else {
            Ok(())
        }
    }
}

async fn read_file(path: String, tx: mpsc::Sender<Target>) -> anyhow::Result<()> {
    let file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("cannot open input {}", path))?;
    let mut reader = BufReader::new(file).lines();
    let sem = Arc::new(Semaphore::new(FILE_RESOLUTION_CONCURRENCY));
    let mut tasks = FuturesUnordered::new();
    let mut first_error: Option<anyhow::Error> = None;
    while let Some(line) = reader.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(spec) = parse_target(trimmed) {
            let tx = tx.clone();
            let sem = sem.clone();
            tasks.push(tokio::spawn(async move {
                let permit = sem.acquire_owned().await?;
                let _permit = permit;
                resolve_and_send(spec, tx).await
            }));
        } else {
            tracing::warn!(line = %trimmed, "skipping invalid target");
        }
    }

    while let Some(res) = tasks.next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(join_err) => {
                if first_error.is_none() {
                    first_error = Some(join_err.into());
                }
            }
        }
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
}

fn parse_target(line: &str) -> Option<TargetSpec> {
    if let Some((host_part, port_part)) = line.rsplit_once(':') {
        let host = host_part
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port: u16 = port_part.parse().ok()?;
        return Some(TargetSpec {
            host: host.to_string(),
            port,
        });
    }
    None
}

async fn resolve_and_send(spec: TargetSpec, tx: mpsc::Sender<Target>) -> anyhow::Result<()> {
    let lookup = lookup_host((spec.host.as_str(), spec.port)).await?;
    for addr in lookup {
        let target = Target {
            original: spec.clone(),
            resolved: addr,
        };
        tx.send(target).await.ok();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{OutputConfig, OutputFormat, ScanMode};
    use std::time::Duration;

    #[tokio::test]
    async fn parses_lines() {
        let spec = parse_target("[::1]:443").unwrap();
        assert_eq!(spec.port, 443);
        assert_eq!(spec.host, "::1");
    }

    #[tokio::test]
    async fn surfaces_input_errors() {
        let cfg = crate::model::Config {
            target: None,
            input: Some("/nonexistent/targets.txt".into()),
            concurrency: 1,
            rate: 1,
            connect_timeout: Duration::from_millis(10),
            read_timeout: Duration::from_millis(10),
            overall_timeout: Duration::from_millis(10),
            max_bytes: 10,
            mode: ScanMode::Passive,
            output: OutputConfig {
                format: OutputFormat::Pretty,
            },
        };

        let (mut stream, sources) = stream_targets(&cfg).await.unwrap();
        assert!(stream.next().await.is_none());
        let err = sources.wait().await.unwrap_err();
        assert!(err.to_string().contains("cannot open input"));
    }
}
