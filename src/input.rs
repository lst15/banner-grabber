use crate::model::{Target, TargetSpec};
use anyhow::Context;
use futures::{stream::FuturesUnordered, StreamExt};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::lookup_host;
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;

const FILE_RESOLUTION_CONCURRENCY: usize = 64;

pub fn stream_targets(
    cfg: &crate::model::Config,
) -> anyhow::Result<ReceiverStream<anyhow::Result<Target>>> {
    let (tx, rx) = mpsc::channel(256);

    if let Some(spec) = cfg.target.clone() {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(err) = resolve_and_send(spec, tx.clone()).await {
                let _ = tx.send(Err(err)).await;
            }
        });
    }

    if let Some(path) = cfg.input.clone() {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(err) = read_file(path, tx.clone()).await {
                tracing::error!(error = %err, "failed to read input file");
                let _ = tx.send(Err(err)).await;
            }
        });
    }

    drop(tx);
    Ok(ReceiverStream::new(rx))
}

async fn read_file(path: String, tx: mpsc::Sender<anyhow::Result<Target>>) -> anyhow::Result<()> {
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

async fn resolve_and_send(
    spec: TargetSpec,
    tx: mpsc::Sender<anyhow::Result<Target>>,
) -> anyhow::Result<()> {
    let lookup = lookup_host((spec.host.as_str(), spec.port)).await?;
    for addr in lookup {
        let target = Target {
            original: spec.clone(),
            resolved: addr,
        };
        tx.send(Ok(target)).await.ok();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_lines() {
        let spec = parse_target("[::1]:443").unwrap();
        assert_eq!(spec.port, 443);
        assert_eq!(spec.host, "::1");
    }
}
