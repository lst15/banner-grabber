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
            let tx_err = tx.clone();
            if let Err(err) = resolve_and_send(spec, tx).await {
                let _ = tx_err.send(Err(err)).await;
            }
        });
    }

    if let Some(path) = cfg.input.clone() {
        let tx = tx.clone();
        let port_filter = cfg.port_filter;
        tokio::spawn(async move {
            let tx_err = tx.clone();
            if let Err(err) = read_file(path, port_filter, tx).await {
                tracing::error!(error = %err, "failed to read input file");
                let _ = tx_err.send(Err(err)).await;
            }
        });
    }

    drop(tx);
    Ok(ReceiverStream::new(rx))
}

async fn read_file(
    path: String,
    port_filter: Option<u16>,
    tx: mpsc::Sender<anyhow::Result<Target>>,
) -> anyhow::Result<()> {
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
            if let Some(filter_port) = port_filter {
                if spec.port != filter_port {
                    continue;
                }
            }
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
        tx.send(Ok(target))
            .await
            .map_err(anyhow::Error::from)
            .with_context(|| "failed to dispatch resolved target")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn parses_lines() {
        let spec = parse_target("[::1]:443").unwrap();
        assert_eq!(spec.port, 443);
        assert_eq!(spec.host, "::1");
    }

    #[tokio::test]
    async fn filters_targets_by_port_when_requested() {
        let mut file = NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(file, "127.0.0.1:80\n127.0.0.1:81").unwrap();

        let cfg = crate::model::Config {
            target: None,
            input: Some(file.path().to_string_lossy().into()),
            port_filter: Some(80),
            concurrency: 1,
            rate: 1,
            connect_timeout: std::time::Duration::from_millis(100),
            read_timeout: std::time::Duration::from_millis(100),
            overall_timeout: std::time::Duration::from_millis(200),
            max_bytes: 64,
            mode: crate::model::ScanMode::Passive,
            output: crate::model::OutputConfig {
                format: crate::model::OutputFormat::Jsonl,
            },
        };

        let mut stream = stream_targets(&cfg).unwrap();
        let mut targets = Vec::new();
        while let Some(res) = stream.next().await {
            let target = res.expect("target resolution should succeed");
            targets.push(target);
        }

        assert!(targets.iter().all(|t| t.original.port == 80));
        assert!(!targets.is_empty());
    }

    #[tokio::test]
    async fn bubbling_up_send_failures() {
        let spec = TargetSpec {
            host: "127.0.0.1".to_string(),
            port: 80,
        };
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        let err = resolve_and_send(spec, tx).await.unwrap_err();
        assert!(err.to_string().contains("failed to dispatch resolved target"));
    }
}
