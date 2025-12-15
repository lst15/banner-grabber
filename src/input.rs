use crate::model::{Target, TargetSpec};
use anyhow::Context;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::lookup_host;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub fn stream_targets(cfg: &crate::model::Config) -> anyhow::Result<ReceiverStream<Target>> {
    let (tx, rx) = mpsc::channel(256);

    if let Some(spec) = cfg.target.clone() {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = resolve_and_send(spec, tx).await;
        });
    }

    if let Some(path) = cfg.input.clone() {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(err) = read_file(path, tx).await {
                tracing::error!(error = %err, "failed to read input file");
            }
        });
    }

    drop(tx);
    Ok(ReceiverStream::new(rx))
}

async fn read_file(path: String, tx: mpsc::Sender<Target>) -> anyhow::Result<()> {
    let file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("cannot open input {}", path))?;
    let mut reader = BufReader::new(file).lines();
    while let Some(line) = reader.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(spec) = parse_target(trimmed) {
            resolve_and_send(spec, tx.clone()).await?;
        } else {
            tracing::warn!(line = %trimmed, "skipping invalid target");
        }
    }
    Ok(())
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

    #[tokio::test]
    async fn parses_lines() {
        let spec = parse_target("[::1]:443").unwrap();
        assert_eq!(spec.port, 443);
        assert_eq!(spec.host, "::1");
    }
}
