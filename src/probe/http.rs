use super::Prober;
use crate::engine::reader::BannerReader;
use crate::model::{Config, Target};
use anyhow::Context;
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub(super) struct HttpProbe;

#[async_trait]
impl Prober for HttpProbe {
    fn name(&self) -> &'static str {
        "http"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        &[]
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(target.resolved.port(), 80 | 443 | 8000 | 8080 | 8443)
    }

    async fn execute(
        &self,
        mut stream: TcpStream,
        cfg: &Config,
        target: &Target,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let host = target.original.host.as_str();
        let host_header = if host.is_empty() {
            target.resolved.ip().to_string()
        } else {
            host.to_string()
        };
        let request = format!("GET / HTTP/1.0\r\nHost: {host_header}\r\n\r\n");

        stream
            .write_all(request.as_bytes())
            .await
            .with_context(|| format!("failed to write probe {}", self.name()))?;

        let mut reader = BannerReader::new(cfg.max_bytes, cfg.read_timeout);
        let mut result = reader.read(&mut stream, self.expected_delimiter()).await?;

        if let Some(content_length) = parse_content_length(&result.bytes) {
            let header_end = find_header_end(&result.bytes).unwrap_or(result.bytes.len());
            let already_have_body = result.bytes.len().saturating_sub(header_end);
            let available = cfg.max_bytes.saturating_sub(result.bytes.len());
            let missing = content_length.saturating_sub(already_have_body);

            if available == 0 || missing == 0 {
                if missing > 0 {
                    result.truncated = true;
                    result.reason = crate::model::ReadStopReason::SizeLimit;
                }
                return Ok(result);
            }

            let expected = missing.min(available);
            let mut buf = vec![0u8; expected];
            let mut read = 0usize;

            while read < expected {
                match tokio::time::timeout(cfg.read_timeout, stream.read(&mut buf[read..])).await {
                    Ok(Ok(0)) => {
                        result.reason = crate::model::ReadStopReason::ConnectionClosed;
                        break;
                    }
                    Ok(Ok(n)) => {
                        read += n;
                    }
                    Ok(Err(err)) => return Err(err.into()),
                    Err(_) => {
                        result.reason = crate::model::ReadStopReason::Timeout;
                        break;
                    }
                }
            }

            if content_length > already_have_body + available {
                result.truncated = true;
                result.reason = crate::model::ReadStopReason::SizeLimit;
            } else if read == expected {
                result.reason = crate::model::ReadStopReason::ConnectionClosed;
            }

            result.bytes.extend_from_slice(&buf[..read]);
        }

        Ok(result)
    }
}

fn parse_content_length(bytes: &[u8]) -> Option<usize> {
    for line in bytes.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }

        if line
            .get(..15)
            .map(|prefix| prefix.eq_ignore_ascii_case(b"Content-Length:"))
            .unwrap_or(false)
        {
            let value = std::str::from_utf8(&line[15..]).ok()?.trim();
            if let Ok(len) = value.parse::<usize>() {
                return Some(len);
            }
        }
    }

    None
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
}
