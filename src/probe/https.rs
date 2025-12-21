use super::Prober;
use crate::engine::reader::{BannerReader, ReadResult};
use crate::model::{Config, Target};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(super) struct HttpsProbe;

#[async_trait]
impl Prober for HttpsProbe {
    fn name(&self) -> &'static str {
        "https"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        &[]
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(target.resolved.port(), 443 | 8443)
    }

    async fn execute(
        &self,
        stream: TcpStream,
        cfg: &Config,
        target: &Target,
    ) -> anyhow::Result<ReadResult> {
        let connector = https_connector()?;

        let host = target.original.host.as_str();
        let sni_host = if host.is_empty() {
            target.resolved.ip().to_string()
        } else {
            host.to_string()
        };

        let mut tls_stream = connector
            .connect(&sni_host, stream)
            .await
            .with_context(|| format!("TLS handshake failed for host {host}"))?;

        let host_header = if host.is_empty() {
            sni_host.as_str()
        } else {
            host
        };
        let request = format!("GET / HTTP/1.0\r\nHost: {host_header}\r\n\r\n");
        tls_stream
            .write_all(request.as_bytes())
            .await
            .context("failed to write HTTPS request")?;

        let mut reader = BannerReader::new(cfg.max_bytes, cfg.read_timeout);
        let mut result = reader.read(&mut tls_stream, None).await?;

        if let Some(content_length) = parse_content_length(&result.bytes) {
            let header_end = find_header_end(&result.bytes).unwrap_or(result.bytes.len());
            let already_have_body = result.bytes.len().saturating_sub(header_end);
            // Respect the remaining budget when attempting to pull the body.
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
                match tokio::time::timeout(cfg.read_timeout, tls_stream.read(&mut buf[read..]))
                    .await
                {
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
                // We successfully pulled the entire expected body.
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

#[cfg(test)]
mod tests {
    use super::{find_header_end, parse_content_length};

    #[test]
    fn parses_length_without_delimiter() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n";
        assert_eq!(parse_content_length(headers), Some(12));
    }

    #[test]
    fn finds_header_end_with_body() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBody";
        assert_eq!(find_header_end(resp), Some(38));
    }
}

fn https_connector() -> anyhow::Result<&'static tokio_native_tls::TlsConnector> {
    static CONNECTOR: OnceLock<anyhow::Result<tokio_native_tls::TlsConnector>> = OnceLock::new();

    CONNECTOR
        .get_or_init(|| {
            let mut builder = native_tls::TlsConnector::builder();
            // We only need to complete the handshake to read the banner, so accept
            // any certificate and hostname.
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
            builder
                .build()
                .map(tokio_native_tls::TlsConnector::from)
                .map_err(|e| anyhow!(e))
        })
        .as_ref()
        .map_err(|err| anyhow!("failed to create TLS connector: {err}"))
}
