use super::https::{find_header_end, parse_content_length};
use super::Prober;
use crate::engine::reader::{BannerReader, ReadResult};
use crate::model::{Config, Target};
use anyhow::Context;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    ) -> anyhow::Result<ReadResult> {
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
            .context("failed to write HTTP request")?;

        let mut reader = BannerReader::new(cfg.max_bytes, cfg.read_timeout);
        let mut result = reader.read(&mut stream, None).await?;

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

#[cfg(test)]
mod tests {
    use super::HttpProbe;
    use crate::model::{Config, OutputConfig, OutputFormat, ScanMode, Target, TargetSpec};
    use crate::probe::registry::Prober;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn collects_body_with_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let n = socket.read(&mut buf).await.unwrap();
            let request = std::str::from_utf8(&buf[..n]).unwrap();
            assert!(request.contains("Host: example.com"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")
                .await
                .unwrap();
        });

        let cfg = Config {
            target: None,
            input: None,
            port_filter: None,
            concurrency: 1,
            rate: 1,
            connect_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(500),
            overall_timeout: Duration::from_secs(1),
            max_bytes: 128,
            mode: ScanMode::Active,
            protocol: crate::model::Protocol::Http,
            output: OutputConfig {
                format: OutputFormat::Pretty,
            },
        };

        let target = Target {
            original: TargetSpec {
                host: "example.com".into(),
                port: addr.port(),
            },
            resolved: SocketAddr::new("127.0.0.1".parse().unwrap(), addr.port()),
        };

        let stream = TcpStream::connect(addr).await.unwrap();
        let res = HttpProbe
            .execute(stream, &cfg, &target)
            .await
            .expect("http probe failed");

        let body = std::str::from_utf8(&res.bytes).unwrap();
        assert!(body.ends_with("Hello"));
    }
}
