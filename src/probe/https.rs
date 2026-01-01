use super::Prober;
use crate::engine::reader::{BannerReader, ReadResult};
use crate::model::{Config, Target, TlsInfo};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509NameRef;
use std::pin::Pin;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

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

        let ssl = connector
            .configure()
            .context("failed to configure TLS connector")?
            .into_ssl(&sni_host)
            .context("failed to configure TLS SNI")?;
        let mut tls_stream =
            SslStream::new(ssl, stream).context("failed to initialize TLS stream")?;
        Pin::new(&mut tls_stream)
            .connect()
            .await
            .with_context(|| format!("TLS handshake failed for host {host}"))?;
        let tls_info = extract_tls_info(&tls_stream);

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
                result.tls_info = Some(tls_info);
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

        result.tls_info = Some(tls_info);
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

fn https_connector() -> anyhow::Result<&'static SslConnector> {
    static CONNECTOR: OnceLock<anyhow::Result<SslConnector>> = OnceLock::new();

    CONNECTOR
        .get_or_init(|| {
            let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| anyhow!(e))?;
            // We only need to complete the handshake to read the banner, so accept
            // any certificate and hostname.
            builder.set_verify(SslVerifyMode::NONE);
            Ok(builder.build())
        })
        .as_ref()
        .map_err(|err| anyhow!("failed to create TLS connector: {err}"))
}

fn extract_tls_info(stream: &SslStream<TcpStream>) -> TlsInfo {
    let ssl = stream.ssl();
    let mut info = TlsInfo {
        cipher: ssl
            .current_cipher()
            .map(|cipher| cipher.name().to_string())
            .unwrap_or_default(),
        version: ssl.version_str().to_string(),
        ..TlsInfo::default()
    };

    if let Some(cert) = ssl.peer_certificate() {
        info.cert_subject = format_x509_name(cert.subject_name());
        info.cert_issuer = format_x509_name(cert.issuer_name());
        info.cert_valid_from = cert.not_before().to_string();
        info.cert_valid_to = cert.not_after().to_string();
    }

    info
}

fn format_x509_name(name: &X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let key = entry.object().nid().short_name().unwrap_or("UNKNOWN");
        let value = entry
            .data()
            .as_utf8()
            .map(|val| val.to_string())
            .unwrap_or_default();
        if !value.is_empty() {
            parts.push(format!("{key}={value}"));
        }
    }
    parts.join(", ")
}
