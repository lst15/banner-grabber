use super::Prober;
use crate::engine::reader::{BannerReader, ReadResult};
use crate::model::{Config, Target};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use std::sync::OnceLock;
use tokio::io::AsyncWriteExt;
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
        reader.read(&mut tls_stream, None).await
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
