use crate::clients::UdpClient;
use crate::engine::reader::ReadResult;
use crate::model::{Config, ReadStopReason, Target};
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Active UPnP SSDP client that issues an M-SEARCH probe and captures the raw response.
pub struct UpnpClient;

#[async_trait]
impl UdpClient for UpnpClient {
    fn name(&self) -> &'static str {
        "upnp"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 1900
    }

    async fn execute(&self, target: &Target, cfg: &Config) -> anyhow::Result<ReadResult> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(target.resolved).await?;

        let host_header = format!("HOST: {}:{}", target.original.host, target.original.port);
        let probe = format!(
            "M-SEARCH * HTTP/1.1\r\n{host}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
            host = host_header
        );

        timeout(cfg.connect_timeout, socket.send(probe.as_bytes())).await??;

        let mut buf = vec![0u8; cfg.max_bytes.min(2048)];
        let recv_result = timeout(cfg.read_timeout, socket.recv(&mut buf)).await;

        match recv_result {
            Ok(Ok(n)) => {
                buf.truncate(n);
                Ok(ReadResult {
                    bytes: buf,
                    reason: ReadStopReason::ConnectionClosed,
                    truncated: n >= cfg.max_bytes,
                    tls_info: None,
                })
            }
            Ok(Err(err)) => Err(err.into()),
            Err(_) => Ok(ReadResult {
                bytes: Vec::new(),
                reason: ReadStopReason::Timeout,
                truncated: false,
                tls_info: None,
            }),
        }
    }
}
