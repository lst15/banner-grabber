use crate::core::clients::UdpClient;
use crate::core::engine::reader::ReadResult;
use crate::core::model::{Config, ReadStopReason, Target};
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Basic NTP client that issues a time request over UDP and captures the raw response.
pub struct NtpClient;

#[async_trait]
impl UdpClient for NtpClient {
    fn name(&self) -> &'static str {
        "ntp"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 123
    }

    async fn execute(&self, target: &Target, cfg: &Config) -> anyhow::Result<ReadResult> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(target.resolved).await?;

        // LI = 0, Version = 3, Mode = Client
        let mut packet = [0u8; 48];
        packet[0] = 0x1B;

        timeout(cfg.connect_timeout, socket.send(&packet)).await??;

        let mut buf = vec![0u8; cfg.max_bytes.min(512)];
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
