use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::session::ClientSession;
use super::Client;

pub(super) struct SshClient;

#[async_trait]
impl Client for SshClient {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 22
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
        deadline: std::time::Instant,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg, deadline);
        if session.read(stream, Some(b"\n")).await? {
            return Ok(session.finish());
        }
        // Sending our identification string is optional; ignore errors if the server closes early.
        let _ = session.send(stream, b"SSH-2.0-banner-grabber\r\n").await;
        let _ = session.read(stream, None).await?;
        Ok(session.finish())
    }
}
