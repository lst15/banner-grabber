use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::session::ClientSession;
use super::Client;

pub(super) struct SmtpClient;

#[async_trait]
impl Client for SmtpClient {
    fn name(&self) -> &'static str {
        "smtp"
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(target.resolved.port(), 25 | 587)
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        if session.read(stream, None).await? {
            return Ok(session.finish());
        }
        session.send(stream, b"EHLO banner-grabber\r\n").await?;
        if session.read(stream, None).await? {
            return Ok(session.finish());
        }
        session.send(stream, b"QUIT\r\n").await?;
        let _ = session.read(stream, None).await?;
        Ok(session.finish())
    }
}
