use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::session::ClientSession;
use super::Client;

pub(super) struct FtpClient;

#[async_trait]
impl Client for FtpClient {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 21
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
        deadline: std::time::Instant,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg, deadline);
        if session.read(stream, None).await? {
            return Ok(session.finish());
        }
        session.send(stream, b"FEAT\r\n").await?;
        if session.read(stream, None).await? {
            return Ok(session.finish());
        }
        session.send(stream, b"SYST\r\n").await?;
        let _ = session.read(stream, None).await?;
        Ok(session.finish())
    }
}
