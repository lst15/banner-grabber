use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::session::ClientSession;
use super::Client;

pub(super) struct VncClient;

#[async_trait]
impl Client for VncClient {
    fn name(&self) -> &'static str {
        "vnc"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 5900
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);

        let version_response = session.read_with_result(stream, Some(b"\n")).await?;

        if !version_response.bytes.is_empty() {
            session.send(stream, &version_response.bytes).await?;
        }

        let _ = session.read_with_result(stream, None).await?;

        Ok(session.finish())
    }
}
