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

        // read the list of supported security types
        let security = session.read_with_result(stream, None).await?;

        // If the server returned any security type, pick the first one to keep the
        // handshake flowing so we can capture the server banner/metadata.
        if let Some(first_type) = security.bytes.get(1) {
            session.send(stream, &[*first_type]).await?;

            // read the security result (success or failure)
            let _ = session.read_with_result(stream, None).await?;

            // request to share the desktop and read the server init data (includes the
            // server name/banner)
            session.send(stream, &[1u8]).await?;
            let _ = session.read_with_result(stream, None).await?;
        }

        Ok(session.finish())
    }
}
