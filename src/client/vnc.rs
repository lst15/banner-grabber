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

        let security_response = session.read_with_result(stream, None).await?;

        if has_no_authentication(&security_response.bytes) {
            let _ = session.send(stream, &[1]).await;
            let _ = session.read(stream, None).await;
        }

        Ok(session.finish())
    }
}

fn has_no_authentication(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    if bytes.len() >= 4 {
        let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if value == 1 {
            return true;
        }
    }

    let security_types_len = bytes[0] as usize;
    let security_types = bytes.get(1..1 + security_types_len).unwrap_or(&[]);
    security_types.contains(&1)
}
