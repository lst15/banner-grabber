use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::clients::session::ClientSession;
use crate::clients::Client;

pub(crate) struct MssqlClient;

#[async_trait]
impl Client for MssqlClient {
    fn name(&self) -> &'static str {
        "ms-sql-s"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 1433
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);

        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x00, 0x00, 0x1a, 0x00, 0x06]);
        payload.extend_from_slice(&[0x01, 0x00, 0x20, 0x00, 0x01]);
        payload.extend_from_slice(&[0x02, 0x00, 0x21, 0x00, 0x01]);
        payload.extend_from_slice(&[0x03, 0x00, 0x22, 0x00, 0x04]);
        payload.extend_from_slice(&[0x04, 0x00, 0x26, 0x00, 0x01]);
        payload.push(0xff);
        payload.extend_from_slice(&[0x0f, 0x00, 0x00, 0x00, 0x00, 0x00]);
        payload.push(0x02);
        payload.push(0x00);
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        payload.push(0x00);

        let total_len = (payload.len() + 8) as u16;
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x12, 0x01]);
        packet.extend_from_slice(&total_len.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(0x00);
        packet.push(0x00);
        packet.extend_from_slice(&payload);

        session.send(stream, &packet).await?;
        session.read_with_result(stream, None).await?;
        Ok(session.finish())
    }
}
