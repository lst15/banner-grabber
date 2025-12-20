use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::clients::session::ClientSession;
use crate::clients::Client;

pub(crate) struct MqttClient;

#[async_trait]
impl Client for MqttClient {
    fn name(&self) -> &'static str {
        "mqtt"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 1883
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);

        let connect_packet: [u8; 14] = [
            0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x0a, 0x00, 0x00,
        ];

        session.send(stream, &connect_packet).await?;
        session.read(stream, None).await?;
        Ok(session.finish())
    }
}
