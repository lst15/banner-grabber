use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::clients::session::ClientSession;
use crate::clients::Client;

pub(crate) struct MongodbClient;

#[async_trait]
impl Client for MongodbClient {
    fn name(&self) -> &'static str {
        "mongodb"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 27017
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);

        let mut document = Vec::new();
        document.extend_from_slice(&(19i32).to_le_bytes());
        document.push(0x10);
        document.extend_from_slice(b"isMaster");
        document.push(0x00);
        document.extend_from_slice(&1i32.to_le_bytes());
        document.push(0x00);

        let full_collection = b"admin.$cmd\0";
        let flags = 0i32;
        let number_to_skip = 0i32;
        let number_to_return = -1i32;

        let message_length = 16 + full_collection.len() + 4 + 4 + document.len();

        let mut packet = Vec::new();
        packet.extend_from_slice(&(message_length as i32).to_le_bytes());
        packet.extend_from_slice(&1i32.to_le_bytes());
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&2004i32.to_le_bytes());
        packet.extend_from_slice(&flags.to_le_bytes());
        packet.extend_from_slice(full_collection);
        packet.extend_from_slice(&number_to_skip.to_le_bytes());
        packet.extend_from_slice(&number_to_return.to_le_bytes());
        packet.extend_from_slice(&document);

        session.send(stream, &packet).await?;
        session.read(stream, None).await?;
        Ok(session.finish())
    }
}
