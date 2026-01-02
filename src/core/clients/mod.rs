use crate::core::engine::reader::ReadResult;
use crate::core::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

pub mod session;

#[async_trait]
pub trait Client: Send + Sync {
    fn name(&self) -> &'static str;
    #[allow(dead_code)]
    fn matches(&self, target: &Target) -> bool;

    async fn execute(&self, stream: &mut TcpStream, cfg: &Config) -> anyhow::Result<ReadResult>;
}

#[async_trait]
pub trait UdpClient: Send + Sync {
    fn name(&self) -> &'static str;
    #[allow(dead_code)]
    fn matches(&self, target: &Target) -> bool;

    async fn execute(&self, target: &Target, cfg: &Config) -> anyhow::Result<ReadResult>;
}
