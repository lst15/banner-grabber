mod ftp;
mod imap;
mod memcached;
mod mongodb;
mod mqtt;
mod mssql;
mod mysql;
mod pop3;
mod postgres;
mod redis;
mod registry;
mod session;
mod smtp;
mod ssh;

pub use registry::{client_for_target, ClientRequest};

use crate::engine::reader::ReadResult;
use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

#[async_trait]
pub trait Client: Send + Sync {
    fn name(&self) -> &'static str;
    fn matches(&self, target: &Target) -> bool;

    async fn execute(&self, stream: &mut TcpStream, cfg: &Config) -> anyhow::Result<ReadResult>;
}
