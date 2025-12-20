mod binaries;
#[path = "line-based/mod.rs"]
mod line_based;
mod registry;
mod session;
mod stateful;

pub use binaries::{mongodb, mssql, mysql, postgres};
pub use line_based::{ftp, imap, memcached, mqtt, pop3, redis, smtp, telnet};
pub use binaries::ntp::NtpClient;
pub use registry::{client_for_target, udp_client_for_target, ClientRequest};
pub use stateful::{smb, ssh, vnc};

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

#[async_trait]
pub trait UdpClient: Send + Sync {
    fn name(&self) -> &'static str;
    fn matches(&self, target: &Target) -> bool;

    async fn execute(&self, target: &Target, cfg: &Config) -> anyhow::Result<ReadResult>;
}
