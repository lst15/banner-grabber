use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSpec {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub original: TargetSpec,
    pub resolved: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub target: Option<TargetSpec>,
    pub input: Option<String>,
    pub port_filter: Option<u16>,
    pub concurrency: usize,
    pub rate: u32,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub overall_timeout: Duration,
    pub max_bytes: usize,
    pub mode: ScanMode,
    pub protocol: Protocol,
    pub webdriver: bool,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum ScanMode {
    Passive,
    Active,
}

pub fn adjusted_connect_timeout(connect_timeout: Duration, mode: ScanMode, port: u16) -> Duration {
    if matches!(mode, ScanMode::Active) && port == 21 {
        // FTP servers are often slower to finish the TCP handshake due to
        // connection tracking and banner throttling. Give them extra time so
        // we don't misclassify healthy endpoints as timeouts in active mode.
        return connect_timeout.saturating_mul(4);
    }

    connect_timeout
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: OutputFormat,
}

#[derive(Clone, Debug, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ftp,
    Http,
    Https,
    Imap,
    Memcached,
    Mongodb,
    Mqtt,
    Mssql,
    Mysql,
    Pop3,
    Postgres,
    Redis,
    Smb,
    Smtp,
    Ssh,
    Telnet,
    Tls,
    Vnc,
    Ntp,
}

#[derive(Clone, Debug, Serialize, Deserialize, ValueEnum)]
pub enum OutputFormat {
    Jsonl,
    Pretty,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Jsonl => write!(f, "jsonl"),
            OutputFormat::Pretty => write!(f, "pretty"),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Protocol::Ftp => "ftp",
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Imap => "imap",
            Protocol::Memcached => "memcached",
            Protocol::Mongodb => "mongodb",
            Protocol::Mqtt => "mqtt",
            Protocol::Mssql => "mssql",
            Protocol::Mysql => "mysql",
            Protocol::Pop3 => "pop3",
            Protocol::Postgres => "postgres",
            Protocol::Redis => "redis",
            Protocol::Smb => "smb",
            Protocol::Smtp => "smtp",
            Protocol::Ssh => "ssh",
            Protocol::Telnet => "telnet",
            Protocol::Tls => "tls",
            Protocol::Vnc => "vnc",
            Protocol::Ntp => "ntp",
        };
        write!(f, "{}", label)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub target: TargetView,
    pub status: Status,
    pub tcp: TcpMeta,
    pub banner: Banner,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webdriver: Option<String>,
    pub fingerprint: Fingerprint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Diagnostics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetView {
    pub host: String,
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpMeta {
    pub connect_ms: Option<u128>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Banner {
    pub raw_hex: String,
    pub printable: String,
    pub truncated: bool,
    pub read_reason: ReadStopReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Diagnostics {
    pub stage: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
    pub protocol: Option<String>,
    pub score: f32,
    pub fields: BTreeMap<String, String>,
}

impl Fingerprint {
    pub fn from_protocol(protocol: &Protocol) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("source".into(), "user-provided".into());
        Fingerprint {
            protocol: Some(protocol.to_string()),
            score: 1.0,
            fields,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Status {
    Open,
    Timeout,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum ReadStopReason {
    #[default]
    NotStarted,
    ConnectionClosed,
    Delimiter,
    SizeLimit,
    Timeout,
}

impl Target {
    pub fn view(&self) -> TargetView {
        TargetView {
            host: self.original.host.clone(),
            addr: self.resolved.ip().to_string(),
            port: self.resolved.port(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_view_formats() {
        let target = Target {
            original: TargetSpec {
                host: "example".into(),
                port: 80,
            },
            resolved: "127.0.0.1:80".parse().unwrap(),
        };
        let view = target.view();
        assert_eq!(view.addr, "127.0.0.1");
    }

    #[test]
    fn extends_timeout_for_active_ftp() {
        let timeout = adjusted_connect_timeout(Duration::from_secs(1), ScanMode::Active, 21);
        assert_eq!(timeout, Duration::from_secs(4));
    }

    #[test]
    fn leaves_timeout_unchanged_for_other_modes_and_ports() {
        let timeout = adjusted_connect_timeout(Duration::from_secs(1), ScanMode::Passive, 21);
        assert_eq!(timeout, Duration::from_secs(1));

        let timeout = adjusted_connect_timeout(Duration::from_secs(1), ScanMode::Active, 22);
        assert_eq!(timeout, Duration::from_secs(1));
    }
}
