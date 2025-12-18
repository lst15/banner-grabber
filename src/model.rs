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
    pub concurrency: usize,
    pub rate: u32,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub overall_timeout: Duration,
    pub max_bytes: usize,
    pub mode: ScanMode,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum ScanMode {
    Passive,
    Active,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: OutputFormat,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub target: TargetView,
    pub status: Status,
    pub tcp: TcpMeta,
    pub banner: Banner,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Status {
    Open,
    Timeout,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
}
