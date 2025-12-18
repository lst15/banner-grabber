use crate::model::OutputFormat;
use clap::{ArgAction, Parser, ValueEnum};
use std::fmt;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(author, version, about = "Async banner grabbing tool", long_about = None)]
pub struct Cli {
    /// Single host to scan
    #[arg(short = 'H', long = "host", value_name = "HOST")]
    pub host: Option<String>,

    /// Single port to scan
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    pub port: Option<u16>,

    /// File containing targets (one per line)
    #[arg(short = 'i', long = "input", value_name = "FILE")]
    pub input: Option<String>,

    /// Concurrency limit
    #[arg(long = "concurrency", default_value_t = 64)]
    pub concurrency: usize,

    /// New connections per second (token bucket fill rate)
    #[arg(long = "rate", default_value_t = 64)]
    pub rate: u32,

    /// Connect timeout in milliseconds
    #[arg(long = "connect-timeout", default_value_t = 1500)]
    pub connect_timeout_ms: u64,

    /// Read timeout in milliseconds
    #[arg(long = "read-timeout", default_value_t = 2000)]
    pub read_timeout_ms: u64,

    /// Overall timeout per target in milliseconds
    #[arg(long = "overall-timeout", default_value_t = 4000)]
    pub overall_timeout_ms: u64,

    /// Max bytes to capture from banner
    #[arg(long = "max-bytes", default_value_t = 4096)]
    pub max_bytes: usize,

    /// Mode: passive or active
    #[arg(long = "mode", default_value_t = Mode::Passive)]
    pub mode: Mode,

    /// Output format
    #[arg(long = "output", default_value_t = OutputFormat::Jsonl)]
    pub output: OutputFormat,

    /// Enable pretty logging output instead of JSONL
    #[arg(long = "pretty", action = ArgAction::SetTrue)]
    pub pretty: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Mode {
    Passive,
    Active,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Passive => write!(f, "passive"),
            Mode::Active => write!(f, "active"),
        }
    }
}

impl Cli {
    pub fn into_config(self) -> anyhow::Result<crate::model::Config> {
        if self.host.is_none() && self.input.is_none() {
            anyhow::bail!("either --host/--port or --input is required");
        }

        if self.host.is_some() && self.input.is_some() {
            anyhow::bail!("--host/--port and --input are mutually exclusive");
        }

        if self.concurrency == 0 {
            anyhow::bail!("concurrency must be greater than zero");
        }

        if self.rate == 0 {
            anyhow::bail!("rate must be greater than zero");
        }

        let target = match (self.host, self.port) {
            (Some(h), Some(p)) => Some(crate::model::TargetSpec { host: h, port: p }),
            (None, None) => None,
            _ => anyhow::bail!("--host and --port must be used together"),
        };

        Ok(crate::model::Config {
            target,
            input: self.input,
            concurrency: self.concurrency,
            rate: self.rate,
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            read_timeout: Duration::from_millis(self.read_timeout_ms),
            overall_timeout: Duration::from_millis(self.overall_timeout_ms),
            max_bytes: self.max_bytes.max(1),
            mode: match self.mode {
                Mode::Passive => crate::model::ScanMode::Passive,
                Mode::Active => crate::model::ScanMode::Active,
            },
            output: crate::model::OutputConfig {
                format: if self.pretty {
                    OutputFormat::Pretty
                } else {
                    self.output
                },
            },
        })
    }
}
