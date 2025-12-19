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
        let Cli {
            host,
            port,
            input,
            concurrency,
            rate,
            connect_timeout_ms,
            read_timeout_ms,
            overall_timeout_ms,
            max_bytes,
            mode,
            output,
            pretty,
        } = self;

        if host.is_none() && input.is_none() {
            anyhow::bail!("either --host/--port or --input is required");
        }

        if host.is_some() && input.is_some() {
            anyhow::bail!("--host/--port and --input are mutually exclusive");
        }

        if concurrency == 0 {
            anyhow::bail!("concurrency must be greater than zero");
        }

        if rate == 0 {
            anyhow::bail!("rate must be greater than zero");
        }

        let target = match (host.clone(), port, input.is_some()) {
            (Some(h), Some(p), _) => Some(crate::model::TargetSpec { host: h, port: p }),
            (Some(_), None, _) => anyhow::bail!("--host and --port must be used together"),
            (None, Some(_), false) => anyhow::bail!("--host and --port must be used together"),
            (None, Some(_), true) => None,
            (None, None, _) => None,
        };

        let port_filter = if host.is_none() && input.is_some() {
            port
        } else {
            None
        };

        let ftp_connect_multiplier = if matches!(mode, Mode::Active)
            && matches!(port, Some(21))
        {
            // Active FTP handshakes can linger in connect; mirror the pipeline's
            // extended connect timeout so the overall timeout leaves room for it.
            4
        } else {
            1
        };

        let effective_connect_timeout_ms = connect_timeout_ms.saturating_mul(ftp_connect_multiplier);

        let min_overall_timeout_ms =
            effective_connect_timeout_ms.saturating_add(read_timeout_ms.saturating_mul(2));
        let overall_timeout_ms = overall_timeout_ms.max(min_overall_timeout_ms);

        Ok(crate::model::Config {
            target,
            input,
            concurrency,
            rate,
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            read_timeout: Duration::from_millis(read_timeout_ms),
            overall_timeout: Duration::from_millis(overall_timeout_ms),
            max_bytes: max_bytes.max(1),
            port_filter,
            mode: match mode {
                Mode::Passive => crate::model::ScanMode::Passive,
                Mode::Active => crate::model::ScanMode::Active,
            },
            output: crate::model::OutputConfig {
                format: if pretty {
                    OutputFormat::Pretty
                } else {
                    output
                },
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_minimum_overall_timeout() {
        let cli = Cli {
            host: Some("127.0.0.1".into()),
            port: Some(21),
            input: None,
            concurrency: 1,
            rate: 1,
            connect_timeout_ms: 1500,
            read_timeout_ms: 2000,
            overall_timeout_ms: 3000,
            max_bytes: 1024,
            mode: Mode::Active,
            output: OutputFormat::Jsonl,
            pretty: false,
        };

        let cfg = cli.into_config().expect("config should build");
        assert_eq!(cfg.overall_timeout, Duration::from_millis(10000));
    }

    #[test]
    fn allows_port_filter_with_input() {
        let cli = Cli {
            host: None,
            port: Some(443),
            input: Some("targets.txt".into()),
            concurrency: 4,
            rate: 10,
            connect_timeout_ms: 1000,
            read_timeout_ms: 2000,
            overall_timeout_ms: 4000,
            max_bytes: 2048,
            mode: Mode::Passive,
            output: OutputFormat::Jsonl,
            pretty: false,
        };

        let cfg = cli.into_config().expect("config should build");
        assert!(cfg.target.is_none());
        assert_eq!(cfg.port_filter, Some(443));
    }
}
