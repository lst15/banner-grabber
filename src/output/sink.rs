mod common;
mod http;
mod imap;
mod mssql;
mod mysql;
mod ssh;

use crate::model::{OutputConfig, OutputFormat, ScanOutcome, Status};
use serde::Serialize;
use serde_json::Value;
use std::io::{BufWriter, Write};

pub struct OutputSink {
    cfg: OutputConfig,
    writer: BufWriter<std::io::Stdout>,
}

#[derive(Serialize)]
struct StandardizedOutcome<'a> {
    ip: &'a str,
    timestamp: &'a str,
    port: u16,
    proto: &'a str,
    ttl: Option<u8>,
    data: Value,
}

impl OutputSink {
    pub fn new(cfg: OutputConfig) -> Self {
        Self {
            cfg,
            writer: BufWriter::new(std::io::stdout()),
        }
    }

    pub fn write_outcome(&mut self, outcome: ScanOutcome) -> anyhow::Result<()> {
        match self.cfg.format {
            OutputFormat::Jsonl => {
                let proto = outcome.fingerprint.protocol.as_deref().unwrap_or("unknown");
                let data = if matches!(proto, "http" | "https") {
                    http::http_data(&outcome, proto)
                } else if proto == "imap" {
                    imap::imap_data(&outcome)
                } else if matches!(proto, "mssql" | "ms-sql-s") {
                    mssql::mssql_data(&outcome)
                } else if proto == "mysql" {
                    mysql::mysql_data(&outcome)
                } else if proto == "ssh" {
                    ssh::ssh_data(&outcome)
                } else {
                    serde_json::json!(common::raw_banner_for_data(&outcome))
                };
                let formatted = StandardizedOutcome {
                    ip: &outcome.target.addr,
                    timestamp: &outcome.timestamp,
                    port: outcome.target.port,
                    proto,
                    ttl: outcome.ttl,
                    data,
                };
                let line = serde_json::to_string(&formatted)?;
                writeln!(self.writer, "{line}")?;
            }
            OutputFormat::Pretty => {
                writeln!(
                    self.writer,
                    "{} {} -> {}",
                    outcome.target.host,
                    outcome.target.port,
                    outcome.status_text()
                )?;
                writeln!(self.writer, "  banner: {}", outcome.banner.printable)?;
                if let Some(webdriver) = &outcome.webdriver {
                    writeln!(self.writer, "  webdriver: {}", webdriver)?;
                }
                if let Some(diag) = &outcome.diagnostics {
                    writeln!(
                        self.writer,
                        "  diagnostics: [{}] {}",
                        diag.stage, diag.message
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) {
        let _ = self.writer.flush();
    }
}

impl ScanOutcome {
    fn status_text(&self) -> &'static str {
        match self.status {
            Status::Open => "open",
            Status::Timeout => "timeout",
            Status::Error => "error",
        }
    }
}
