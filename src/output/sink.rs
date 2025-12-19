use crate::model::{OutputConfig, OutputFormat, ScanOutcome, Status};
use std::io::{BufWriter, Write};

pub struct OutputSink {
    cfg: OutputConfig,
    writer: BufWriter<std::io::Stdout>,
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
                let line = serde_json::to_string(&outcome)?;
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
