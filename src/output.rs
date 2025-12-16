use crate::model::{
    Banner, Fingerprint, OutputConfig, OutputFormat, ScanOutcome, Status, Target, TcpMeta,
};
use std::io::{BufWriter, Write};
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct OutputSink {
    inner: std::sync::Arc<OutputInner>,
}

struct OutputInner {
    tx: mpsc::UnboundedSender<OutputCommand>,
}

enum OutputCommand {
    Emit(ScanOutcome),
}

impl OutputSink {
    pub fn new(cfg: OutputConfig) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let cfg_clone = cfg.clone();

        tokio::task::spawn_blocking(move || run_writer(cfg_clone, rx));

        Ok(Self {
            inner: std::sync::Arc::new(OutputInner { tx }),
        })
    }

    pub async fn emit(&self, outcome: ScanOutcome) {
        if self.inner.tx.send(OutputCommand::Emit(outcome)).is_err() {
            eprintln!("output worker not available; dropping scan outcome");
        }
    }

    pub async fn emit_error(&self, target: Target, error: String) {
        let view = target.view();
        let outcome = ScanOutcome {
            target: view,
            status: Status::Error,
            tcp: TcpMeta {
                connect_ms: None,
                error: Some(error.clone()),
            },
            banner: Banner {
                raw_hex: String::new(),
                printable: String::new(),
                truncated: false,
            },
            fingerprint: Fingerprint {
                protocol: None,
                score: 0.0,
                fields: Default::default(),
            },
        };
        self.emit(outcome).await;
    }
}

fn run_writer(cfg: OutputConfig, mut rx: mpsc::UnboundedReceiver<OutputCommand>) {
    let stdout = std::io::stdout();
    let mut writer = BufWriter::new(stdout);

    while let Some(cmd) = rx.blocking_recv() {
        if let Err(err) = match cmd {
            OutputCommand::Emit(outcome) => write_outcome(&cfg, &mut writer, outcome),
        } {
            eprintln!("failed to write scan outcome: {err}");
        }
    }

    let _ = writer.flush();
}

fn write_outcome(
    cfg: &OutputConfig,
    writer: &mut BufWriter<std::io::Stdout>,
    outcome: ScanOutcome,
) -> anyhow::Result<()> {
    match cfg.format {
        OutputFormat::Jsonl => {
            let line = serde_json::to_string(&outcome)?;
            writeln!(writer, "{line}")?;
        }
        OutputFormat::Pretty => {
            writeln!(
                writer,
                "{} {} -> {}",
                outcome.target.host,
                outcome.target.port,
                outcome.status_text()
            )?;
            writeln!(writer, "  banner: {}", outcome.banner.printable)?;
        }
    }

    writer.flush()?;
    Ok(())
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
