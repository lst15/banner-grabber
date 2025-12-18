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
    tx: tokio::sync::Mutex<Option<mpsc::UnboundedSender<OutputCommand>>>,
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

enum OutputCommand {
    Emit(ScanOutcome),
}

impl OutputSink {
    pub fn new(cfg: OutputConfig) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let cfg_clone = cfg.clone();

        let handle = tokio::task::spawn_blocking(move || run_writer(cfg_clone, rx));

        Ok(Self {
            inner: std::sync::Arc::new(OutputInner {
                tx: tokio::sync::Mutex::new(Some(tx)),
                handle: tokio::sync::Mutex::new(Some(handle)),
            }),
        })
    }

    pub async fn emit(&self, outcome: ScanOutcome) {
        let guard = self.inner.tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            if tx.send(OutputCommand::Emit(outcome)).is_err() {
                eprintln!("output worker not available; dropping scan outcome");
            }
        } else {
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

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.inner.tx.lock().await.take();

        if let Some(handle) = self.inner.handle.lock().await.take() {
            handle
                .await
                .map_err(|err| anyhow::anyhow!("failed to join output worker: {err}"))?;
        }

        Ok(())
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
