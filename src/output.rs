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
    tx: tokio::sync::Mutex<Option<mpsc::Sender<OutputCommand>>>,
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

enum OutputCommand {
    Emit(ScanOutcome),
}

impl OutputSink {
    pub fn new(cfg: OutputConfig) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel(1024);
        let cfg_clone = cfg.clone();

        let handle = tokio::task::spawn_blocking(move || run_writer(cfg_clone, rx));

        Ok(Self {
            inner: std::sync::Arc::new(OutputInner {
                tx: tokio::sync::Mutex::new(Some(tx)),
                handle: tokio::sync::Mutex::new(Some(handle)),
            }),
        })
    }

    pub async fn emit(&self, outcome: ScanOutcome) -> anyhow::Result<()> {
        let guard = self.inner.tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            tx.send(OutputCommand::Emit(outcome))
                .await
                .map_err(|err| anyhow::anyhow!("output worker not available: {err}"))?
        } else {
            anyhow::bail!("output worker not available; dropping scan outcome");
        }
        Ok(())
    }

    pub async fn emit_error(&self, target: Target, error: String) -> anyhow::Result<()> {
        let view = target.view();
        let outcome = ScanOutcome {
            target: view,
            status: Status::Error,
            tcp: TcpMeta {
                connect_ms: None,
                error: Some(error.clone()),
            },
            banner: Banner::default(),
            fingerprint: Fingerprint {
                protocol: None,
                score: 0.0,
                fields: Default::default(),
            },
            diagnostics: Some(crate::model::Diagnostics {
                stage: "pipeline".into(),
                message: error,
            }),
        };
        self.emit(outcome).await
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

fn run_writer(cfg: OutputConfig, mut rx: mpsc::Receiver<OutputCommand>) {
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
            if let Some(diag) = &outcome.diagnostics {
                writeln!(writer, "  diagnostics: [{}] {}", diag.stage, diag.message)?;
            }
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
