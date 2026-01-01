use crate::model::{
    Diagnostics, Fingerprint, OutputConfig, Protocol, ScanOutcome, Status, Target, TcpMeta,
};
use crate::util::now_iso8601;
use tokio::sync::mpsc;

use super::sink::OutputSink;

#[derive(Clone)]
pub struct OutputChannel {
    inner: std::sync::Arc<OutputInner>,
}

struct OutputInner {
    tx: tokio::sync::Mutex<Option<mpsc::Sender<OutputCommand>>>,
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

enum OutputCommand {
    Emit(ScanOutcome),
}

impl OutputChannel {
    pub fn new(cfg: OutputConfig) -> anyhow::Result<Self> {
        let (tx, mut rx) = mpsc::channel(1024);
        let handle = tokio::task::spawn_blocking(move || {
            let mut sink = OutputSink::new(cfg);
            while let Some(cmd) = rx.blocking_recv() {
                if let Err(err) = match cmd {
                    OutputCommand::Emit(outcome) => sink.write_outcome(outcome),
                } {
                    eprintln!("failed to write scan outcome: {err}");
                }
            }
            sink.flush();
        });

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

    pub async fn emit_error(
        &self,
        target: Target,
        protocol: &Protocol,
        error: String,
    ) -> anyhow::Result<()> {
        let view = target.view();
        let outcome = ScanOutcome {
            target: view,
            status: Status::Error,
            tcp: TcpMeta {
                connect_ms: None,
                error: Some(error.clone()),
            },
            banner: Default::default(),
            timestamp: now_iso8601(),
            ttl: None,
            webdriver: None,
            tls_info: None,
            fingerprint: Fingerprint::from_protocol(protocol),
            diagnostics: Some(Diagnostics {
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
