use crate::model::{
    Banner, Fingerprint, OutputConfig, OutputFormat, ScanOutcome, Status, Target, TcpMeta,
};
use std::io::Write;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct OutputSink {
    cfg: OutputConfig,
    writer: std::sync::Arc<Mutex<std::io::Stdout>>, // stdout locked
}

impl OutputSink {
    pub fn new(cfg: OutputConfig) -> anyhow::Result<Self> {
        Ok(Self {
            cfg,
            writer: std::sync::Arc::new(Mutex::new(std::io::stdout())),
        })
    }

    pub async fn emit(&self, outcome: ScanOutcome) {
        match self.cfg.format {
            OutputFormat::Jsonl => {
                let line = serde_json::to_string(&outcome).unwrap();
                let mut guard = self.writer.lock().await;
                writeln!(&mut *guard, "{}", line).ok();
            }
            OutputFormat::Pretty => {
                let mut guard = self.writer.lock().await;
                writeln!(
                    &mut *guard,
                    "{} {} -> {}",
                    outcome.target.host,
                    outcome.target.port,
                    outcome.status_text()
                )
                .ok();
                writeln!(&mut *guard, "  banner: {}", outcome.banner.printable).ok();
            }
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

impl ScanOutcome {
    fn status_text(&self) -> &'static str {
        match self.status {
            Status::Open => "open",
            Status::Timeout => "timeout",
            Status::Error => "error",
        }
    }
}
