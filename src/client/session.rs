use crate::engine::reader::{BannerReader, ReadResult};
use crate::model::{Config, ReadStopReason};
use anyhow::Context;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use std::time::{Duration, Instant};

pub(super) struct ClientSession {
    reader: BannerReader,
    parts: Vec<ReadResult>,
    max_bytes: usize,
    truncated: bool,
    deadline: Instant,
    idle_timeout: Duration,
}

impl ClientSession {
    pub(super) fn new(cfg: &Config, deadline: Instant) -> Self {
        Self {
            reader: BannerReader::new(cfg.max_bytes, cfg.read_timeout),
            parts: Vec::new(),
            max_bytes: cfg.max_bytes,
            truncated: false,
            deadline,
            idle_timeout: cfg.read_timeout,
        }
    }

    pub(super) async fn read(
        &mut self,
        stream: &mut TcpStream,
        delimiter: Option<&[u8]>,
    ) -> anyhow::Result<bool> {
        let idle = match self.remaining_time() {
            Some(dur) if dur.is_zero() => {
                self.push_timeout();
                return Ok(true);
            }
            Some(dur) => dur,
            None => {
                self.push_timeout();
                return Ok(true);
            }
        };

        match self.reader.read_with_timeout(stream, delimiter, idle).await {
            Ok(res) => {
                self.truncated |= res.truncated;
                self.parts.push(res);
                Ok(self.deadline_exhausted())
            }
            Err(err) => Err(err.into()),
        }
    }

    pub(super) async fn send(
        &mut self,
        stream: &mut TcpStream,
        bytes: &[u8],
    ) -> anyhow::Result<()> {
        stream
            .write_all(bytes)
            .await
            .with_context(|| "failed to write client command")
    }

    pub(super) fn finish(mut self) -> ReadResult {
        let mut merged = Vec::new();
        let mut reason = ReadStopReason::NotStarted;

        for part in self.parts.drain(..) {
            reason = part.reason.clone();
            if merged.len() < self.max_bytes {
                let remaining = self.max_bytes - merged.len();
                let take = part.bytes.len().min(remaining);
                merged.extend_from_slice(&part.bytes[..take]);
                if take < part.bytes.len() {
                    self.truncated = true;
                }
            } else {
                self.truncated = true;
            }
        }

        let final_len = merged.len();
        ReadResult {
            bytes: merged,
            reason,
            truncated: self.truncated || final_len >= self.max_bytes,
        }
    }

    fn remaining_time(&self) -> Option<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .map(|remaining| remaining.min(self.idle_timeout))
    }

    fn deadline_exhausted(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn push_timeout(&mut self) {
        self.parts.push(ReadResult {
            bytes: Vec::new(),
            reason: ReadStopReason::Timeout,
            truncated: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_partial_reads_with_truncation() {
        let cfg = Config {
            target: None,
            input: None,
            concurrency: 1,
            rate: 1,
            connect_timeout: std::time::Duration::from_millis(100),
            read_timeout: std::time::Duration::from_millis(100),
            overall_timeout: std::time::Duration::from_millis(100),
            max_bytes: 5,
            mode: crate::model::ScanMode::Active,
            output: crate::model::OutputConfig {
                format: crate::model::OutputFormat::Jsonl,
            },
        };
        let mut session = ClientSession::new(&cfg, Instant::now() + cfg.overall_timeout);
        session.truncated = true;
        session.parts.push(ReadResult {
            bytes: b"hello".to_vec(),
            reason: ReadStopReason::Delimiter,
            truncated: false,
        });
        session.parts.push(ReadResult {
            bytes: b"world".to_vec(),
            reason: ReadStopReason::ConnectionClosed,
            truncated: false,
        });
        let result = session.finish();
        assert_eq!(result.bytes, b"hello".to_vec());
        assert!(result.truncated);
        assert_eq!(result.reason, ReadStopReason::ConnectionClosed);
    }
}
