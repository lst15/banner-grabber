use crate::core::engine::reader::{BannerReader, ReadResult};
use crate::core::model::{Config, ReadStopReason};
use anyhow::Context;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub(crate) struct ClientSession {
    reader: BannerReader,
    parts: Vec<ReadResult>,
    max_bytes: usize,
    truncated: bool,
}

impl ClientSession {
    pub(crate) fn new(cfg: &Config) -> Self {
        Self {
            reader: BannerReader::new(cfg.max_bytes, cfg.read_timeout),
            parts: Vec::new(),
            max_bytes: cfg.max_bytes,
            truncated: false,
        }
    }

    pub(crate) async fn read(
        &mut self,
        stream: &mut TcpStream,
        delimiter: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let res = self.reader.read(stream, delimiter).await?;
        self.truncated |= res.truncated;
        self.parts.push(res);
        Ok(())
    }

    pub(crate) async fn read_with_result(
        &mut self,
        stream: &mut TcpStream,
        delimiter: Option<&[u8]>,
    ) -> anyhow::Result<ReadResult> {
        let res = self.reader.read(stream, delimiter).await?;
        self.truncated |= res.truncated;
        self.parts.push(res.clone());
        Ok(res)
    }

    pub(crate) async fn send(
        &mut self,
        stream: &mut TcpStream,
        bytes: &[u8],
    ) -> anyhow::Result<()> {
        stream
            .write_all(bytes)
            .await
            .with_context(|| "failed to write clients command")
    }

    pub(crate) fn append_metadata(&mut self, bytes: impl Into<Vec<u8>>) {
        let bytes = bytes.into();
        self.parts.push(ReadResult {
            bytes,
            reason: ReadStopReason::NotStarted,
            truncated: false,
            tls_info: None,
        });
    }

    pub(crate) fn finish(mut self) -> ReadResult {
        let mut merged = Vec::new();
        let mut reason = ReadStopReason::NotStarted;
        let mut tls_info = None;

        for part in self.parts.drain(..) {
            reason = part.reason.clone();
            if tls_info.is_none() {
                tls_info = part.tls_info.clone();
            }
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
            tls_info,
        }
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
            port_filter: None,
            concurrency: 1,
            rate: 1,
            connect_timeout: std::time::Duration::from_millis(100),
            read_timeout: std::time::Duration::from_millis(100),
            overall_timeout: std::time::Duration::from_millis(100),
            max_bytes: 5,
            mode: crate::core::model::ScanMode::Active,
            protocol: crate::core::model::Protocol::Http,
            webdriver: false,
            tech: false,
            output: crate::core::model::OutputConfig {
                format: crate::core::model::OutputFormat::Jsonl,
            },
        };
        let mut session = ClientSession::new(&cfg);
        session.truncated = true;
        session.parts.push(ReadResult {
            bytes: b"hello".to_vec(),
            reason: ReadStopReason::Delimiter,
            truncated: false,
            tls_info: None,
        });
        session.parts.push(ReadResult {
            bytes: b"world".to_vec(),
            reason: ReadStopReason::ConnectionClosed,
            truncated: false,
            tls_info: None,
        });
        let result = session.finish();
        assert_eq!(result.bytes, b"hello".to_vec());
        assert!(result.truncated);
        assert_eq!(result.reason, ReadStopReason::ConnectionClosed);
    }
}
