use crate::model::{Banner, ReadStopReason, TlsInfo};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

pub struct BannerReader {
    max_bytes: usize,
    idle_timeout: Duration,
}

impl BannerReader {
    pub fn new(max_bytes: usize, idle_timeout: Duration) -> Self {
        Self {
            max_bytes,
            idle_timeout,
        }
    }

    pub async fn read<T: AsyncReadExt + Unpin>(
        &mut self,
        stream: &mut T,
        extra_delimiter: Option<&[u8]>,
    ) -> anyhow::Result<ReadResult> {
        let mut buf = vec![0u8; self.max_bytes];
        let mut total = 0usize;
        let mut reason = ReadStopReason::ConnectionClosed;
        loop {
            match timeout(self.idle_timeout, stream.read(&mut buf[total..])).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    total += n;
                    if total >= self.max_bytes {
                        reason = ReadStopReason::SizeLimit;
                        break;
                    }
                    if find_delimiter(&buf[..total], extra_delimiter).is_some() {
                        reason = ReadStopReason::Delimiter;
                        break;
                    }
                }
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => {
                    reason = ReadStopReason::Timeout;
                    break;
                }
            }
        }
        buf.truncate(total);
        Ok(ReadResult {
            bytes: buf,
            reason,
            truncated: total >= self.max_bytes,
            tls_info: None,
        })
    }

    pub fn render(&self, result: ReadResult) -> Banner {
        let raw_hex = crate::util::hex::to_hex(&result.bytes);
        let printable = crate::util::sanitize_text(&result.bytes);
        Banner {
            raw_hex,
            printable,
            truncated: result.truncated,
            read_reason: result.reason,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReadResult {
    pub bytes: Vec<u8>,
    pub reason: ReadStopReason,
    pub truncated: bool,
    pub tls_info: Option<TlsInfo>,
}

fn find_delimiter(buf: &[u8], extra: Option<&[u8]>) -> Option<usize> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos + 4);
    }
    if let Some(delim) = extra {
        if delim.is_empty() {
            return None;
        }
        if let Some(pos) = buf.windows(delim.len()).position(|window| window == delim) {
            return Some(pos + delim.len());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn stops_on_delimiter() {
        let mut reader = BannerReader::new(64, Duration::from_millis(200));
        let mut data: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nBody";
        let res = reader.read(&mut data, None).await.unwrap();
        assert!(res.bytes.starts_with(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert_eq!(res.reason, ReadStopReason::Delimiter);
    }

    #[tokio::test]
    async fn retains_bytes_read_after_delimiter() {
        let mut reader = BannerReader::new(64, Duration::from_millis(200));
        let mut data: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nBody";
        let res = reader.read(&mut data, None).await.unwrap();
        assert_eq!(res.bytes, b"HTTP/1.1 200 OK\r\n\r\nBody");
        assert_eq!(res.reason, ReadStopReason::Delimiter);
    }

    #[tokio::test]
    async fn consumes_single_line_without_delimiter() {
        let mut reader = BannerReader::new(64, Duration::from_millis(200));
        let mut data: &[u8] = b"VTUN server ver 3.X 12/31/2013\n...";
        let res = reader.read(&mut data, None).await.unwrap();
        assert_eq!(res.reason, ReadStopReason::ConnectionClosed);
        assert_eq!(res.bytes, b"VTUN server ver 3.X 12/31/2013\n...");
    }

    #[tokio::test]
    async fn captures_multiline_banner_until_idle() {
        let mut reader = BannerReader::new(128, Duration::from_millis(50));
        let mut data: &[u8] = b"220-line1\r\n220-line2\r\n220 final\r\n";
        let res = reader.read(&mut data, None).await.unwrap();
        assert_eq!(res.bytes, b"220-line1\r\n220-line2\r\n220 final\r\n");
        assert_eq!(res.reason, ReadStopReason::ConnectionClosed);
    }
}
