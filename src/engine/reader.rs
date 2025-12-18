use crate::model::{Banner, ReadStopReason};
use tokio::io::AsyncReadExt;

pub struct BannerReader {
    max_bytes: usize,
}

impl BannerReader {
    pub fn new(max_bytes: usize) -> Self {
        Self { max_bytes }
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
            let n = stream.read(&mut buf[total..]).await?;
            if n == 0 {
                break;
            }
            total += n;
            if total >= self.max_bytes {
                reason = ReadStopReason::SizeLimit;
                break;
            }
            if let Some(pos) = find_delimiter(&buf[..total], extra_delimiter) {
                total = pos;
                reason = ReadStopReason::Delimiter;
                break;
            }
        }
        buf.truncate(total);
        Ok(ReadResult {
            bytes: buf,
            reason,
            truncated: total >= self.max_bytes,
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
}

fn find_delimiter(buf: &[u8], extra: Option<&[u8]>) -> Option<usize> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos + 4);
    }
    if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
        return Some(pos + 2);
    }
    if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        return Some(pos + 1);
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

    #[tokio::test]
    async fn stops_on_delimiter() {
        let mut reader = BannerReader::new(64);
        let mut data: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nBody";
        let res = reader.read(&mut data, None).await.unwrap();
        assert!(res.bytes.ends_with(b"\r\n\r\n"));
    }

    #[tokio::test]
    async fn stops_on_single_newline() {
        let mut reader = BannerReader::new(64);
        let mut data: &[u8] = b"VTUN server ver 3.X 12/31/2013\n...";
        let res = reader.read(&mut data, None).await.unwrap();
        assert!(res.bytes.ends_with(b"\n"));
        assert_eq!(res.bytes, b"VTUN server ver 3.X 12/31/2013\n");
    }
}
