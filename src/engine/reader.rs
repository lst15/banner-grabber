use crate::model::Banner;
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
    ) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.max_bytes];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut buf[total..]).await?;
            if n == 0 {
                break;
            }
            total += n;
            if total >= self.max_bytes {
                break;
            }
            if let Some(pos) = find_delimiter(&buf[..total], extra_delimiter) {
                total = pos;
                break;
            }
        }
        buf.truncate(total);
        Ok(buf)
    }

    pub fn render(&self, bytes: Vec<u8>) -> Banner {
        let truncated = bytes.len() >= self.max_bytes;
        let raw_hex = crate::util::hex::to_hex(&bytes);
        let printable = crate::util::sanitize_text(&bytes);
        Banner {
            raw_hex,
            printable,
            truncated,
        }
    }
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
        if let Some(pos) = buf
            .windows(delim.len())
            .position(|window| window == delim)
        {
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
        assert!(res.ends_with(b"\r\n\r\n"));
    }

    #[tokio::test]
    async fn stops_on_single_newline() {
        let mut reader = BannerReader::new(64);
        let mut data: &[u8] = b"VTUN server ver 3.X 12/31/2013\n...";
        let res = reader.read(&mut data, None).await.unwrap();
        assert!(res.ends_with(b"\n"));
        assert_eq!(res, b"VTUN server ver 3.X 12/31/2013\n");
    }
}
