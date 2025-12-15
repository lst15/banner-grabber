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
            if let Some(pos) = find_delimiter(&buf[..total]) {
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

fn find_delimiter(buf: &[u8]) -> Option<usize> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos + 4);
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
        let res = reader.read(&mut data).await.unwrap();
        assert!(res.ends_with(b"\r\n\r\n"));
    }
}
