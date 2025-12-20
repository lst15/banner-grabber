use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::clients::session::ClientSession;
use crate::clients::Client;

pub(crate) struct FtpClient;

#[async_trait]
impl Client for FtpClient {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 21
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);
        let greeting = session.read_with_result(stream, None).await?;

        let mut logged_in = false;
        let attempts = [
            ("anonymous", "anonymous"),
            ("anonymous", ""),
            ("ftp", "ftp"),
            ("ftp", "anonymous"),
        ];

        for (user, pass) in attempts {
            // LOGIN ANÔNIMO
            session
                .send(stream, format!("USER {}\r\n", user).as_bytes())
                .await?;
            let user_res = session.read_with_result(stream, None).await?;

            if is_login_success(&user_res.bytes) {
                logged_in = true;
                break;
            }

            if requires_password(&user_res.bytes) {
                session
                    .send(stream, format!("PASS {}\r\n", pass).as_bytes())
                    .await?;
                let pass_res = session.read_with_result(stream, None).await?;

                if is_login_success(&pass_res.bytes) {
                    logged_in = true;
                    break;
                }
            }
        }

        if logged_in {
            for command in [
                "SYST\r\n",
                "FEAT\r\n",
                "STAT\r\n",
                "PWD\r\n",
                "HELP SITE\r\n",
                "HELP\r\n",
            ] {
                session.send(stream, command.as_bytes()).await?;
                session.read(stream, None).await?;
            }
        } else {
            // Ainda coletamos detalhes básicos do servidor mesmo sem autenticação
            if !is_login_success(&greeting.bytes) {
                session.read(stream, None).await.ok();
            }
        }

        Ok(session.finish())
    }
}

fn status_code(bytes: &[u8]) -> Option<u16> {
    let first_line = bytes.split(|b| *b == b'\n').next()?;
    let trimmed_start = first_line
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .copied()
        .collect::<Vec<u8>>();

    if trimmed_start.len() < 3 {
        return None;
    }

    if trimmed_start[0..3].iter().all(|b| b.is_ascii_digit()) {
        let digits = std::str::from_utf8(&trimmed_start[0..3]).ok()?;
        return digits.parse().ok();
    }

    None
}

fn is_login_success(bytes: &[u8]) -> bool {
    matches!(status_code(bytes), Some(230))
}

fn requires_password(bytes: &[u8]) -> bool {
    matches!(status_code(bytes), Some(331) | Some(332))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_code_from_first_line() {
        assert_eq!(status_code(b"220-Welcome\n220 continue"), Some(220));
        assert_eq!(status_code(b"   331 Password required"), Some(331));
        assert_eq!(status_code(b"garbled"), None);
    }

    #[test]
    fn detects_login_outcomes() {
        assert!(is_login_success(b"230 Logged in"));
        assert!(requires_password(b"331 Please specify the password."));
        assert!(!requires_password(b"530 Permission denied"));
    }
}
