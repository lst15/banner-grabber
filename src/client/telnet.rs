use crate::model::{Config, Target};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::session::ClientSession;
use super::Client;

const IAC: u8 = 255; // Interpret as Command
const DO: u8 = 253;
const DONT: u8 = 254;
const WILL: u8 = 251;
const WONT: u8 = 252;
const SB: u8 = 250;
const SE: u8 = 240;

pub(super) struct TelnetClient;

#[async_trait]
impl Client for TelnetClient {
    fn name(&self) -> &'static str {
        "telnet"
    }

    fn matches(&self, target: &Target) -> bool {
        matches!(target.resolved.port(), 23 | 2323)
    }

    async fn execute(
        &self,
        stream: &mut TcpStream,
        cfg: &Config,
    ) -> anyhow::Result<crate::engine::reader::ReadResult> {
        let mut session = ClientSession::new(cfg);

        let initial = session.read_with_result(stream, None).await?;
        self.handle_negotiation(stream, &mut session, &initial.bytes)
            .await?;

        session.send(stream, b"\r\n").await?;

        let follow_up = session.read_with_result(stream, None).await?;
        self.handle_negotiation(stream, &mut session, &follow_up.bytes)
            .await?;

        session.read(stream, None).await?;

        Ok(session.finish())
    }
}

impl TelnetClient {
    async fn handle_negotiation(
        &self,
        stream: &mut TcpStream,
        session: &mut ClientSession,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let response = build_negotiation_response(payload);
        if !response.is_empty() {
            session.send(stream, &response).await?;
        }
        Ok(())
    }
}

fn build_negotiation_response(bytes: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != IAC {
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() {
            break;
        }
        match bytes[i + 1] {
            DO => {
                if i + 2 >= bytes.len() {
                    break;
                }
                response.extend_from_slice(&[IAC, WONT, bytes[i + 2]]);
                i += 3;
            }
            WILL => {
                if i + 2 >= bytes.len() {
                    break;
                }
                response.extend_from_slice(&[IAC, DONT, bytes[i + 2]]);
                i += 3;
            }
            SB => {
                i += 2;
                while i < bytes.len() {
                    if bytes[i] == IAC && (i + 1) < bytes.len() && bytes[i + 1] == SE {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            DONT | WONT => {
                if i + 2 >= bytes.len() {
                    break;
                }
                i += 3;
            }
            _ => {
                i += 2;
            }
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_negotiation_responses_for_do_and_will() {
        let payload = [IAC, DO, 1, IAC, WILL, 3];
        let response = build_negotiation_response(&payload);
        assert_eq!(response, [IAC, WONT, 1, IAC, DONT, 3]);
    }

    #[test]
    fn skips_subnegotiation_blocks() {
        let payload = [IAC, SB, 24, 1, 0, IAC, SE, IAC, DO, 31];
        let response = build_negotiation_response(&payload);
        assert_eq!(response, [IAC, WONT, 31]);
    }
}
