use super::Prober;
use crate::model::Target;

pub(super) struct RedisProbe;

impl Prober for RedisProbe {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn probe_bytes(&self) -> &'static [u8] {
        b"PING\r\n"
    }

    fn matches(&self, target: &Target) -> bool {
        target.resolved.port() == 6379
    }
}
