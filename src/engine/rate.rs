use rand::{thread_rng, Rng};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    permits: Arc<Semaphore>,
    fill_rate: u32,
    last_refill: Arc<tokio::sync::Mutex<Instant>>,
    jitter_enabled: bool,
    refill_interval: Duration,
}

impl RateLimiter {
    pub fn new(fill_rate: u32) -> Self {
        Self::with_jitter(fill_rate, true)
    }

    pub fn with_jitter(fill_rate: u32, jitter_enabled: bool) -> Self {
        Self::with_jitter_and_interval(fill_rate, jitter_enabled, Duration::from_secs(1))
    }

    pub fn with_jitter_and_interval(
        fill_rate: u32,
        jitter_enabled: bool,
        refill_interval: Duration,
    ) -> Self {
        let permits = Arc::new(Semaphore::new(fill_rate as usize));
        Self {
            permits,
            fill_rate,
            last_refill: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            jitter_enabled,
            refill_interval,
        }
    }

    pub async fn acquire(&self) {
        loop {
            self.refill().await;
            if let Ok(permit) = self.permits.clone().try_acquire_owned() {
                permit.forget();
                return;
            }

            let mut wait_for = self.time_until_refill().await;
            let jitter = self.jitter_delay();
            if jitter > Duration::ZERO {
                wait_for += jitter;
            }

            sleep(wait_for).await;
        }
    }

    async fn refill(&self) {
        let mut guard = self.last_refill.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*guard);
        if elapsed >= self.refill_interval {
            let to_add = self
                .fill_rate
                .saturating_sub(self.permits.available_permits() as u32);
            if to_add > 0 {
                self.permits.add_permits(to_add as usize);
            }
            *guard = now;
        }
    }

    async fn time_until_refill(&self) -> Duration {
        let guard = self.last_refill.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*guard);
        self.refill_interval.saturating_sub(elapsed)
    }

    fn jitter_delay(&self) -> Duration {
        if !self.jitter_enabled {
            Duration::ZERO
        } else {
            let mut rng = thread_rng();
            Duration::from_millis(rng.gen_range(5..20))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, timeout};

    #[tokio::test]
    async fn acquire_returns_immediately_when_permits_available() {
        let limiter = RateLimiter::with_jitter_and_interval(2, true, Duration::from_millis(50));

        let first = timeout(Duration::from_millis(10), limiter.acquire()).await;
        assert!(first.is_ok());

        let second = timeout(Duration::from_millis(10), limiter.acquire()).await;
        assert!(second.is_ok());
    }

    #[tokio::test]
    async fn acquire_waits_for_refill_when_exhausted() {
        let limiter = RateLimiter::with_jitter_and_interval(1, false, Duration::from_millis(50));

        limiter.acquire().await;

        let pending = timeout(Duration::from_millis(20), limiter.acquire()).await;
        assert!(pending.is_err());

        sleep(Duration::from_millis(60)).await;

        let after_refill = timeout(Duration::from_millis(20), limiter.acquire()).await;
        assert!(after_refill.is_ok());
    }
}
