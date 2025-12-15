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
}

impl RateLimiter {
    pub fn new(fill_rate: u32) -> Self {
        let permits = Arc::new(Semaphore::new(fill_rate as usize));
        Self {
            permits,
            fill_rate,
            last_refill: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        }
    }

    pub async fn acquire(&self) {
        self.refill().await;
        let _ = self.permits.acquire().await;
    }

    async fn refill(&self) {
        let mut guard = self.last_refill.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*guard);
        if elapsed >= Duration::from_secs(1) {
            let to_add = self
                .fill_rate
                .saturating_sub(self.permits.available_permits() as u32);
            if to_add > 0 {
                self.permits.add_permits(to_add as usize);
            }
            *guard = now;
        }
    }

    pub async fn sleep_jitter(&self) {
        let mut rng = thread_rng();
        let jitter_ms: u64 = rng.gen_range(5..20);
        sleep(Duration::from_millis(jitter_ms)).await;
    }
}
