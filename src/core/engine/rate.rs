use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep_until, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    state: Arc<tokio::sync::Mutex<State>>,
    fill_rate: f64,
    capacity: f64,
}

struct State {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(fill_rate: u32) -> Self {
        let fill_rate = fill_rate.max(1) as f64;
        Self {
            state: Arc::new(tokio::sync::Mutex::new(State {
                tokens: fill_rate,
                last_refill: Instant::now(),
            })),
            capacity: fill_rate,
            fill_rate,
        }
    }

    pub async fn acquire(&self) {
        loop {
            let wait_until = {
                let mut state = self.state.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(state.last_refill);
                if elapsed > Duration::ZERO {
                    let to_add = elapsed.as_secs_f64() * self.fill_rate;
                    if to_add > 0.0 {
                        state.tokens = (state.tokens + to_add).min(self.capacity);
                        state.last_refill = now;
                    }
                }

                if state.tokens >= 1.0 {
                    state.tokens -= 1.0;
                    None
                } else {
                    let missing = 1.0 - state.tokens;
                    let wait_seconds = missing / self.fill_rate;
                    state.last_refill = now;
                    Some(now + Duration::from_secs_f64(wait_seconds))
                }
            };

            match wait_until {
                None => return,
                Some(when) => {
                    sleep_until(when).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;
    use std::time::Duration;
    use tokio::time::advance;

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_refills_in_smaller_steps() {
        let limiter = RateLimiter::new(4);

        for _ in 0..4 {
            limiter.acquire().await;
        }

        let next = tokio::spawn({
            let limiter = limiter.clone();
            async move {
                limiter.acquire().await;
            }
        });

        advance(Duration::from_millis(90)).await;
        assert!(!next.is_finished());

        advance(Duration::from_millis(90)).await;
        assert!(!next.is_finished());

        advance(Duration::from_millis(90)).await;
        assert!(next.await.is_ok());
    }
}
