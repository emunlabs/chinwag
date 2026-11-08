// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! One owner clock, including its first bind and first close futures. A timeout
//! is unconfirmed retirement, never proof that dropping Iroh joined its tasks.
use crate::runtime::{Result, RuntimeError};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::{Instant, sleep_until, timeout_at};

#[derive(Clone)]
pub(crate) struct OwnerBudget {
    pub(crate) work_until: Instant,
    pub(crate) close_until: Instant,
    stop: Arc<AtomicBool>,
}
impl OwnerBudget {
    pub(crate) fn new(lifetime: Duration, stop: Arc<AtomicBool>) -> Self {
        let close_until = Instant::now() + lifetime;
        Self {
            work_until: close_until - Duration::from_secs(10),
            close_until,
            stop,
        }
    }
    pub(crate) fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire) || Instant::now() >= self.work_until
    }
    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub(crate) async fn work_stopped(&self) {
        loop {
            if self.stopped() {
                return;
            }
            tokio::select! {
                _ = sleep_until(self.work_until) => return,
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    }
    pub(crate) async fn finish_close<F: Future<Output = ()>>(&self, close: F) -> Result<()> {
        // Keep polling this FIRST close. Iroh sets its closing bit before
        // draining; a second close can return immediately without joining it.
        timeout_at(
            self.close_until
                .min(Instant::now() + Duration::from_secs(10)),
            close,
        )
        .await
        .map_err(|_| RuntimeError)
    }
    pub(crate) async fn bind<B, P, C, F>(&self, bind: B, close_late: C) -> Result<P>
    where
        B: Future<Output = Result<P>>,
        C: FnOnce(P) -> F,
        F: Future<Output = ()>,
    {
        tokio::pin!(bind);
        let result = tokio::select! {
            biased;
            _ = self.work_stopped() => None,
            result = &mut bind => Some(result),
        };
        if let Some(result) = result {
            let pair = result?;
            if !self.stopped() {
                return Ok(pair);
            }
            self.finish_close(close_late(pair)).await?;
        } else {
            // A late successful bind is closed, never advertised as ready.
            let pair = timeout_at(
                self.close_until
                    .min(Instant::now() + Duration::from_secs(10)),
                &mut bind,
            )
            .await
            .map_err(|_| RuntimeError)??;
            self.finish_close(close_late(pair)).await?;
        }
        Err(RuntimeError)
    }
    #[cfg(test)]
    pub(crate) fn test(work: Duration, drain: Duration) -> Self {
        let work_until = Instant::now() + work;
        Self {
            work_until,
            close_until: work_until + drain,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    #[tokio::test]
    async fn stalled_original_bind_ends_unconfirmed_at_absolute_owner_deadline() {
        let budget = OwnerBudget::test(Duration::from_millis(15), Duration::from_millis(35));
        let start = Instant::now();
        let result = budget
            .bind(std::future::pending::<Result<()>>(), |_| async {})
            .await;
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[tokio::test]
    async fn late_bind_is_closed_once_and_never_becomes_ready() {
        let budget = OwnerBudget::test(Duration::from_millis(10), Duration::from_millis(150));
        let closed = AtomicUsize::new(0);
        let bind = async {
            tokio::time::sleep(Duration::from_millis(35)).await;
            Ok(())
        };
        assert!(
            budget
                .bind(bind, |_| async {
                    closed.fetch_add(1, Ordering::AcqRel);
                })
                .await
                .is_err()
        );
        assert_eq!(closed.load(Ordering::Acquire), 1);
    }
    #[tokio::test]
    async fn stalled_first_close_is_not_retried_or_reported_clean() {
        let budget = OwnerBudget::test(Duration::from_millis(5), Duration::from_millis(35));
        let calls = AtomicUsize::new(0);
        let close = async {
            calls.fetch_add(1, Ordering::AcqRel);
            std::future::pending::<()>().await;
        };
        assert!(budget.finish_close(close).await.is_err());
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }
}
