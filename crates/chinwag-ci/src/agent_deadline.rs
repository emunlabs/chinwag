// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Conservative conversion of integer signed expiries. Sample monotonic time
//! first, then wall time; discard the entire uncertain fractional Unix second.
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

pub(crate) struct Sample {
    monotonic_before: Instant,
    unix: u64,
}
impl Sample {
    pub(crate) fn now() -> Result<Self, ()> {
        let monotonic_before = Instant::now();
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs();
        Ok(Self {
            monotonic_before,
            unix,
        })
    }
    pub(crate) fn unix(&self) -> u64 {
        self.unix
    }
    pub(crate) fn until(&self, expiry: u64) -> Result<Instant, ()> {
        let seconds = expiry
            .checked_sub(self.unix)
            .and_then(|n| n.checked_sub(1))
            .filter(|n| *n > 0)
            .ok_or(())?;
        self.monotonic_before
            .checked_add(Duration::from_secs(seconds))
            .ok_or(())
    }
    #[cfg(test)]
    pub(crate) fn fixture(monotonic_before: Instant, unix: u64) -> Self {
        Self {
            monotonic_before,
            unix,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_refreshes_in_the_last_fractional_second_have_no_provable_lifetime() {
        let before = Instant::now();
        // Integer expiry T=102; wall samples at 101.998 and 101.999 both
        // produce 101. Neither may invent a full extra monotonic second.
        let first = Sample::fixture(before, 101);
        let second = Sample::fixture(before + Duration::from_micros(1000), 101);
        assert!(first.until(102).is_err());
        assert!(second.until(102).is_err());
        assert!(Sample::fixture(before, 102).until(102).is_err());
        assert_eq!(
            Sample::fixture(before, 100).until(102).unwrap(),
            before + Duration::from_secs(1)
        );
        // Delayed wall sampling consumes time; it never moves the anchor later.
        assert!(
            Sample::fixture(before, 101).until(103).unwrap() <= before + Duration::from_secs(1)
        );
    }
}
