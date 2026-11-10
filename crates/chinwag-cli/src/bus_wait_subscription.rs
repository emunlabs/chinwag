//! Bounded process-local change subscriptions. These carry no task authority.
#![forbid(unsafe_code)]
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::sync::broadcast;

pub struct Subscriptions<T: Clone> {
    entries: BTreeMap<String, (Instant, broadcast::Receiver<T>)>,
}
impl<T: Clone> Default for Subscriptions<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}
impl<T: Clone> Subscriptions<T> {
    pub fn register(
        &mut self,
        id: &str,
        lifetime: Duration,
        sender: &broadcast::Sender<T>,
    ) -> bool {
        self.entries
            .retain(|_, (expiry, _)| *expiry > Instant::now());
        if id.len() != 64
            || !id.bytes().all(|b| b.is_ascii_hexdigit())
            || lifetime.is_zero()
            || lifetime > Duration::from_secs(3600)
            || self.entries.len() >= 64
            || self.entries.contains_key(id)
        {
            return false;
        }
        // Receiver exists before registration is acknowledged and before the
        // caller opens its catch-up snapshot. No mark substitutes for this.
        self.entries
            .insert(id.into(), (Instant::now() + lifetime, sender.subscribe()));
        true
    }
    pub fn take(&mut self, id: &str) -> Option<broadcast::Receiver<T>> {
        let (expiry, receiver) = self.entries.remove(id)?;
        (expiry > Instant::now()).then_some(receiver)
    }
    pub fn cancel(&mut self, id: &str) {
        self.entries.remove(id);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn r1_subscription_precedes_catchup_and_boundary_arrival_survives_once() {
        let (sender, _) = broadcast::channel(2);
        let mut subscriptions = Subscriptions::default();
        let id = "a".repeat(64);
        assert!(subscriptions.register(&id, Duration::from_secs(2), &sender));
        // Deterministic boundary: register -> arrival/rotation -> catch-up.
        assert_eq!(sender.send("boundary-original").unwrap(), 1);
        let mut receiver = subscriptions.take(&id).unwrap();
        assert_eq!(receiver.recv().await.unwrap(), "boundary-original");
        assert!(receiver.try_recv().is_err());
        assert!(subscriptions.take(&id).is_none());
        assert!(subscriptions.register(&id, Duration::from_secs(2), &sender));
        assert!(!subscriptions.register(&id, Duration::from_secs(2), &sender));
        subscriptions.cancel(&id);
        assert!(subscriptions.take(&id).is_none());
    }
}
