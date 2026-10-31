use crate::{Result, SteerError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[derive(Default)]
pub(crate) struct Admission {
    sequence: u64,
    flight: Option<Ticket>,
}
#[derive(Clone)]
pub(crate) struct Ticket {
    sequence: u64,
    id: String,
    live: Arc<AtomicBool>,
}
impl Ticket {
    pub(crate) fn permits(&self, id: &str) -> bool {
        self.id == id && self.live.load(Ordering::Acquire)
    }
}
impl Admission {
    pub(crate) fn prepare_sequence(&self) -> Result<u64> {
        if self.flight.is_some() {
            Err(SteerError::Busy)
        } else {
            Ok(self.sequence)
        }
    }
    pub(crate) fn admit(&mut self, expected: Option<u64>, id: &str) -> Result<Ticket> {
        if expected.is_some_and(|s| s != self.sequence) {
            return Err(SteerError::StaleTarget);
        }
        if self.flight.is_some() {
            return Err(SteerError::Busy);
        }
        let sequence = self.sequence.checked_add(1).ok_or(SteerError::Capacity)?;
        let ticket = Ticket {
            sequence,
            id: id.into(),
            live: Arc::new(AtomicBool::new(true)),
        };
        self.sequence = sequence;
        self.flight = Some(ticket.clone());
        Ok(ticket)
    }
    pub(crate) fn release(&mut self, ticket: &Ticket) -> bool {
        if self.flight.as_ref().is_some_and(|own| {
            own.sequence == ticket.sequence
                && own.id == ticket.id
                && Arc::ptr_eq(&own.live, &ticket.live)
        }) {
            ticket.live.store(false, Ordering::Release);
            self.flight = None;
            true
        } else {
            false
        }
    }
    pub(crate) fn invalidate(&mut self) {
        self.sequence = self.sequence.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_only_capture_and_stale_prepared_sequence() {
        let mut a = Admission::default();
        let original = a.prepare_sequence().unwrap();
        assert_eq!(a.prepare_sequence().unwrap(), original);
        let first = a.admit(Some(original), "first").unwrap();
        assert_eq!(a.prepare_sequence().err(), Some(SteerError::Busy));
        assert!(first.permits("first"));
        assert!(a.release(&first));
        assert_eq!(
            a.admit(Some(original), "old").err(),
            Some(SteerError::StaleTarget)
        );
    }
    #[test]
    fn admitted_ticket_survives_new_sequence_and_only_owner_can_release() {
        let mut a = Admission::default();
        let first = a.admit(None, "first").unwrap();
        a.invalidate();
        assert!(first.permits("first"));
        assert!(a.release(&first));
        let second = a.admit(None, "second").unwrap();
        assert!(!a.release(&first));
        assert!(second.permits("second"));
        assert!(!second.permits("first"));
        assert_eq!(a.prepare_sequence().err(), Some(SteerError::Busy));
        assert!(a.release(&second));
    }
}
