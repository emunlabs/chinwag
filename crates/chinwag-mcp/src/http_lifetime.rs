//! Activity observations cannot construct or release the original HTTP owner.
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Default)]
pub(crate) struct HttpLifetime {
    closing: AtomicBool,
    frontends: AtomicUsize,
    handlers: AtomicUsize,
    #[cfg(test)]
    pub(crate) probe: Option<Arc<crate::http_probe::Probe>>,
}
enum Kind {
    Frontend,
    Handler,
}
pub(crate) struct Activity {
    lifetime: Arc<HttpLifetime>,
    kind: Kind,
}
impl HttpLifetime {
    #[cfg(test)]
    pub(crate) fn with_probe(probe: Arc<crate::http_probe::Probe>) -> Self {
        Self {
            probe: Some(probe),
            ..Self::default()
        }
    }
    fn enter(self: &Arc<Self>, kind: Kind) -> Result<Activity, &'static str> {
        if self.closing.load(Ordering::Acquire) {
            return Err("HTTP owner is closing");
        }
        let counter = match kind {
            Kind::Frontend => &self.frontends,
            Kind::Handler => &self.handlers,
        };
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| "HTTP activity count overflow")?;
        let activity = Activity {
            lifetime: self.clone(),
            kind,
        };
        if self.closing.load(Ordering::Acquire) {
            return Err("HTTP owner is closing");
        }
        Ok(activity)
    }
    pub(crate) fn frontend(self: &Arc<Self>) -> Result<Activity, &'static str> {
        self.enter(Kind::Frontend)
    }
    pub(crate) fn handler(self: &Arc<Self>) -> Result<Activity, &'static str> {
        self.enter(Kind::Handler)
    }
    pub(crate) fn close(&self) {
        self.closing.store(true, Ordering::Release)
    }
    pub(crate) fn counts(&self) -> (usize, usize) {
        (
            self.frontends.load(Ordering::Acquire),
            self.handlers.load(Ordering::Acquire),
        )
    }
}
impl Drop for Activity {
    fn drop(&mut self) {
        let counter = match self.kind {
            Kind::Frontend => &self.lifetime.frontends,
            Kind::Handler => &self.lifetime.handlers,
        };
        counter.fetch_sub(1, Ordering::AcqRel);
    }
}
