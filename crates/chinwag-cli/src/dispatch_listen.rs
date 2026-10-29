//! Dispatch admission and bounded QUIC serving. Production membership is an
//! owned live RoomSession; a discovered address cannot construct membership.
use super::dispatch_status::{Event, StatusStore};
use chinwag_swarm::{
    dispatch_wire::{self as wire, Payload, Refused, ReplayGuard, Request, Response},
    identity::Identity,
    room::RoomSession,
};
use iroh::{Endpoint, EndpointId, endpoint::Connection};
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const MAX_CONCURRENT: usize = 2;
pub const REQUESTS_PER_MINUTE: u32 = 6;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) trait Dispatcher: Send + Sync + 'static {
    fn dispatch(&self, payload: Payload, output: &mut dyn Write) -> u8;
}

pub(crate) struct LocalDispatcher {
    pub repo: std::path::PathBuf,
}
impl Dispatcher for LocalDispatcher {
    fn dispatch(&self, payload: Payload, output: &mut dyn Write) -> u8 {
        // CRDB is fixed by the Studio. The signed optional history/persona
        // context follows the existing stdin path without changing its runner.
        let Ok(bytes) = serde_json::to_vec(&payload) else {
            return 1;
        };
        crate::run_agent_dispatch(
            crate::AgentDispatchRequest {
                agent: None,
                item: None,
                sender: None,
                body: None,
                crdb: Some(self.repo.join(".chinwag/state.crdb")),
                stdin_json: true,
            },
            &mut bytes.as_slice(),
            output,
            &mut io::sink(),
        )
    }
}

enum Membership {
    Room(Arc<Mutex<RoomSession>>),
    #[cfg(test)]
    Fixture {
        peer: EndpointId,
        expiry: u64,
    },
}
impl Membership {
    fn allows(&self, peer: EndpointId, _now: u64) -> bool {
        match self {
            Self::Room(room) => room.lock().is_ok_and(|room| {
                room.pinned_peer_id() == peer && room.require_fresh_peer().is_ok()
            }),
            #[cfg(test)]
            Self::Fixture {
                peer: expected,
                expiry,
            } => *expected == peer && *expiry > _now,
        }
    }
}

struct Admission {
    replay: ReplayGuard,
    window_start: u64,
    attempts: u32,
}

pub(crate) struct Listener<D> {
    identity: Arc<Identity>,
    pin: EndpointId,
    membership: Membership,
    admission: Mutex<Admission>,
    dispatcher: Arc<D>,
    slots: Arc<Semaphore>,
    status: Arc<StatusStore>,
}
impl<D: Dispatcher> Listener<D> {
    pub(crate) fn new(
        identity: Arc<Identity>,
        pin: EndpointId,
        room: Arc<Mutex<RoomSession>>,
        dispatcher: D,
        started: u64,
        status: Arc<StatusStore>,
    ) -> Self {
        Self::with_membership(
            identity,
            pin,
            Membership::Room(room),
            dispatcher,
            started,
            status,
        )
    }
    fn with_membership(
        identity: Arc<Identity>,
        pin: EndpointId,
        membership: Membership,
        dispatcher: D,
        started: u64,
        status: Arc<StatusStore>,
    ) -> Self {
        Self {
            identity,
            pin,
            membership,
            admission: Mutex::new(Admission {
                replay: ReplayGuard::new(started),
                window_start: started,
                attempts: 0,
            }),
            dispatcher: Arc::new(dispatcher),
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            status,
        }
    }
    fn authorize(&self, peer: EndpointId, bytes: &[u8], now: u64) -> Result<Request, Refused> {
        if !self.status.healthy() || peer != self.pin || !self.membership.allows(peer, now) {
            return Err(Refused);
        }
        let mut admission = self.admission.lock().map_err(|_| Refused)?;
        if now < admission.window_start {
            return Err(Refused);
        }
        if now - admission.window_start >= 60 {
            admission.window_start = now;
            admission.attempts = 0;
        }
        if admission.attempts >= REQUESTS_PER_MINUTE {
            return Err(Refused);
        }
        admission.attempts += 1;
        let request = Request::from_bytes(bytes)?;
        admission
            .replay
            .accept(&request, peer, self.identity.endpoint_id(), now)?;
        Ok(request)
    }

    async fn dispatch(
        &self,
        request: Request,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Result<Response, Refused> {
        self.status
            .record(Event::Accepted, super::dispatch_remote::now()?)?;
        let dispatcher = self.dispatcher.clone();
        let identity = self.identity.clone();
        let status = self.status.clone();
        tokio::task::spawn_blocking(move || {
            // Keep the permit in the blocking task even if its client goes away.
            let _permit = permit;
            let mut output = CappedOutput::default();
            let code = dispatcher.dispatch(request.payload.clone(), &mut output);
            let result = if code == 0 && !output.overflow {
                String::from_utf8(output.bytes).ok()
            } else {
                None
            };
            let (code, reply) = match result {
                Some(reply)
                    if serde_json::from_str::<serde_json::Value>(&reply)
                        .is_ok_and(|v| v.is_object()) =>
                {
                    (0, reply)
                }
                _ => (if code == 0 { 1 } else { code }, String::new()),
            };
            if code != 0 {
                status.record(Event::Failed, super::dispatch_remote::now()?)?;
            }
            Response::sign(
                &identity,
                &request,
                code,
                reply,
                super::dispatch_remote::now()?,
            )
        })
        .await
        .map_err(|_| Refused)?
    }

    async fn connection(
        &self,
        connection: Connection,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), Refused> {
        let permit = Arc::new(permit);
        let mut accepted = false;
        let mut dispatch_failed = false;
        let result = async {
            if connection.alpn() != wire::ALPN || connection.remote_id() != self.pin {
                return Err(Refused);
            }
            let (mut send, request) = tokio::time::timeout(READ_TIMEOUT, async {
                let (send, mut recv) = connection.accept_bi().await.map_err(|_| Refused)?;
                let bytes = recv
                    .read_to_end(wire::MAX_REQUEST_BYTES)
                    .await
                    .map_err(|_| Refused)?;
                let request = self.authorize(
                    connection.remote_id(),
                    &bytes,
                    super::dispatch_remote::now()?,
                )?;
                Ok::<_, Refused>((send, request))
            })
            .await
            .map_err(|_| Refused)??;
            accepted = true;
            let response = self.dispatch(request, permit.clone()).await?;
            dispatch_failed = !response.ok;
            tokio::time::timeout(READ_TIMEOUT, async {
                send.write_all(&response.to_bytes()?)
                    .await
                    .map_err(|_| Refused)?;
                send.finish().map_err(|_| Refused)?;
                // Wait for acknowledgment before closing the connection.
                if send.stopped().await.map_err(|_| Refused)?.is_some() {
                    return Err(Refused);
                }
                Ok::<_, Refused>(())
            })
            .await
            .map_err(|_| Refused)??;
            Ok(())
        }
        .await;
        connection.close(0u32.into(), b"dispatch_finished");
        if result.is_err() && !dispatch_failed {
            let _ = self.status.record(
                if accepted {
                    Event::Failed
                } else {
                    Event::Refused
                },
                super::dispatch_remote::now().unwrap_or(0),
            );
        }
        result
    }

    /// Finite room lease: stop accepting at expiry, drain admitted work. There
    /// is no implicit coordinator retry or permission extension.
    pub(crate) async fn serve(
        self: Arc<Self>,
        endpoint: &Endpoint,
        lease: Duration,
    ) -> Result<(), Refused> {
        let cutoff = tokio::time::sleep(lease);
        tokio::pin!(cutoff);
        let mut tasks = tokio::task::JoinSet::new();
        let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = &mut cutoff => break,
                _ = heartbeat.tick() => { if self.status.record(Event::Heartbeat,super::dispatch_remote::now()?).is_err() { break; } },
                _ = tokio::signal::ctrl_c() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break; };
                    let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                        incoming.refuse();
                        if self.status.record(Event::Refused,super::dispatch_remote::now()?).is_err() { break; }
                        continue;
                    };
                    let listener = self.clone();
                    tasks.spawn(async move {
                        let result = match tokio::time::timeout(READ_TIMEOUT, incoming).await {
                            Ok(Ok(connection)) => listener.connection(connection, permit).await,
                            _ => { let _=listener.status.record(Event::Refused, super::dispatch_remote::now().unwrap_or(0)); Err(Refused) },
                        };
                        if result.is_err() { eprintln!("chinwag: dispatch_refused"); }
                    });
                }
            }
        }
        let stopped = self
            .status
            .record(Event::Stopped, super::dispatch_remote::now()?);
        while tasks.join_next().await.is_some() {}
        stopped
    }
}

#[derive(Default)]
struct CappedOutput {
    bytes: Vec<u8>,
    overflow: bool,
}
impl Write for CappedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > wire::MAX_REPLY_BYTES {
            self.overflow = true;
            return Err(io::Error::other("dispatch_failed"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayMode, SecretKey, address_lookup::memory::MemoryLookup, endpoint::presets};
    use ssh_key::{LineEnding, PrivateKey, private::Ed25519Keypair};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    struct Fake {
        calls: Arc<AtomicUsize>,
        fail: bool,
    }
    impl Dispatcher for Fake {
        fn dispatch(&self, _payload: Payload, output: &mut dyn Write) -> u8 {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                let _ = output.write_all(b"private diagnostic must not leave the Studio");
                return 7;
            }
            output
                .write_all(b"{\"ok\":true,\"reply\":\"fake dispatcher\"}\n")
                .unwrap();
            0
        }
    }
    struct Fixture {
        directory: TempDir,
        peer: Identity,
        studio: Arc<Identity>,
        listener: Arc<Listener<Fake>>,
        calls: Arc<AtomicUsize>,
        now: u64,
    }
    fn identity(directory: &std::path::Path, name: &str, seed: u8) -> Identity {
        let path = directory.join(name);
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
            .write_openssh_file(&path, LineEnding::LF)
            .unwrap();
        Identity::from_ssh_signing_file(&path).unwrap()
    }
    impl Fixture {
        fn new(verified: bool, fail: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            std::fs::create_dir(directory.path().join(".chinwag")).unwrap();
            let peer = identity(directory.path(), "peer", 41);
            let studio = Arc::new(identity(directory.path(), "studio", 42));
            let now = super::super::dispatch_remote::now().unwrap();
            let status = Arc::new(StatusStore::start(directory.path(), now - 1).unwrap());
            status.ready(now, now + 120).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let listener = Arc::new(Listener::with_membership(
                studio.clone(),
                peer.endpoint_id(),
                Membership::Fixture {
                    peer: peer.endpoint_id(),
                    expiry: if verified { now + 120 } else { now },
                },
                Fake {
                    calls: calls.clone(),
                    fail,
                },
                now - 1,
                status,
            ));
            Self {
                directory,
                peer,
                studio,
                listener,
                calls,
                now,
            }
        }
        fn request(&self, nonce: u8) -> Request {
            Request::sign(
                &self.peer,
                self.studio.endpoint_id(),
                Payload {
                    agent: "RUST".into(),
                    sender: "Brian".into(),
                    body: "inert fixture".into(),
                    item_key: "IROH-DISPATCH-1".into(),
                    history: vec![],
                    custom_agent: None,
                },
                [nonce; 32],
                self.now,
            )
            .unwrap()
        }
        fn accept(&self, request: &Request) -> Result<Request, Refused> {
            self.listener.authorize(
                self.peer.endpoint_id(),
                &request.to_bytes().unwrap(),
                self.now,
            )
        }
    }

    #[tokio::test]
    async fn admission_refuses_unpinned_unverified_bad_signature_replay_expiry_and_oversize() {
        let f = Fixture::new(true, false);
        let request = f.request(1);
        assert!(
            f.listener
                .authorize(f.studio.endpoint_id(), &request.to_bytes().unwrap(), f.now)
                .is_err()
        );
        let unverified = Fixture::new(false, false);
        assert!(unverified.accept(&unverified.request(1)).is_err());
        let mut bad = request.clone();
        bad.payload.body.push('!');
        assert!(f.accept(&bad).is_err());
        let mut expired = request.clone();
        expired.issued_unix = f.now - 121;
        expired.expiry_unix = f.now - 1;
        // Re-sign via the regular signer to prove expiry, rather than forgery.
        let expired = Request::sign(
            &f.peer,
            f.studio.endpoint_id(),
            expired.payload,
            [2; 32],
            f.now - 121,
        )
        .unwrap();
        assert!(f.accept(&expired).is_err());
        assert!(
            f.listener
                .authorize(
                    f.peer.endpoint_id(),
                    &vec![b' '; wire::MAX_REQUEST_BYTES + 1],
                    f.now
                )
                .is_err()
        );
        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["extra"] = true.into();
        assert!(
            f.listener
                .authorize(
                    f.peer.endpoint_id(),
                    &serde_json::to_vec(&unknown).unwrap(),
                    f.now
                )
                .is_err()
        );
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        let request = f.accept(&request).unwrap();
        assert!(f.accept(&request).is_err());
        let permit = f.listener.slots.clone().try_acquire_owned().unwrap();
        let response = f
            .listener
            .dispatch(request.clone(), Arc::new(permit))
            .await
            .unwrap();
        response
            .verify(
                f.studio.endpoint_id(),
                &request,
                super::super::dispatch_remote::now().unwrap(),
            )
            .unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        let status =
            super::super::dispatch_status::read_dispatch_status(f.directory.path(), f.now).unwrap();
        assert_eq!(status.requests_accepted, 1);
    }

    #[test]
    fn rate_limit_and_concurrency_are_bounded() {
        let f = Fixture::new(true, false);
        for nonce in 0..REQUESTS_PER_MINUTE as u8 {
            f.accept(&f.request(nonce)).unwrap();
        }
        assert!(f.accept(&f.request(99)).is_err());
        let one = f.listener.slots.clone().try_acquire_owned().unwrap();
        let two = f.listener.slots.clone().try_acquire_owned().unwrap();
        assert!(f.listener.slots.clone().try_acquire_owned().is_err());
        drop(one);
        drop(two);
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dispatcher_failure_is_signed_without_diagnostic_payload() {
        let f = Fixture::new(true, true);
        let request = f.accept(&f.request(1)).unwrap();
        let response = f
            .listener
            .dispatch(
                request.clone(),
                Arc::new(f.listener.slots.clone().try_acquire_owned().unwrap()),
            )
            .await
            .unwrap();
        response
            .verify(
                f.studio.endpoint_id(),
                &request,
                super::super::dispatch_remote::now().unwrap(),
            )
            .unwrap();
        assert!(!response.ok);
        assert_eq!(response.exit_code, 7);
        assert!(response.reply.is_empty());
        assert_eq!(
            super::super::dispatch_status::read_dispatch_status(f.directory.path(), f.now)
                .unwrap()
                .requests_failed,
            1
        );
    }

    async fn endpoint(seed: u8, lookup: MemoryLookup, alpns: Vec<Vec<u8>>) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .clear_address_lookup()
            .address_lookup(lookup)
            .relay_mode(RelayMode::Disabled)
            .alpns(alpns)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn loopback_pair_dispatches_once_and_refuses_replay_unknown_alpn_and_unpinned_peer() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let f = Fixture::new(true, false);
            let server = endpoint(42, MemoryLookup::new(), vec![wire::ALPN.to_vec()]).await;
            let book = MemoryLookup::new();
            book.set_endpoint_info(server.addr());
            let client = endpoint(41, book.clone(), vec![]).await;
            assert!(
                server
                    .bound_sockets()
                    .iter()
                    .all(|addr| addr.ip().is_loopback())
            );
            assert!(server.addr().relay_urls().next().is_none());
            assert_eq!(server.address_lookup().unwrap().len(), 1);
            let listener = f.listener.clone();
            let server_task = tokio::spawn({
                let server = server.clone();
                async move {
                    for expected_ok in [true, false, false] {
                        let connection = server.accept().await.unwrap().await.unwrap();
                        let permit = listener.slots.clone().try_acquire_owned().unwrap();
                        assert_eq!(
                            listener.connection(connection, permit).await.is_ok(),
                            expected_ok
                        );
                    }
                }
            });
            let request = f.request(1);
            let response = super::super::dispatch_remote::exchange(
                &client,
                f.studio.endpoint_id(),
                &request,
                tokio::time::Instant::now() + Duration::from_secs(120),
            )
            .await
            .unwrap();
            assert_eq!(
                response.reply,
                "{\"ok\":true,\"reply\":\"fake dispatcher\"}\n"
            );
            assert!(
                super::super::dispatch_remote::exchange(
                    &client,
                    f.studio.endpoint_id(),
                    &request,
                    tokio::time::Instant::now() + Duration::from_secs(120)
                )
                .await
                .is_err()
            );
            let attacker = endpoint(43, book, vec![]).await;
            assert!(
                super::super::dispatch_remote::exchange(
                    &attacker,
                    f.studio.endpoint_id(),
                    &request,
                    tokio::time::Instant::now() + Duration::from_secs(120),
                )
                .await
                .is_err()
            );
            server_task.await.unwrap();
            let (dial, accept) =
                tokio::join!(client.connect(server.addr(), b"unknown/dispatch"), async {
                    server.accept().await.unwrap().await
                });
            assert!(dial.is_err());
            assert!(accept.is_err());
            assert_eq!(f.calls.load(Ordering::SeqCst), 1);
            attacker.close().await;
            client.close().await;
            server.close().await;
        })
        .await
        .expect("loopback dispatch must finish within 20 seconds");
    }
}
