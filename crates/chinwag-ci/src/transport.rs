// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! One native pinned pair, isolated from normal operational bus profiles.
//! Frames are untrusted opaque bytes until the application verifies the signed
//! encrypted envelope and workload admission. Transport replies are not storage
//! or processing proofs until their destination signatures/content are checked.

use chinwag_swarm::relay_policy::RelayPolicy;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey, TransportAddr,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, presets},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{future::Future, time::Duration};
use tokio::time::timeout;
use zeroize::Zeroizing;

pub const CI_ALPN: &[u8] = b"chinwag/ci-ciphertext/1";
pub const MAX_MANIFEST_BYTES: usize = 128 * 1024;
pub const MAX_CIPHERTEXT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const HEADER_BYTES: usize = 52;
const MAGIC: &[u8; 8] = b"CHWGCI01";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    #[error("native CI pair requires distinct pinned identities and one approved owned relay")]
    Policy,
    #[error("native CI operation has an invalid finite deadline")]
    Deadline,
    #[error("native CI selected peer, ALPN, or actual relay path differs from its profile")]
    Path,
    #[error("native CI frame has invalid length, checksum, or version")]
    Frame,
    #[error("native CI transport operation failed")]
    Network,
    #[error("native CI operation exceeded its whole-operation deadline")]
    Timeout,
    #[error("native CI application refused the received evidence")]
    Application,
}

#[derive(Clone, Debug)]
struct PairSelection {
    peer: EndpointId,
    relay: RelayUrl,
}

fn route_matches(peer: EndpointId, relay: &RelayUrl, remote: &EndpointAddr, alpn: &[u8]) -> bool {
    remote.id == peer
        && alpn == CI_ALPN
        && !remote.addrs.is_empty()
        && remote
            .addrs
            .iter()
            .all(|address| matches!(address,TransportAddr::Relay(url) if url==relay))
}

#[derive(Clone, Serialize)]
pub struct SelectedRelayWitness {
    pub peer_endpoint_id: String,
    pub alpn: String,
    pub selected_transport: &'static str,
    pub relay_origin: String,
}

impl PairSelection {
    fn witness(&self, connection: &Connection) -> Result<SelectedRelayWitness, TransferError> {
        if connection.remote_id() != self.peer || connection.alpn() != CI_ALPN {
            return Err(TransferError::Path);
        }
        let paths = connection.paths();
        let mut selected = paths.iter().filter(|path| path.is_selected());
        let path = selected.next().ok_or(TransferError::Path)?;
        if selected.next().is_some()
            || !matches!(path.remote_addr(),TransportAddr::Relay(url) if url==&self.relay)
        {
            return Err(TransferError::Path);
        }
        Ok(SelectedRelayWitness {
            peer_endpoint_id: self.peer.to_string(),
            alpn: String::from_utf8_lossy(CI_ALPN).into_owned(),
            selected_transport: "relay",
            relay_origin: self.relay.to_string(),
        })
    }
}

impl EndpointHooks for PairSelection {
    async fn before_connect<'a>(
        &'a self,
        remote: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if route_matches(self.peer, &self.relay, remote, alpn) {
            BeforeConnectOutcome::Accept
        } else {
            BeforeConnectOutcome::Reject
        }
    }
    async fn after_handshake<'a>(&'a self, connection: &'a Connection) -> AfterHandshakeOutcome {
        if self.witness(connection).is_ok() {
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: 0x403_u32.into(),
                reason: b"ci_pinned_relay_profile_required".to_vec(),
            }
        }
    }
}

struct ConnectionGuard(Connection, bool);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.close(
            if self.1 { 0_u32 } else { 0x4c1_u32 }.into(),
            b"ci_transfer_finished",
        );
    }
}

/// No raw-frame Debug implementation: manifests can contain short-lived workload
/// credentials. Only independently verified signed receipt fields may be logged.
pub struct ReceivedCiphertextClaim {
    pub manifest: Zeroizing<Vec<u8>>,
    pub ciphertext: Zeroizing<Vec<u8>>,
    pub ciphertext_sha256: [u8; 32],
    pub path_before: SelectedRelayWitness,
    pub path_after_receive: SelectedRelayWitness,
}

pub struct ReturnedReceipt {
    pub unverified_receipt: Vec<u8>,
    pub path_before: SelectedRelayWitness,
    pub path_after: SelectedRelayWitness,
}

pub struct CiPair {
    endpoint: Endpoint,
    selection: PairSelection,
}

fn valid_deadline(deadline: Duration) -> Result<(), TransferError> {
    if deadline.is_zero() || deadline > Duration::from_secs(1800) {
        Err(TransferError::Deadline)
    } else {
        Ok(())
    }
}

struct Header {
    manifest_bytes: usize,
    ciphertext_bytes: usize,
    sha256: [u8; 32],
}
fn bounded_lengths(manifest: usize, ciphertext: usize) -> Result<(), TransferError> {
    if manifest == 0
        || manifest > MAX_MANIFEST_BYTES
        || ciphertext == 0
        || ciphertext > MAX_CIPHERTEXT_BYTES
    {
        Err(TransferError::Frame)
    } else {
        Ok(())
    }
}
impl Header {
    fn encode(&self) -> Result<[u8; HEADER_BYTES], TransferError> {
        bounded_lengths(self.manifest_bytes, self.ciphertext_bytes)?;
        let mut wire = [0; HEADER_BYTES];
        wire[..8].copy_from_slice(MAGIC);
        wire[8..12].copy_from_slice(&(self.manifest_bytes as u32).to_be_bytes());
        wire[12..20].copy_from_slice(&(self.ciphertext_bytes as u64).to_be_bytes());
        wire[20..].copy_from_slice(&self.sha256);
        Ok(wire)
    }
    fn decode(wire: &[u8; HEADER_BYTES]) -> Result<Self, TransferError> {
        if &wire[..8] != MAGIC {
            return Err(TransferError::Frame);
        }
        let manifest_bytes =
            u32::from_be_bytes(wire[8..12].try_into().map_err(|_| TransferError::Frame)?) as usize;
        let raw = u64::from_be_bytes(wire[12..20].try_into().map_err(|_| TransferError::Frame)?);
        let ciphertext_bytes = usize::try_from(raw).map_err(|_| TransferError::Frame)?;
        let header = Self {
            manifest_bytes,
            ciphertext_bytes,
            sha256: wire[20..].try_into().map_err(|_| TransferError::Frame)?,
        };
        header.encode()?;
        Ok(header)
    }
}

impl CiPair {
    /// Selection strings/public keys are not admission. The original operator
    /// must supply its authenticated CI profile and its own fresh identity.
    /// No existing operational endpoint, relay allowlist or service is changed.
    pub async fn bind(
        identity: SecretKey,
        peer: EndpointId,
        selected_relay: &str,
        approved_relay: &str,
    ) -> Result<Self, TransferError> {
        if identity.public() == peer {
            return Err(TransferError::Policy);
        }
        let policy = RelayPolicy::from_local_manifest(Some(selected_relay), Some(approved_relay))
            .map_err(|_| TransferError::Policy)?;
        let relay = policy.relay_url().cloned().ok_or(TransferError::Policy)?;
        let selection = PairSelection { peer, relay };
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(identity)
            .clear_address_lookup()
            .relay_mode(policy.relay_mode().map_err(|_| TransferError::Policy)?)
            .alpns(vec![CI_ALPN.to_vec()])
            .hooks(selection.clone())
            .clear_ip_transports()
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .map_err(|_| TransferError::Policy)?,
            )
            .map_err(|_| TransferError::Policy)?
            .bind()
            .await
            .map_err(|_| TransferError::Network)?;
        // A bound loopback socket is topology evidence, not relay readiness.
        if endpoint.bound_sockets().is_empty()
            || endpoint
                .bound_sockets()
                .iter()
                .any(|address| !address.ip().is_loopback())
        {
            endpoint.close().await;
            return Err(TransferError::Path);
        }
        Ok(Self {
            endpoint,
            selection,
        })
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }
    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// No retry is performed, including after an uncertain receipt outcome.
    /// Returned bytes still require exact destination signature/role/event/hash
    /// verification before the application may claim durable dual delivery.
    pub async fn send(
        &self,
        manifest: &[u8],
        ciphertext: &[u8],
        deadline: Duration,
    ) -> Result<ReturnedReceipt, TransferError> {
        valid_deadline(deadline)?;
        bounded_lengths(manifest.len(), ciphertext.len())?;
        timeout(deadline, async {
            let header = Header {
                manifest_bytes: manifest.len(),
                ciphertext_bytes: ciphertext.len(),
                sha256: Sha256::digest(ciphertext).into(),
            }
            .encode()?;
            let remote =
                EndpointAddr::new(self.selection.peer).with_relay_url(self.selection.relay.clone());
            let mut connection = ConnectionGuard(
                self.endpoint
                    .connect(remote, CI_ALPN)
                    .await
                    .map_err(|_| TransferError::Network)?,
                false,
            );
            let path_before = self.selection.witness(&connection.0)?;
            let (mut send, mut receive) = connection
                .0
                .open_bi()
                .await
                .map_err(|_| TransferError::Network)?;
            send.write_all(&header)
                .await
                .map_err(|_| TransferError::Network)?;
            send.write_all(manifest)
                .await
                .map_err(|_| TransferError::Network)?;
            send.write_all(ciphertext)
                .await
                .map_err(|_| TransferError::Network)?;
            send.finish().map_err(|_| TransferError::Network)?;
            let receipt = receive
                .read_to_end(MAX_RECEIPT_BYTES)
                .await
                .map_err(|_| TransferError::Network)?;
            if receipt.is_empty() {
                return Err(TransferError::Frame);
            }
            let path_after = self.selection.witness(&connection.0)?;
            // The final application-data receiver closes AFTER reading. A
            // QUIC FIN ACK alone does not prove the application read bytes.
            connection.1 = true;
            connection.0.close(0_u32.into(), b"ci_receipt_bytes_read");
            Ok(ReturnedReceipt {
                unverified_receipt: receipt,
                path_before,
                path_after,
            })
        })
        .await
        .map_err(|_| TransferError::Timeout)?
    }

    /// The application callback must authenticate admission and the encrypted
    /// manifest before persistence, then return its own SIGNED correlated
    /// durable receipt. It may refuse. This library never creates a synthetic
    /// success ACK. Cancellation closes the connection; it does not prove that
    /// separately spawned callback children stopped. Their owner must join them.
    pub async fn receive_once<F, Fut>(
        &self,
        deadline: Duration,
        handler: F,
    ) -> Result<SelectedRelayWitness, TransferError>
    where
        F: FnOnce(ReceivedCiphertextClaim) -> Fut,
        Fut: Future<Output = Result<Vec<u8>, TransferError>>,
    {
        valid_deadline(deadline)?;
        timeout(deadline, async {
            let incoming = self.endpoint.accept().await.ok_or(TransferError::Network)?;
            let mut connection =
                ConnectionGuard(incoming.await.map_err(|_| TransferError::Network)?, false);
            let path_before = self.selection.witness(&connection.0)?;
            let (send, mut receive) = connection
                .0
                .accept_bi()
                .await
                .map_err(|_| TransferError::Network)?;
            let mut wire = [0; HEADER_BYTES];
            receive
                .read_exact(&mut wire)
                .await
                .map_err(|_| TransferError::Frame)?;
            let header = Header::decode(&wire)?;
            let mut manifest = Zeroizing::new(vec![0; header.manifest_bytes]);
            receive
                .read_exact(&mut manifest)
                .await
                .map_err(|_| TransferError::Frame)?;
            let mut ciphertext = Zeroizing::new(vec![0; header.ciphertext_bytes]);
            receive
                .read_exact(&mut ciphertext)
                .await
                .map_err(|_| TransferError::Frame)?;
            receive
                .read_to_end(0)
                .await
                .map_err(|_| TransferError::Frame)?;
            if <[u8; 32]>::from(Sha256::digest(&ciphertext)) != header.sha256 {
                return Err(TransferError::Frame);
            }
            let path_after_receive = self.selection.witness(&connection.0)?;
            let receipt = handler(ReceivedCiphertextClaim {
                manifest,
                ciphertext,
                ciphertext_sha256: header.sha256,
                path_before,
                path_after_receive,
            })
            .await?;
            if receipt.is_empty() || receipt.len() > MAX_RECEIPT_BYTES {
                return Err(TransferError::Application);
            }
            // Preserve the live path before the final receiver may close. It
            // can cease to be observable after normal peer closure.
            let path_after = self.selection.witness(&connection.0)?;
            send_reply_and_wait_reader_close(&connection.0, send, &receipt).await?;
            connection.1 = true;
            Ok(path_after)
        })
        .await
        .map_err(|_| TransferError::Timeout)?
    }

    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

async fn send_reply_and_wait_reader_close(
    connection: &Connection,
    mut send: iroh::endpoint::SendStream,
    receipt: &[u8],
) -> Result<(), TransferError> {
    send.write_all(receipt)
        .await
        .map_err(|_| TransferError::Network)?;
    send.finish().map_err(|_| TransferError::Network)?;
    // The peer implementation closes0 only AFTER its receipt read/path check.
    // This is a transport read convention, not a signed processing receipt.
    match connection.closed().await {
        iroh::endpoint::ConnectionError::ApplicationClosed(close)
            if close.error_code == 0_u32.into() =>
        {
            Ok(())
        }
        _ => Err(TransferError::Network),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostile_frame_lengths_fail_before_allocation() {
        let header = Header {
            manifest_bytes: 1,
            ciphertext_bytes: 12 * 1024 * 1024,
            sha256: [1; 32],
        };
        let valid = header.encode().unwrap();
        assert_eq!(
            Header::decode(&valid).unwrap().ciphertext_bytes,
            12 * 1024 * 1024
        );
        for length in [0_u64, MAX_CIPHERTEXT_BYTES as u64 + 1, u64::MAX] {
            let mut wire = valid;
            wire[12..20].copy_from_slice(&length.to_be_bytes());
            assert!(Header::decode(&wire).is_err());
        }
        for length in [0_u32, MAX_MANIFEST_BYTES as u32 + 1, u32::MAX] {
            let mut wire = valid;
            wire[8..12].copy_from_slice(&length.to_be_bytes());
            assert!(Header::decode(&wire).is_err());
        }
        let mut wire = valid;
        wire[0] ^= 1;
        assert!(Header::decode(&wire).is_err());
    }
    #[test]
    fn a_peer_or_alpn_or_direct_address_cannot_replace_the_selected_relay() {
        let peer = SecretKey::generate().public();
        let other = SecretKey::generate().public();
        let relay: RelayUrl = "https://owned-relay.invalid/".parse().unwrap();
        let address = EndpointAddr::new(peer).with_relay_url(relay.clone());
        assert!(route_matches(peer, &relay, &address, CI_ALPN));
        assert!(!route_matches(other, &relay, &address, CI_ALPN));
        assert!(!route_matches(peer, &relay, &address, b"chinwag/bus/1"));
        let address = address.with_ip_addr("127.0.0.1:44330".parse().unwrap());
        assert!(!route_matches(peer, &relay, &address, CI_ALPN));
        assert!(!route_matches(
            peer,
            &relay,
            &EndpointAddr::new(peer),
            CI_ALPN
        ));
    }

    #[tokio::test]
    async fn quic_fin_ack_does_not_close_before_the_application_reads_the_reply() {
        // Controlled loopback receipt-lifecycle regression ONLY. This does not
        // use the production selected-relay hook or claim live CF transport.
        async fn fixture_endpoint() -> Endpoint {
            Endpoint::builder(presets::Minimal)
                .secret_key(SecretKey::generate())
                .clear_address_lookup()
                .relay_mode(iroh::RelayMode::Disabled)
                .alpns(vec![CI_ALPN.to_vec()])
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
                .unwrap()
                .bind()
                .await
                .unwrap()
        }
        let server = fixture_endpoint().await;
        let client = fixture_endpoint().await;
        let server_copy = server.clone();
        let mut worker = tokio::spawn(async move {
            timeout(Duration::from_secs(3), async {
                let incoming = server_copy.accept().await.ok_or(TransferError::Network)?;
                let connection = incoming.await.map_err(|_| TransferError::Network)?;
                let (send, mut receive) = connection
                    .accept_bi()
                    .await
                    .map_err(|_| TransferError::Network)?;
                receive
                    .read_to_end(64)
                    .await
                    .map_err(|_| TransferError::Frame)?;
                send_reply_and_wait_reader_close(&connection, send, b"test-only unverified receipt")
                    .await
            })
            .await
            .map_err(|_| TransferError::Timeout)?
        });
        let reading = timeout(Duration::from_secs(3), async {
            let connection = client
                .connect(server.addr(), CI_ALPN)
                .await
                .map_err(|_| TransferError::Network)?;
            let (mut send, mut receive) = connection
                .open_bi()
                .await
                .map_err(|_| TransferError::Network)?;
            send.write_all(b"test-only request")
                .await
                .map_err(|_| TransferError::Network)?;
            send.finish().map_err(|_| TransferError::Network)?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let closed_before_application_read = worker.is_finished();
            let bytes = receive
                .read_to_end(64)
                .await
                .map_err(|_| TransferError::Network)?;
            connection.close(0_u32.into(), b"fixture_receipt_read");
            Ok::<_, TransferError>((closed_before_application_read, bytes))
        })
        .await;
        // Always close our endpoints and join/abort the one owned worker before
        // assertions, including failure paths; no detached loopback listener.
        client.close().await;
        let finished = timeout(Duration::from_secs(3), &mut worker).await;
        if finished.is_err() {
            worker.abort();
            let _ = worker.await;
        }
        server.close().await;
        let (closed, bytes) = reading.unwrap().unwrap();
        assert!(!closed, "FIN ACK must not become an application-read claim");
        assert_eq!(bytes, b"test-only unverified receipt");
        assert!(matches!(finished, Ok(Ok(Ok(())))));
    }
}
