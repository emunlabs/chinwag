//! One operator-selected byte reception on a borrowed, coherent room/plane pair.
//! Saved bytes and a locally queued ACK are not peer acceptance, verified Git,
//! received-source Cargo, a model verdict, a write lease, or a seal.

use crate::{
    bundle::{BundleExpectation, GitCandidate, MAX_BUNDLE_BYTES},
    bundle_io::{bounded_read, canonical, private_empty_directory, private_file},
    bundle_wire::{BundleBytesAck, BundleOffer, MAX_OFFER_BYTES, run_id},
    private_trace::{PrivateStageJournal, Stage, observe_cached_ips},
    send_owner::peer::bundle_topic,
};
use chinwag_swarm::{room::RoomSession, transport::DataPlane};
use futures_util::{Stream, StreamExt};
use iroh::EndpointId;
use iroh_gossip::api::{Event, GossipTopic};
use rustix::fs::{Mode, OFlags, openat};
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const BUNDLE_FILE: &str = "candidate.bundle";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("bundle reception failed; preserve the original scope and do not retry")]
pub struct ReceiveError;

/// The exact saved path and original offer after a local ACK broadcast returned.
/// This is an observation, not `VerifiedBundle` or proof the sender saw the ACK.
/// The offer retains the hash/size/run bindings for later independent intake.
/// Retain this value with the room and plane through the caller's bounded
/// receive phase. Dropping it leaves the topic; retention is not delivery proof.
#[must_use = "retain the saved-file observation with its room and plane through the receive phase"]
pub struct ReceivedFile {
    path: PathBuf,
    offer: BundleOffer,
    // Own both topic halves after the ACK command is queued. Without this,
    // returning the observation would immediately withdraw the subscription.
    _topic: GossipTopic,
}

impl ReceivedFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn offer(&self) -> &BundleOffer {
        &self.offer
    }
}

/// The caller owns one original attempt guard and a bounded phase deadline,
/// supplies the matching live room/plane pair, and keeps them alive through
/// this call. No room, claim, lease, retry, timer, or shutdown starts here.
/// File writes/fsync are synchronous; a caller timeout cannot preempt them.
/// Files already created remain on any failure or cancellation. There is no
/// recovery read: the directory must initially be private, canonical and empty.
pub async fn accept_one_bundle(
    plane: &DataPlane,
    room: &RoomSession,
    peer: EndpointId,
    run: &str,
    candidate: &GitCandidate,
    directory: &Path,
    journal: &mut PrivateStageJournal,
) -> Result<ReceivedFile, ReceiveError> {
    run_id(run).map_err(|_| ReceiveError)?;
    fresh_pair(plane, room, peer, candidate)?;
    let scope = ReceiveDirectory::open(directory)?;
    fresh_pair(plane, room, peer, candidate)?;
    let mut topic = plane
        .join_topic(bundle_topic(run))
        .await
        .map_err(|_| ReceiveError)?;
    journal
        .record(
            Stage::ReceiveJoinReturned,
            &observe_cached_ips(plane, room.cached_peer_ips()),
        )
        .map_err(|_| ReceiveError)?;
    topic.joined().await.map_err(|_| ReceiveError)?;
    journal
        .record(
            Stage::ReceiveNeighborReturned,
            &observe_cached_ips(plane, room.cached_peer_ips()),
        )
        .map_err(|_| ReceiveError)?;
    let body = next_pinned_body(&mut topic, peer).await?;
    fresh_pair(plane, room, peer, candidate)?;
    let offer = BundleOffer::decode_for(&body, run, candidate).map_err(|_| ReceiveError)?;
    journal
        .record(
            Stage::ReceiveOfferReceived,
            &observe_cached_ips(plane, room.cached_peer_ips()),
        )
        .map_err(|_| ReceiveError)?;
    fresh_pair(plane, room, peer, candidate)?;
    let bytes = plane
        .fetch_blob(
            offer.expectation().hash().into(),
            offer.expectation().size(),
        )
        .await
        .map_err(|_| ReceiveError)?;
    journal
        .record(
            Stage::ReceiveFetchReturned,
            &observe_cached_ips(plane, room.cached_peer_ips()),
        )
        .map_err(|_| ReceiveError)?;
    let ack = BundleBytesAck::from_received_bytes(&offer, &bytes).map_err(|_| ReceiveError)?;
    fresh_pair(plane, room, peer, candidate)?;
    let path = scope.save(offer.expectation(), &bytes)?;
    journal
        .record(
            Stage::ReceiveSaveReturned,
            &observe_cached_ips(plane, room.cached_peer_ips()),
        )
        .map_err(|_| ReceiveError)?;
    fresh_pair(plane, room, peer, candidate)?;
    topic
        .broadcast(ack.encode().map_err(|_| ReceiveError)?.into())
        .await
        .map_err(|_| ReceiveError)?;
    journal
        .record(
            Stage::ReceiveAckQueued,
            &observe_cached_ips(plane, room.cached_peer_ips()),
        )
        .map_err(|_| ReceiveError)?;
    Ok(ReceivedFile {
        path,
        offer,
        _topic: topic,
    })
}

fn fresh_pair(
    plane: &DataPlane,
    room: &RoomSession,
    peer: EndpointId,
    candidate: &GitCandidate,
) -> Result<(), ReceiveError> {
    room.require_fresh_peer().map_err(|_| ReceiveError)?;
    if room.pinned_peer_id() != peer
        || plane.pinned_peer_id() != peer
        || plane.endpoint_addr().id == peer
        || candidate.builder() != *peer.as_bytes()
    {
        return Err(ReceiveError);
    }
    Ok(())
}

async fn next_pinned_body<S, E>(stream: &mut S, peer: EndpointId) -> Result<Vec<u8>, ReceiveError>
where
    S: Stream<Item = Result<Event, E>> + Unpin,
{
    loop {
        let event = stream
            .next()
            .await
            .ok_or(ReceiveError)?
            .map_err(|_| ReceiveError)?;
        if let Event::Received(message) = event {
            if message.delivered_from != peer || message.content.len() > MAX_OFFER_BYTES {
                return Err(ReceiveError);
            }
            return Ok(message.content.to_vec());
        }
    }
}

/// A held private directory is an ownership boundary, not an OS sandbox
/// against another process running as this same user.
struct ReceiveDirectory {
    path: PathBuf,
    directory: File,
}

impl ReceiveDirectory {
    fn open(path: &Path) -> Result<Self, ReceiveError> {
        let path = canonical(path).map_err(|_| ReceiveError)?;
        let directory = private_empty_directory(&path).map_err(|_| ReceiveError)?;
        Ok(Self { path, directory })
    }

    fn check_parent(&self) -> Result<(), ReceiveError> {
        let held = self.directory.metadata().map_err(|_| ReceiveError)?;
        let current = fs::symlink_metadata(&self.path).map_err(|_| ReceiveError)?;
        if !current.is_dir()
            || held.dev() != current.dev()
            || held.ino() != current.ino()
            || held.uid() != rustix::process::geteuid().as_raw()
            || held.mode() & 0o077 != 0
        {
            return Err(ReceiveError);
        }
        Ok(())
    }

    fn save(&self, expected: &BundleExpectation, bytes: &[u8]) -> Result<PathBuf, ReceiveError> {
        expected.matches_blob(bytes).map_err(|_| ReceiveError)?;
        self.check_parent()?;
        let fd = openat(
            &self.directory,
            BUNDLE_FILE,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| ReceiveError)?;
        let mut file = File::from(fd);
        file.write_all(bytes).map_err(|_| ReceiveError)?;
        file.sync_all().map_err(|_| ReceiveError)?;
        self.directory.sync_all().map_err(|_| ReceiveError)?;
        self.verify_saved(expected, bytes, &file)?;
        Ok(self.path.join(BUNDLE_FILE))
    }

    fn verify_saved(
        &self,
        expected: &BundleExpectation,
        bytes: &[u8],
        written: &File,
    ) -> Result<(), ReceiveError> {
        self.check_parent()?;
        let original = written.metadata().map_err(|_| ReceiveError)?;
        let mut file = private_file(&self.path.join(BUNDLE_FILE)).map_err(|_| ReceiveError)?;
        let reopened = file.metadata().map_err(|_| ReceiveError)?;
        if original.dev() != reopened.dev() || original.ino() != reopened.ino() {
            return Err(ReceiveError);
        }
        let saved = bounded_read(&mut file, MAX_BUNDLE_BYTES).map_err(|_| ReceiveError)?;
        expected.matches_blob(&saved).map_err(|_| ReceiveError)?;
        if saved != bytes {
            return Err(ReceiveError);
        }
        self.check_parent()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use iroh::{EndpointId, SecretKey};
    use iroh_gossip::{api::Message, proto::DeliveryScope};
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn peer(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn message(from: EndpointId, bytes: Vec<u8>) -> Event {
        Event::Received(Message {
            content: bytes.into(),
            scope: DeliveryScope::Neighbors,
            delivered_from: from,
        })
    }

    fn expectation(bytes: &[u8]) -> BundleExpectation {
        BundleExpectation::new(
            &"a".repeat(40),
            &"b".repeat(40),
            *blake3::hash(bytes).as_bytes(),
            bytes.len() as u64,
            *peer(0x22).as_bytes(),
        )
        .unwrap()
    }

    fn private_dir() -> (tempfile::TempDir, PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().canonicalize().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        (temporary, path)
    }

    #[tokio::test]
    async fn wrong_or_oversized_first_body_leaves_second_frame_unconsumed() {
        let pin = peer(0x22);
        for bad in [
            message(peer(0x33), b"wrong peer".to_vec()),
            message(pin, vec![b'x'; MAX_OFFER_BYTES + 1]),
        ] {
            let good = message(pin, b"second frame".to_vec());
            let mut input = stream::iter(vec![
                Ok::<_, ()>(Event::NeighborUp(pin)),
                Ok(bad),
                Ok(good.clone()),
            ]);
            assert_eq!(next_pinned_body(&mut input, pin).await, Err(ReceiveError));
            assert_eq!(input.next().await, Some(Ok(good)));
        }
        let mut input = stream::iter(vec![
            Ok::<_, ()>(Event::NeighborUp(pin)),
            Ok(message(pin, b"first valid body".to_vec())),
        ]);
        assert_eq!(
            next_pinned_body(&mut input, pin).await.unwrap(),
            b"first valid body"
        );
        println!(
            "receiver_first_body pinned_and_capped=true bad_first_final=true second_unconsumed=true synthetic_stream_only=true"
        );
    }

    #[tokio::test]
    async fn stream_error_and_eof_refuse_without_consuming_a_later_body() {
        let pin = peer(0x22);
        let good = message(pin, b"not consumed".to_vec());
        let mut input = stream::iter(vec![Err::<Event, _>(()), Ok(good.clone())]);
        assert_eq!(next_pinned_body(&mut input, pin).await, Err(ReceiveError));
        assert_eq!(input.next().await, Some(Ok(good)));
        let mut input = stream::iter(Vec::<Result<Event, ()>>::new());
        assert_eq!(next_pinned_body(&mut input, pin).await, Err(ReceiveError));
    }

    #[test]
    fn saved_file_is_exact_private_synced_and_cannot_be_replaced_or_reopened() {
        let (_temporary, path) = private_dir();
        let scope = ReceiveDirectory::open(&path).unwrap();
        let bytes = b"actual saved fixture bytes, not Git or Cargo proof";
        let expected = expectation(bytes);
        let saved = scope.save(&expected, bytes).unwrap();
        assert_eq!(saved, path.join(BUNDLE_FILE));
        assert_eq!(fs::read(&saved).unwrap(), bytes);
        let metadata = fs::symlink_metadata(&saved).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let file = private_file(&saved).unwrap();
        scope.verify_saved(&expected, bytes, &file).unwrap();
        assert!(scope.save(&expected, bytes).is_err());
        assert_eq!(fs::read(&saved).unwrap(), bytes);
        assert!(ReceiveDirectory::open(&path).is_err());
        println!(
            "receiver_file actual_write_fsync_parent_readback=true exact_hash_size=true mode600=true create_new_preserved=true occupied_reopen_refused=true no_network_ack_observation=true"
        );
    }

    #[test]
    fn unsafe_or_occupied_directories_and_changed_parent_refuse() {
        let (_temporary, path) = private_dir();
        let target = path.join("private");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let link = path.join("link");
        symlink(&target, &link).unwrap();
        assert!(ReceiveDirectory::open(&link).is_err());
        assert!(ReceiveDirectory::open(Path::new("relative")).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ReceiveDirectory::open(&target).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(target.join("existing"), b"preserve").unwrap();
        assert!(ReceiveDirectory::open(&target).is_err());
        assert_eq!(fs::read(target.join("existing")).unwrap(), b"preserve");
        let empty = path.join("empty");
        fs::create_dir(&empty).unwrap();
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).unwrap();
        let scope = ReceiveDirectory::open(&empty).unwrap();
        fs::rename(&empty, path.join("moved")).unwrap();
        fs::create_dir(&empty).unwrap();
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o700)).unwrap();
        let bytes = b"private payload";
        assert!(scope.save(&expectation(bytes), bytes).is_err());
        assert!(!empty.join(BUNDLE_FILE).exists());
        assert!(!path.join("moved").join(BUNDLE_FILE).exists());
        let file_link_scope = path.join("file-link-scope");
        fs::create_dir(&file_link_scope).unwrap();
        fs::set_permissions(&file_link_scope, fs::Permissions::from_mode(0o700)).unwrap();
        let scope = ReceiveDirectory::open(&file_link_scope).unwrap();
        let protected = path.join("protected-fixture");
        fs::write(&protected, b"unchanged").unwrap();
        symlink(&protected, file_link_scope.join(BUNDLE_FILE)).unwrap();
        assert!(scope.save(&expectation(bytes), bytes).is_err());
        assert_eq!(fs::read(&protected).unwrap(), b"unchanged");
        assert!(
            fs::symlink_metadata(file_link_scope.join(BUNDLE_FILE))
                .unwrap()
                .is_symlink()
        );
    }

    #[test]
    fn tampered_or_relinked_readback_refuses_and_preserves_actual_file() {
        let (_temporary, path) = private_dir();
        let scope = ReceiveDirectory::open(&path).unwrap();
        let bytes = b"saved payload";
        let expected = expectation(bytes);
        let saved = scope.save(&expected, bytes).unwrap();
        let original = private_file(&saved).unwrap();
        fs::write(&saved, b"wrong payload").unwrap();
        assert!(scope.verify_saved(&expected, bytes, &original).is_err());
        assert_eq!(fs::read(&saved).unwrap(), b"wrong payload");
        // Restore correct fixture bytes first, so the next refusal cannot
        // pass merely because the previous tamper still has the wrong hash.
        fs::write(&saved, bytes).unwrap();
        scope.verify_saved(&expected, bytes, &original).unwrap();
        fs::hard_link(&saved, path.join("second-link")).unwrap();
        assert_eq!(fs::metadata(&saved).unwrap().nlink(), 2);
        assert!(scope.verify_saved(&expected, bytes, &original).is_err());
        assert_eq!(fs::read(&saved).unwrap(), bytes);
        println!(
            "receiver_readback tamper_refused=true hardlink_refused=true created_file_preserved=true broadcast_unreachable_by_source_order_only=true"
        );
    }
}
