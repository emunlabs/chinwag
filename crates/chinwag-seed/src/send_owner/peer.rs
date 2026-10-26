//! Fixed operator-only handoff on the existing shared claim session.
//! A byte receipt is not intake, received-source Cargo, review, or seal proof.

use super::{CallbackOutcome, Error, SendOwner};
use crate::{
    bundle_export::{ExportOperatorConfig, PreparedBundle},
    bundle_io::{canonical, private_empty_directory},
    bundle_wire::{BundleBytesAck, BundleOffer, MAX_ACK_BYTES, run_id},
    edit_mcp::EditState,
    private_trace::{PrivateStageJournal, Stage, observe_cached_ips},
};
use chinwag_swarm::transport::DataPlane;
use futures_util::StreamExt;
use iroh::EndpointId;
use iroh_gossip::{TopicId, api::Event};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

impl SendOwner {
    /// Fix the run, other identity and existing state before the cold job can
    /// start. This does not register a tool or start a room. Retain and drain
    /// the owner before shutting down the shared claim and its data plane.
    pub fn open_peer(
        config: ExportOperatorConfig,
        state: Arc<Mutex<EditState>>,
        run: String,
        peer: EndpointId,
        trace_directory: PathBuf,
    ) -> Result<Self, Error> {
        run_id(&run).map_err(|_| Error::Unavailable)?;
        let builder =
            EndpointId::from_bytes(&config.candidate.builder()).map_err(|_| Error::Unavailable)?;
        if builder == peer {
            return Err(Error::Unavailable);
        }
        let trace_directory = canonical(&trace_directory).map_err(|_| Error::Unavailable)?;
        private_empty_directory(&trace_directory).map_err(|_| Error::Unavailable)?;
        for scope in [
            &config.source,
            &config.export,
            &config.staging,
            &config.empty_templates,
        ] {
            if trace_directory.starts_with(scope) || scope.starts_with(&trace_directory) {
                return Err(Error::Unavailable);
            }
        }
        if config.builder_signers.starts_with(&trace_directory) {
            return Err(Error::Unavailable);
        }
        Self::open(config, move |prepared| async move {
            // One creation after prepare: the existing callback budget already runs.
            let Ok(mut journal) = PrivateStageJournal::create(&trace_directory, builder, peer)
            else {
                return CallbackOutcome::Unknown;
            };
            // One mutex owns the entire callback. Neither a waiter nor the
            // network can manufacture a new session or claim through here.
            let mut state = state.lock().await;
            match send_prepared(&mut state, prepared, &run, peer, &mut journal).await {
                Ok(()) => CallbackOutcome::PublishedLocal,
                Err(()) => CallbackOutcome::Unknown,
            }
        })
    }
}

/// The caller has already checked the fixed 64-character lowercase run.
pub(crate) fn bundle_topic(run: &str) -> TopicId {
    let mut hash = blake3::Hasher::new();
    hash.update(b"chinwag-bundle-bytes/v1\0");
    hash.update(run.as_bytes());
    TopicId::from(*hash.finalize().as_bytes())
}

fn checked_plane(
    state: &EditState,
    builder: EndpointId,
    peer: EndpointId,
) -> Result<&DataPlane, ()> {
    let plane = state.bundle_peer().map_err(|_| ())?;
    if plane.endpoint_addr().id != builder || plane.pinned_peer_id() != peer {
        return Err(());
    }
    Ok(plane)
}

async fn send_prepared(
    state: &mut EditState,
    prepared: PreparedBundle,
    run: &str,
    peer: EndpointId,
    journal: &mut PrivateStageJournal,
) -> Result<(), ()> {
    let builder = EndpointId::from_bytes(&prepared.expectation().builder()).map_err(|_| ())?;
    let offer = BundleOffer::new(run, prepared.expectation().clone()).map_err(|_| ())?;
    state.prepare_bundle_peer().await.map_err(|_| ())?;
    let plane = checked_plane(state, builder, peer)?;
    let (sender, mut receiver) = plane
        .join_topic(bundle_topic(run))
        .await
        .map_err(|_| ())?
        .split();
    journal
        .record(
            Stage::SendJoinReturned,
            &observe_cached_ips(plane, state.bundle_peer_ips()),
        )
        .map_err(|_| ())?;
    receiver.joined().await.map_err(|_| ())?;
    journal
        .record(
            Stage::SendNeighborReturned,
            &observe_cached_ips(plane, state.bundle_peer_ips()),
        )
        .map_err(|_| ())?;
    let tag = checked_plane(state, builder, peer)?
        .publish_blob(prepared.into_bytes())
        .await
        .map_err(|_| ())?;
    if tag.hash().as_bytes() != &offer.expectation().hash() {
        return Err(());
    }
    let plane = checked_plane(state, builder, peer)?;
    sender
        .broadcast(offer.encode().map_err(|_| ())?.into())
        .await
        .map_err(|_| ())?;
    journal
        .record(
            Stage::SendOfferQueued,
            &observe_cached_ips(plane, state.bundle_peer_ips()),
        )
        .map_err(|_| ())?;
    loop {
        checked_plane(state, builder, peer)?;
        let event = receiver.next().await.ok_or(())?.map_err(|_| ())?;
        if let Event::Received(message) = event {
            // The first received body is final. A bad ack is uncertainty,
            // never permission to wait for a replacement or send again.
            let plane = checked_plane(state, builder, peer)?;
            if message.delivered_from != peer || message.content.len() > MAX_ACK_BYTES {
                return Err(());
            }
            BundleBytesAck::decode_for(&message.content, &offer).map_err(|_| ())?;
            journal
                .record(
                    Stage::SendAckReceived,
                    &observe_cached_ips(plane, state.bundle_peer_ips()),
                )
                .map_err(|_| ())?;
            drop(tag);
            return Ok(());
        }
    }
}
