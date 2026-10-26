//! One explicitly selected native-identity denial. Never retries an unknown.
#![forbid(unsafe_code)]

use chinwag_claim::{ClaimRequestUnsigned, Pr, encode_hex, reply::PreparedClaim};
use chinwag_swarm::{
    DiscoveryScope,
    attempt_journal::{AttemptBinding, AttemptJournal, AttemptPhase},
    bind_sovereign_endpoint,
    identity::Identity,
    lan::LanInterfaces,
    room::{ClaimSubmission, RoomClient, RoomSession, now_unix},
};
use iroh::{EndpointId, address_lookup::memory::MemoryLookup};
use rand::{TryRngCore, rngs::OsRng};
use serde::Serialize;
use std::{
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};
use tokio::time::timeout;

const ORIGIN: &str = "https://bootstrap.chinwag.sh/";
const COORDINATOR: &str = "366eb665b85888a6b5f265d340b29d0623c6c92c96e6c0746c7b4554b5949919";
const A: &str = "63e44fbb5054e0730793b2be61daf203b912c7cc5777f86ebbfe5f73b096c3d0";
const B: &str = "df7676a8680f06f1cddb51a793be9a07a0d022638cb25ebe681dd42328867931";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    NoRoom,
    Active,
}
impl Mode {
    fn parse(text: &str) -> Result<Self, &'static str> {
        match text {
            "no-room" => Ok(Self::NoRoom),
            "active" => Ok(Self::Active),
            _ => Err("mode"),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::NoRoom => "no-room",
            Self::Active => "active",
        }
    }
    fn expected(self) -> (u16, &'static str) {
        match self {
            Self::NoRoom => (409, "claim_session"),
            Self::Active => (403, "claim_policy"),
        }
    }
}

#[derive(Serialize)]
struct Proof {
    kind: &'static str,
    mode: &'static str,
    actor: String,
    status: u16,
    code: String,
    cf_ray: String,
    durable_refusal_reloaded: bool,
}

fn random_id() -> Result<String, &'static str> {
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_| "random")?;
    Ok(encode_hex(&bytes))
}
fn require_empty_private_dir(path: &Path) -> Result<(), &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "journal_directory")?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err("journal_directory");
    }
    if std::fs::read_dir(path)
        .map_err(|_| "journal_directory")?
        .next()
        .is_some()
    {
        return Err("journal_not_empty");
    }
    Ok(())
}

async fn submit(
    client: &RoomClient,
    identity: &Identity,
    journal: &mut AttemptJournal,
    session: String,
    mode: Mode,
) -> Result<Proof, &'static str> {
    let issued = now_unix().map_err(|_| "clock")?;
    let expiry = issued.checked_add(60).ok_or("clock")?;
    let unsigned = ClaimRequestUnsigned {
        claim_id: random_id()?,
        actor: encode_hex(&identity.ssh_public_bytes()),
        session,
        nonce: random_id()?,
        pr: Pr::Pr01,
        files: vec!["crates/chinwag-seed/src/main.rs".into()],
        expected_revision: 0,
        issued,
        expiry,
    };
    let signed = identity.sign_claim(unsigned).map_err(|_| "sign_claim")?;
    let original = PreparedClaim::from_signed(signed).map_err(|_| "prepare_claim")?;
    let mut attempt = journal.arm(&original).map_err(|_| "arm_claim")?;
    let outcome = client
        .submit_original(journal, &mut attempt)
        .await
        .map_err(|_| "submission_error_preserve_original")?;
    let (status, code, cf_ray) = match outcome {
        ClaimSubmission::Refused {
            status,
            code,
            cf_ray,
        } => (status, code, cf_ray),
        ClaimSubmission::Unknown { .. } => return Err("unknown_preserve_original_stop"),
        ClaimSubmission::Historical { .. } | ClaimSubmission::ReportedFresh { .. } => {
            return Err("unexpected_signed_outcome_stop");
        }
    };
    if (status, code.as_str()) != mode.expected() {
        return Err("unexpected_refusal_stop");
    }
    let reloaded = journal
        .load()
        .map_err(|_| "reload_refusal")?
        .ok_or("missing_refusal")?;
    if reloaded.phase() != AttemptPhase::Refused
        || reloaded.id() != attempt.id()
        || reloaded.prepared().request_json() != original.request_json()
        || reloaded.prepared().wire_sha256() != original.wire_sha256()
    {
        return Err("refusal_mismatch_stop");
    }
    Ok(Proof {
        kind: "native_claim_denial",
        mode: mode.label(),
        actor: encode_hex(&identity.ssh_public_bytes()),
        status,
        code,
        cf_ray,
        durable_refusal_reloaded: true,
    })
}

async fn run() -> Result<Proof, &'static str> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage_KEY_PATH_EMPTY_JOURNAL_DIR_LAN_IPV4_no-room_or_active");
    }
    let key = PathBuf::from(&args[1]);
    let directory = PathBuf::from(&args[2]);
    let lan: Ipv4Addr = args[3].parse().map_err(|_| "selected_lan_ipv4")?;
    let mode = Mode::parse(&args[4])?;
    let identity = Identity::from_ssh_signing_file(&key).map_err(|_| "own_identity")?;
    let actor = encode_hex(&identity.ssh_public_bytes());
    let peer: EndpointId = match actor.as_str() {
        A => B,
        B => A,
        _ => return Err("unpinned_own_actor"),
    }
    .parse()
    .map_err(|_| "peer_pin")?;
    let coordinator: EndpointId = COORDINATOR.parse().map_err(|_| "coordinator_pin")?;
    if identity.endpoint_id() == coordinator {
        return Err("coordinator_is_actor");
    }
    require_empty_private_dir(&directory)?;
    let binding = AttemptBinding::new(ORIGIN, identity.ssh_public_bytes(), *coordinator.as_bytes())
        .map_err(|_| "binding")?;
    let mut journal = AttemptJournal::open(&directory, binding).map_err(|_| "open_journal")?;
    let client = RoomClient::new(
        ORIGIN,
        coordinator,
        std::sync::Arc::new(chinwag_swarm::relay_policy::RelayPolicy::Disabled),
    )
    .map_err(|_| "room_client")?;
    if mode == Mode::NoRoom {
        return submit(&client, &identity, &mut journal, random_id()?, mode).await;
    }
    let book = MemoryLookup::new();
    let interfaces = LanInterfaces::new(vec![lan]).map_err(|_| "selected_lan_ipv4")?;
    let endpoint = timeout(
        Duration::from_secs(3),
        bind_sovereign_endpoint(
            &identity,
            book.clone(),
            peer,
            interfaces,
            DiscoveryScope::RoomOnly,
            vec![b"chinwag-claim-denial-probe/v1".to_vec()],
            client.relay_policy(),
        ),
    )
    .await
    .map_err(|_| "endpoint_deadline")?
    .map_err(|_| "endpoint")?;
    let mut session: Option<RoomSession> = None;
    let result = timeout(Duration::from_secs(25), async {
        if endpoint.addr().relay_urls().next().is_some() {
            return Err("unexpected_relay");
        }
        let mut addresses = Vec::new();
        for _ in 0..100 {
            addresses = endpoint
                .addr()
                .ip_addrs()
                .copied()
                .filter(|address| address.ip() == std::net::IpAddr::V4(lan))
                .collect();
            if !addresses.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if addresses.is_empty() {
            return Err("no_selected_bound_address");
        }
        session = Some(
            client
                .open(&identity, peer, addresses, book)
                .await
                .map_err(|_| "room_open")?,
        );
        let id = session
            .as_ref()
            .ok_or("missing_room")?
            .attached_session_id()
            .map_err(|_| "missing_verified_attach")?
            .to_owned();
        submit(&client, &identity, &mut journal, id, mode).await
    })
    .await
    .map_err(|_| "active_deadline_preserve_original");
    if let Some(mut room) = session {
        room.close().await;
    }
    timeout(Duration::from_secs(2), endpoint.close())
        .await
        .map_err(|_| "endpoint_cleanup")?;
    result?
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(proof) => match serde_json::to_string(&proof) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("claim_probe_stop=output");
                ExitCode::FAILURE
            }
        },
        Err(category) => {
            eprintln!("claim_probe_stop={category}");
            ExitCode::FAILURE
        }
    }
}
