//! Native, local-only durable wait control. This module never calls an LLM.
#![forbid(unsafe_code)]
use crate::{
    bus_wait_core::{Cursor, DeliveryState},
    bus_wait_grant::{Authority, HostGrant, owner_payload},
    bus_wait_journal::{anchored_snapshot, snapshot},
    bus_wait_message::{decode, hash},
    bus_wait_store::{PrivateStore, random_token, read_private_path},
};
use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
type Result<T> = std::result::Result<T, String>;
type Flags = BTreeMap<String, String>;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn required<'a>(f: &'a Flags, k: &str) -> Result<&'a str> {
    f.get(k)
        .map(String::as_str)
        .ok_or_else(|| format!("MISSING_{k}"))
}
fn parse(args: &[String]) -> Result<Flags> {
    let mut flags = Flags::new();
    let mut i = 0;
    while i < args.len() {
        let key = &args[i];
        if matches!(key.as_str(), "--handoff-token" | "--token") {
            return Err("INSECURE_TOKEN_ARGV_FORBIDDEN".into());
        }
        let boolean = matches!(
            key.as_str(),
            "--current-tail" | "--json" | "--handoff-token-stdin"
        );
        if !matches!(
            key.as_str(),
            "--repo"
                | "--for"
                | "--grant-file"
                | "--current-tail"
                | "--json"
                | "--since-seq"
                | "--since-id"
                | "--timeout-secs"
                | "--delivery-id"
                | "--admission-request-id"
                | "--msg-id"
                | "--digest-sha256"
                | "--handoff-token-file"
                | "--handoff-token-stdin"
                | "--state"
                | "--admission-id"
                | "--turn-id"
                | "--owner-proof-file"
        ) {
            return Err("UNKNOWN_WAIT_FLAG".into());
        }
        let value = if boolean {
            "true".into()
        } else {
            i += 1;
            args.get(i)
                .filter(|v| !v.starts_with("--"))
                .ok_or("MISSING_FLAG_VALUE")?
                .clone()
        };
        if flags.insert(key.clone(), value).is_some() {
            return Err("DUPLICATE_WAIT_FLAG".into());
        }
        i += 1;
    }
    Ok(flags)
}
/// Walk every component with descriptor-relative NOFOLLOW; trust never comes
/// from the candidate checkout or a public key supplied on the bus/argv.
fn owner_public() -> Result<EndpointId> {
    use rustix::fs::{Mode, OFlags, open, openat};
    let home = std::env::var_os("HOME").ok_or("OWNER_HOME_MISSING")?;
    let path = PathBuf::from(home).join(".chinwag/signing/owner_ed25519.pub");
    if !path.is_absolute() {
        return Err("UNSAFE_OWNER_KEY".into());
    }
    let mut directory = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "OWNER_KEY_UNAVAILABLE")?,
    );
    let components = path.components().collect::<Vec<_>>();
    for c in components.iter().skip(1).take(components.len() - 2) {
        let std::path::Component::Normal(name) = c else {
            return Err("UNSAFE_OWNER_KEY".into());
        };
        directory = File::from(
            openat(
                &directory,
                *name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "UNSAFE_OWNER_KEY")?,
        );
        let m = directory.metadata().map_err(|_| "OWNER_KEY_METADATA")?;
        if m.mode() & 0o7022 != 0
            || !matches!(m.uid(), 0) && m.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("UNSAFE_OWNER_KEY".into());
        }
    }
    let mut file = File::from(
        openat(
            &directory,
            "owner_ed25519.pub",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "OWNER_KEY_UNAVAILABLE")?,
    );
    let m = file.metadata().map_err(|_| "OWNER_KEY_METADATA")?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.nlink() != 1
        || m.mode() & 0o7022 != 0
        || m.len() > 4096
    {
        return Err("UNSAFE_OWNER_KEY".into());
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .map_err(|_| "OWNER_KEY_ENCODING")?;
    if let Ok(public) = raw.trim().parse::<EndpointId>() {
        return Ok(public);
    }
    let keys = chinwag_swarm::identity::parse_allowed_signers(&format!(
        "owner-agent@chinwag.sh {}",
        raw.trim()
    ));
    if keys.len() != 1 {
        return Err("OWNER_KEY_ENCODING".into());
    }
    EndpointId::from_bytes(&keys[0].1).map_err(|_| "OWNER_KEY_ENCODING".into())
}
fn authority(repo: &Path, actor: &str, pin: EndpointId) -> Result<Authority> {
    let store = PrivateStore::open(repo, "enrollments", actor)?;
    let a: Authority =
        serde_json::from_slice(&store.read_named_bytes("authority-state.json", 256 * 1024)?)
            .map_err(|_| "INVALID_OWNER_AUTHORITY")?;
    a.verify(pin)?;
    Ok(a)
}
fn grant(repo: &Path, actor: &str, pin: EndpointId) -> Result<(HostGrant, String)> {
    let store = PrivateStore::open(repo, "enrollments", actor)?;
    let grant: HostGrant = store.read()?.ok_or("HOST_NOT_ENROLLED")?;
    grant.verify(&authority(repo, actor, pin)?, pin, actor, now())?;
    let digest = hash(&serde_json::to_vec(&grant).map_err(|_| "GRANT_ENCODING")?);
    Ok((grant, digest))
}
fn load(store: &PrivateStore, g: &HostGrant, digest: &str) -> Result<Cursor> {
    let c: Cursor = store.read()?.ok_or("CURSOR_NOT_ENROLLED")?;
    c.validate(g, digest)?;
    Ok(c)
}
fn save(store: &PrivateStore, expected: u64, c: &mut Cursor) -> Result<()> {
    let lock = store.lock()?;
    let old: Cursor = store.read()?.ok_or("CURSOR_NOT_ENROLLED")?;
    if old.version != expected {
        return Err("CURSOR_VERSION_CHANGED".into());
    }
    if serde_json::to_value(&old).map_err(|_| "CURSOR_ENCODING")?
        == serde_json::to_value(&*c).map_err(|_| "CURSOR_ENCODING")?
    {
        return Ok(());
    }
    c.version = expected.checked_add(1).ok_or("CURSOR_VERSION_OVERFLOW")?;
    lock.write(c)
}
fn enroll(repo: &Path, actor: &str, flags: &Flags, pin: EndpointId) -> Result<serde_json::Value> {
    let raw = read_private_path(Path::new(required(flags, "--grant-file")?), 256 * 1024)?;
    let g: HostGrant = serde_json::from_slice(&raw).map_err(|_| "INVALID_ENROLLMENT")?;
    g.verify(&authority(repo, actor, pin)?, pin, actor, now())?;
    let digest = hash(&serde_json::to_vec(&g).map_err(|_| "GRANT_ENCODING")?);
    let journal = snapshot(repo)?;
    let mut c = Cursor::new(
        &g,
        digest,
        if flags.contains_key("--current-tail") {
            "CurrentTailAtEnrollment"
        } else {
            "ExplicitWatermarkSeq"
        }
        .into(),
    );
    let anchor = if flags.contains_key("--current-tail") {
        if flags.contains_key("--since-seq") || flags.contains_key("--since-id") {
            return Err("AMBIGUOUS_BACKLOG_POLICY".into());
        }
        journal.rows.last()
    } else {
        let seq: u64 = required(flags, "--since-seq")?
            .parse()
            .map_err(|_| "INVALID_WATERMARK")?;
        let id = required(flags, "--since-id")?;
        if seq == 0 && id == "GENESIS" {
            None
        } else {
            Some(
                journal
                    .rows
                    .iter()
                    .find(|m| m.seq == seq && m.id == id)
                    .ok_or("CURSOR_ANCHOR_MISSING")?,
            )
        }
    };
    if let Some(m) = anchor {
        c.last_scanned_seq = m.seq;
        c.last_scanned_id = m.id.clone();
        c.last_scanned_digest = m.digest_sha256.clone();
    }
    c.last_scanned_inode = journal.inode;
    c.last_scanned_line1_digest = journal.first_digest;
    let enrollments = PrivateStore::open(repo, "enrollments", actor)?;
    let cursors = PrivateStore::open(repo, "cursors", actor)?;
    // Enrollment is create-only. An interrupted two-file creation is held,
    // never repaired by resetting existing quota/cursor state.
    let enrollment_lock = enrollments.lock()?;
    let cursor_lock = cursors.lock()?;
    if enrollments.read::<HostGrant>()?.is_some() || cursors.read::<Cursor>()?.is_some() {
        return Err("ENROLLMENT_ALREADY_EXISTS_OR_INCOMPLETE".into());
    }
    cursor_lock.write(&c)?;
    enrollment_lock.write(&g)?;
    Ok(
        json!({"schema":"chinwag.host.enrollment-receipt.v1","actor":actor,"grant_id":g.grant_id,"grant_digest_sha256":c.grant_digest_sha256,
        "backlog_policy":c.backlog_policy,"enrolled_at_seq":c.last_scanned_seq,"enrolled_at_id":c.last_scanned_id,"scope":"LOCAL_ENROLLMENT_ONLY"}),
    )
}
fn token(flags: &Flags) -> Result<String> {
    if flags.contains_key("--handoff-token-file") && flags.contains_key("--handoff-token-stdin") {
        return Err("AMBIGUOUS_TOKEN_SOURCE".into());
    }
    let bytes = if let Some(path) = flags.get("--handoff-token-file") {
        read_private_path(Path::new(path), 65)?
    } else if flags.contains_key("--handoff-token-stdin") {
        let mut bytes = vec![];
        std::io::stdin()
            .take(66)
            .read_to_end(&mut bytes)
            .map_err(|_| "UNAUTHORIZED_WAIT_ACK")?;
        bytes
    } else {
        return Err("UNAUTHORIZED_WAIT_ACK".into());
    };
    let text = String::from_utf8(bytes).map_err(|_| "UNAUTHORIZED_WAIT_ACK")?;
    let text = text.trim_end_matches('\n');
    decode::<32>(text).map_err(|_| "UNAUTHORIZED_WAIT_ACK")?;
    Ok(text.into())
}
fn ack(repo: &Path, actor: &str, f: &Flags, pin: EndpointId) -> Result<serde_json::Value> {
    let (g, digest) = grant(repo, actor, pin)?;
    let secret = token(f)?;
    let token_hash = hash(secret.as_bytes());
    let store = PrivateStore::open(repo, "cursors", actor)?;
    let mut c = {
        let _lock = store.lock()?;
        load(&store, &g, &digest)?
    };
    let version = c.version;
    let delivery = required(f, "--delivery-id")?;
    let request = required(f, "--admission-request-id")?;
    let message = required(f, "--msg-id")?;
    let original_digest = required(f, "--digest-sha256")?;
    let state = required(f, "--state")?;
    let index = c
        .pending_deliveries
        .iter()
        .position(|p| p.delivery_id == delivery);
    if let Some(index) = index {
        let p = &c.pending_deliveries[index];
        if p.admission_request_id != request
            || !p
                .messages
                .iter()
                .any(|m| m.id == message && m.digest_sha256 == original_digest)
            || !bool::from(
                p.handoff_token_sha256
                    .as_deref()
                    .unwrap_or("")
                    .as_bytes()
                    .ct_eq(token_hash.as_bytes()),
            )
        {
            return Err("UNAUTHORIZED_WAIT_ACK".into());
        }
        c.acknowledge(
            index,
            state,
            f.get("--admission-id").map(String::as_str),
            f.get("--turn-id").map(String::as_str),
            now(),
        )?;
        if state == "PENDING_ACTIVE_TURN" {
            let journal = anchored_snapshot(repo, &mut c)?;
            c.coalesce_active(index, &journal.rows, &g, now())?;
            c.last_scanned_inode = journal.inode;
            c.last_scanned_line1_digest = journal.first_digest;
        }
        // Recheck current signed authority immediately before committing.
        grant(repo, actor, pin)?;
        save(&store, version, &mut c)?;
        if state == "PROCESSED" {
            store.remove_token(delivery)?;
        }
    } else {
        let done = c
            .completed_deliveries
            .iter()
            .find(|p| p.delivery_id == delivery)
            .ok_or("UNKNOWN_DELIVERY")?;
        if state != "PROCESSED"
            || done.admission_request_id != request
            || f.get("--turn-id") != Some(&done.turn_id)
            || !done
                .witnesses
                .iter()
                .any(|w| w.id == message && w.digest == original_digest)
            || !bool::from(done.token_sha256.as_bytes().ct_eq(token_hash.as_bytes()))
        {
            return Err("UNAUTHORIZED_WAIT_ACK".into());
        }
        store.remove_token(delivery)?;
    }
    let pending_messages = c
        .pending_deliveries
        .iter()
        .find(|p| p.delivery_id == delivery)
        .map(|p| &p.messages);
    Ok(
        json!({"schema":"chinwag.bus.wait-ack.v1","actor":actor,"delivery_id":delivery,"state":state,
        "scope":"LOCAL_HOST_LIFECYCLE_ONLY","content_disposition":"DATA_ONLY","pending_messages":pending_messages}),
    )
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconciliation {
    schema: String,
    actor: String,
    delivery_id: String,
    admission_request_id: String,
    expected_cursor_version: u64,
    expires_at_unix: u64,
    outcome: String,
    issuer_pubkey_ed25519: String,
    issuer_signature_ed25519: String,
}
fn reconcile(repo: &Path, actor: &str, f: &Flags, pin: EndpointId) -> Result<serde_json::Value> {
    let (g, digest) = grant(repo, actor, pin)?;
    let proof: Reconciliation = serde_json::from_slice(&read_private_path(
        Path::new(required(f, "--owner-proof-file")?),
        64 * 1024,
    )?)
    .map_err(|_| "INVALID_OWNER_PROOF")?;
    if proof.schema != "chinwag.bus.wait-reconciliation.v1"
        || proof.actor != actor
        || proof.issuer_pubkey_ed25519 != pin.to_string()
        || proof.expires_at_unix < now()
        || proof.expires_at_unix > 9_007_199_254_740_991
        || proof.outcome != "NEVER_RECEIVED"
    {
        return Err("INVALID_OWNER_PROOF".into());
    }
    pin.verify(
        &owner_payload("chinwag-wait-reconciliation-v1|", &proof)?,
        &Signature::from_bytes(&decode::<64>(&proof.issuer_signature_ed25519)?),
    )
    .map_err(|_| "INVALID_OWNER_SIGNATURE")?;
    let store = PrivateStore::open(repo, "cursors", actor)?;
    let mut c = {
        let _lock = store.lock()?;
        load(&store, &g, &digest)?
    };
    let version = c.version;
    if version != proof.expected_cursor_version {
        return Err("CURSOR_VERSION_CHANGED".into());
    }
    let p = c
        .pending_deliveries
        .iter_mut()
        .find(|p| {
            p.delivery_id == proof.delivery_id
                && p.admission_request_id == proof.admission_request_id
        })
        .ok_or("UNKNOWN_DELIVERY")?;
    if p.state != DeliveryState::HeldUncertainPreAckOutcome || !p.quota_reserved || p.quota_charged
    {
        return Err("OWNER_RECONCILIATION_UNSUPPORTED_OUTCOME".into());
    }
    p.state = DeliveryState::Received;
    p.handoff_token_sha256 = None;
    let lock = store.lock()?;
    let current = load(&store, &g, &digest)?;
    if current.version != version {
        return Err("CURSOR_VERSION_CHANGED".into());
    }
    store.remove_token(&proof.delivery_id)?;
    c.version += 1;
    lock.write(&c)?;
    Ok(
        json!({"schema":"chinwag.bus.wait-reconciliation-receipt.v1","scope":"OWNER_ASSERTED_NEVER_RECEIVED","quota_preserved":true,"actor":actor,"delivery_id":proof.delivery_id}),
    )
}

fn wait<F>(
    repo: &Path,
    actor: &str,
    f: &Flags,
    pin: EndpointId,
    mut changed: F,
) -> Result<(u8, serde_json::Value)>
where
    F: FnMut(&Path, u64, u64, u64) -> Result<bool>,
{
    let timeout: u64 = f
        .get("--timeout-secs")
        .map(String::as_str)
        .unwrap_or("300")
        .parse()
        .map_err(|_| "INVALID_TIMEOUT")?;
    if !(1..=3600).contains(&timeout) {
        return Err("INVALID_TIMEOUT".into());
    }
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let store = PrivateStore::open(repo, "cursors", actor)?;
    loop {
        let (g, digest) = grant(repo, actor, pin)?;
        let mut c = {
            let _lock = store.lock()?;
            load(&store, &g, &digest)?
        };
        let version = c.version;
        if let Some(index) = c
            .pending_deliveries
            .iter()
            .position(|p| p.state != DeliveryState::Received)
        {
            c.hold_uncertain(index)?;
            save(&store, version, &mut c)?;
            return Ok((
                75,
                json!({"status":"UNKNOWN","reason":"HOST_RECOVERY_LOOKUP_UNSUPPORTED","state":c.pending_deliveries[index].state,"host_admitted_at_unix":c.pending_deliveries[index].host_admitted_at_unix,"host_turn_started_at_unix":c.pending_deliveries[index].host_turn_started_at_unix}),
            ));
        }
        let journal = anchored_snapshot(repo, &mut c)?;
        c.scan(&journal.rows, &g, now())?;
        c.last_scanned_inode = journal.inode;
        c.last_scanned_line1_digest = journal.first_digest;
        if let Some(index) = c
            .pending_deliveries
            .iter()
            .position(|p| p.state == DeliveryState::Received)
        {
            let secret = random_token()?;
            c.reserve(index, hash(secret.as_bytes()))?;
            let p = c.pending_deliveries[index].clone();
            let envelope = json!({"schema":"chinwag.bus.wait-delivery.v1","content_disposition":"DATA_ONLY","actor":actor,"conversation_id":g.conversation_id,
                "grant_ref":{"grant_id":g.grant_id,"authority_epoch":g.authority_epoch,"grant_digest_sha256":digest},"delivery_id":p.delivery_id,
                "admission_request_id":p.admission_request_id,"state":p.state,"handoff_token_file":store.token_path(repo,&p.delivery_id)?,"messages":p.messages,
                "host_admitted_at_unix":null,"host_turn_started_at_unix":null});
            if serde_json::to_vec(&envelope)
                .map_err(|_| "ENVELOPE_ENCODING")?
                .len()
                > 262144
            {
                return Err("BACKPRESSURE_PENDING_FULL".into());
            }
            grant(repo, actor, pin)?;
            {
                let lock = store.lock()?;
                let current = load(&store, &g, &digest)?;
                if current.version != version {
                    return Err("CURSOR_VERSION_CHANGED".into());
                }
                if current.pending_deliveries.iter().any(|old| {
                    old.delivery_id == p.delivery_id
                        && (old.state != DeliveryState::Received
                            || old.handoff_token_sha256.is_some())
                }) {
                    return Err("OWNER_RECONCILIATION_REQUIRED".into());
                }
                // An orphan here predates the atomic reservation commit; no
                // envelope could have escaped. Never clear a committed token.
                store.clear_uncommitted_token(&p.delivery_id)?;
                store.write_new_token(&p.delivery_id, &secret)?;
                c.version = version + 1;
                lock.write(&c)?;
            }
            return Ok((0, envelope));
        }
        save(&store, version, &mut c)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok((124, json!({"status":"TIMEOUT","actor":actor})));
        }
        // Server subscribes before comparing this exact journal mark. Any append
        // between catch-up and subscription forces immediate rescan, closing the gap.
        if !changed(repo, journal.len, journal.inode, remaining.as_secs().max(1))? {
            return Ok((124, json!({"status":"TIMEOUT","actor":actor})));
        }
    }
}
pub fn run<F>(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write, changed: F) -> u8
where
    F: FnMut(&Path, u64, u64, u64) -> Result<bool>,
{
    let result = (|| {
        let f = parse(&args[1..])?;
        let repo = Path::new(required(&f, "--repo")?);
        if !repo.is_absolute() {
            return Err("ABSOLUTE_REPO_REQUIRED".into());
        }
        let actor = required(&f, "--for")?;
        crate::agent_instance::ActorAddress::parse(actor)
            .and_then(crate::agent_instance::ActorAddress::require_instance)
            .map_err(|_| "QUALIFIED_ACTOR_REQUIRED")?;
        let pin = owner_public()?;
        match args[0].as_str() {
            "enroll-host" => Ok((0, enroll(repo, actor, &f, pin)?)),
            "wait-ack" => Ok((0, ack(repo, actor, &f, pin)?)),
            "wait-reconcile" => Ok((0, reconcile(repo, actor, &f, pin)?)),
            "wait" => wait(repo, actor, &f, pin, changed),
            _ => Err("UNKNOWN_WAIT_COMMAND".into()),
        }
    })();
    match result {
        Ok((code, value)) => {
            if serde_json::to_writer(&mut *stdout, &value).is_err()
                || writeln!(stdout).is_err()
                || stdout.flush().is_err()
            {
                return 74;
            }
            code
        }
        Err(error) => {
            let _ = writeln!(stderr, "chinwag bus wait HELD: {error}");
            if error.contains("OFFLINE") || error.contains("UNSUPPORTED") || error.contains("HELD")
            {
                75
            } else {
                2
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus_federation::BusMessage;
    use crate::bus_wait_core::Delivery;
    use crate::bus_wait_message::hex;
    use iroh::SecretKey;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        owner: SecretKey,
        grant: HostGrant,
    }
    impl Fixture {
        fn new(actor: &str, room: &str, task: &str) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(temp.path()).unwrap();
            let owner = SecretKey::generate();
            let instance = actor.split_once('#').unwrap().1;
            let mut grant = HostGrant {
                schema: "chinwag.host.enrollment.v3".into(),
                grant_id: "fixture-grant".into(),
                authority_epoch: 1,
                actor: actor.into(),
                host_kind: "antigravity_bg_task".into(),
                host_version: "fixture".into(),
                host_node: None,
                conversation_id: instance.into(),
                supports_idempotent_admission_lookup: false,
                allow_legacy_plaintext: true,
                owner: "fixture owner".into(),
                granted_capabilities: vec!["bus_wait".into(), "same_chat_wake".into()],
                allowed_rooms: vec![room.into()],
                allowed_tasks: vec![task.into()],
                max_turns_quota: 32,
                enrolled_at_unix: now() - 1,
                expires_at_unix: now() + 3600,
                issuer_pubkey_ed25519: owner.public().to_string(),
                issuer_signature_ed25519: String::new(),
            };
            grant.issuer_signature_ed25519 = hex(&owner
                .sign(&owner_payload("chinwag-host-enrollment-v3|", &grant).unwrap())
                .to_bytes());
            let mut authority = Authority {
                schema: "chinwag.host.authority.v1".into(),
                min_authority_epoch: 1,
                revoked_grant_ids: vec![],
                issuer_pubkey_ed25519: owner.public().to_string(),
                issuer_signature_ed25519: String::new(),
            };
            authority.issuer_signature_ed25519 = hex(&owner
                .sign(&owner_payload("chinwag-host-authority-v1|", &authority).unwrap())
                .to_bytes());
            let e = PrivateStore::open(&root, "enrollments", actor).unwrap();
            let authority_path = root.join(".chinwag/bus/enrollments/authority-state.json");
            std::fs::write(&authority_path, serde_json::to_vec(&authority).unwrap()).unwrap();
            std::fs::set_permissions(&authority_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            e.lock().unwrap().write(&grant).unwrap();
            let c = Cursor::new(
                &grant,
                hash(&serde_json::to_vec(&grant).unwrap()),
                "ExplicitWatermarkSeq".into(),
            );
            PrivateStore::open(&root, "cursors", actor)
                .unwrap()
                .lock()
                .unwrap()
                .write(&c)
                .unwrap();
            Self {
                _temp: temp,
                root,
                owner,
                grant,
            }
        }
        fn store(&self) -> PrivateStore {
            PrivateStore::open(&self.root, "cursors", &self.grant.actor).unwrap()
        }
        fn cursor(&self) -> Cursor {
            self.store().read().unwrap().unwrap()
        }
        fn put(&self, c: &Cursor) {
            self.store().lock().unwrap().write(c).unwrap();
        }
        fn seed_pending(&self) {
            let mut c = self.cursor();
            let message:BusMessage=serde_json::from_value(json!({"id":"fixture-msg","seq":1,"ts_unix":1,"ts_iso":"fixture","room":"#eng","sender":"GEMINI-PM#fixture","sender_cast":"","sender_endpoint_id":"fixture","to":self.grant.actor,"task_id":"TEST","body":"fixture","digest_sha256":"d".repeat(64),"pubkey_ed25519":null,"signature_ed25519":null,"sig_verified":false})).unwrap();
            // Trusted private-state fixture tests handoff mechanics only. Crypto
            // interoperability uses the separate preserved-original integration.
            c.pending_deliveries.push(Delivery {
                delivery_id: "a".repeat(64),
                admission_request_id: "admreq-fixture".into(),
                state: DeliveryState::Received,
                messages: vec![message],
                handoff_token_sha256: None,
                quota_reserved: false,
                quota_charged: false,
                admission_id: None,
                turn_id: None,
                first_seen_at_unix: now(),
                host_admitted_at_unix: None,
                host_turn_started_at_unix: None,
            });
            self.put(&c);
        }
        fn ack_flags(&self, token_file: &Path, state: &str) -> Flags {
            BTreeMap::from([
                ("--delivery-id".into(), "a".repeat(64)),
                ("--admission-request-id".into(), "admreq-fixture".into()),
                ("--msg-id".into(), "fixture-msg".into()),
                ("--digest-sha256".into(), "d".repeat(64)),
                ("--state".into(), state.into()),
                (
                    "--handoff-token-file".into(),
                    token_file.to_string_lossy().into(),
                ),
            ])
        }
    }

    #[test]
    fn r1_held_restarts_preserve_classification_quota_witnesses_and_version() {
        for queued in [false, true] {
            let f = Fixture::new("WORKHORSE#fixture", "#eng", "TEST");
            f.seed_pending();
            let mut c = f.cursor();
            c.reserve(0, "e".repeat(64)).unwrap();
            if queued {
                c.acknowledge(0, "PENDING_ACTIVE_TURN", Some("queued"), None, now())
                    .unwrap();
            }
            f.put(&c);
            let call = || {
                wait(
                    &f.root,
                    &f.grant.actor,
                    &Flags::new(),
                    f.owner.public(),
                    |_, _, _, _| panic!("held work cannot be reissued"),
                )
            };
            assert_eq!(call().unwrap().0, 75);
            let held = f.cursor();
            assert_eq!(
                held.pending_deliveries[0].state,
                if queued {
                    DeliveryState::HeldUncertainHostOutcome
                } else {
                    DeliveryState::HeldUncertainPreAckOutcome
                }
            );
            assert_eq!((held.turns_reserved, held.turns_used), (1, 0));
            for _ in 0..3 {
                assert_eq!(call().unwrap().0, 75);
                assert_eq!(
                    serde_json::to_value(f.cursor()).unwrap(),
                    serde_json::to_value(&held).unwrap()
                );
            }
        }
    }
    #[test]
    fn r1_idle_save_is_noop_and_stale_save_is_rejected() {
        let f = Fixture::new("WORKHORSE#fixture", "#eng", "TEST");
        let mut c = f.cursor();
        let version = c.version;
        save(&f.store(), version, &mut c).unwrap();
        assert_eq!(f.cursor().version, version);
        let mut newer = c.clone();
        newer.version += 1;
        f.put(&newer);
        assert_eq!(
            save(&f.store(), version, &mut c).unwrap_err(),
            "CURSOR_VERSION_CHANGED"
        );
        assert_eq!(f.cursor().version, version + 1);
        let store = f.store();
        let _lock = store.lock().unwrap();
        assert!(
            wait(
                &f.root,
                &f.grant.actor,
                &Flags::new(),
                f.owner.public(),
                |_, _, _, _| Ok(false)
            )
            .is_err()
        );
    }
    #[test]
    fn timeout_and_offline_release_lock_without_claiming_host_admission() {
        let f = Fixture::new("WORKHORSE#fixture", "#eng", "TEST");
        let args = Flags::from([("--timeout-secs".into(), "5".into())]);
        let mut calls = 0;
        let (code, value) = wait(
            &f.root,
            &f.grant.actor,
            &args,
            f.owner.public(),
            |_, _, _, seconds| {
                calls += 1;
                assert!(seconds <= 5);
                assert!(f.store().lock().is_ok());
                Ok(false)
            },
        )
        .unwrap();
        assert_eq!(code, 124);
        assert_eq!(value["status"], "TIMEOUT");
        assert_eq!(calls, 1);
        assert!(f.cursor().pending_deliveries.is_empty());
        assert_eq!(f.cursor().turns_used, 0);
        assert!(
            wait(
                &f.root,
                &f.grant.actor,
                &args,
                f.owner.public(),
                |_, _, _, _| Err("WAKE_HOST_OFFLINE".into())
            )
            .unwrap_err()
            .contains("OFFLINE")
        );
        assert!(f.store().lock().is_ok());
    }
    #[test]
    fn durable_handoff_ack_auth_and_all_lifecycle_states_preserve_one_quota_slot() {
        let f = Fixture::new("WORKHORSE#fixture", "#eng", "TEST");
        f.seed_pending();
        // Crash before the cursor reservation can leave a private token orphan.
        f.store()
            .write_new_token(&"a".repeat(64), &"b".repeat(64))
            .unwrap();
        let (code, envelope) = wait(
            &f.root,
            &f.grant.actor,
            &Flags::new(),
            f.owner.public(),
            |_, _, _, _| panic!("ready pending batch must not block"),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(envelope["content_disposition"], "DATA_ONLY");
        assert!(f.store().lock().is_ok());
        let token_file = PathBuf::from(envelope["handoff_token_file"].as_str().unwrap());
        assert_eq!(
            std::fs::metadata(&token_file).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!((f.cursor().turns_reserved, f.cursor().turns_used), (1, 0));
        let mut args = f.ack_flags(&token_file, "HOST_ADMITTED");
        args.insert("--admission-id".into(), "admission".into());
        let mut wrong = args.clone();
        wrong.insert("--msg-id".into(), "wrong".into());
        assert!(
            ack(&f.root, &f.grant.actor, &wrong, f.owner.public())
                .unwrap_err()
                .contains("UNAUTHORIZED")
        );
        let wrong_file = f.root.join("wrong-token");
        std::fs::write(&wrong_file, "c".repeat(64)).unwrap();
        std::fs::set_permissions(&wrong_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        wrong = args.clone();
        wrong.insert(
            "--handoff-token-file".into(),
            wrong_file.to_string_lossy().into(),
        );
        assert!(
            ack(&f.root, &f.grant.actor, &wrong, f.owner.public())
                .unwrap_err()
                .contains("UNAUTHORIZED")
        );
        let mut premature = args.clone();
        premature.insert("--turn-id".into(), "premature".into());
        assert!(ack(&f.root, &f.grant.actor, &premature, f.owner.public()).is_err());
        for state in [
            "HOST_CALL_DISPATCHING",
            "PENDING_ACTIVE_TURN",
            "HOST_ADMITTED",
        ] {
            args.insert("--state".into(), state.into());
            ack(&f.root, &f.grant.actor, &args, f.owner.public()).unwrap();
        }
        assert_eq!((f.cursor().turns_reserved, f.cursor().turns_used), (0, 1));
        assert!(
            f.cursor().pending_deliveries[0]
                .host_turn_started_at_unix
                .is_none()
        );
        args.insert("--state".into(), "HOST_TURN_STARTED".into());
        args.insert("--turn-id".into(), "turn".into());
        ack(&f.root, &f.grant.actor, &args, f.owner.public()).unwrap();
        args.insert("--state".into(), "PROCESSED".into());
        ack(&f.root, &f.grant.actor, &args, f.owner.public()).unwrap();
        assert!(!token_file.exists());
        assert!(f.cursor().pending_deliveries.is_empty());
        assert_eq!(f.cursor().completed_recent_digests.len(), 1);
    }
    #[test]
    fn restart_before_ack_holds_unknown_and_owner_reconciliation_cannot_reset_quota() {
        let f = Fixture::new("WORKHORSE#fixture", "#eng", "TEST");
        f.seed_pending();
        wait(
            &f.root,
            &f.grant.actor,
            &Flags::new(),
            f.owner.public(),
            |_, _, _, _| Ok(false),
        )
        .unwrap();
        let (code, value) = wait(
            &f.root,
            &f.grant.actor,
            &Flags::new(),
            f.owner.public(),
            |_, _, _, _| panic!("uncertain host must not be retried"),
        )
        .unwrap();
        assert_eq!(code, 75);
        assert_eq!(value["state"], "HELD_UNCERTAIN_PRE_ACK_OUTCOME");
        assert_eq!(f.cursor().turns_reserved, 1);
        let mut proof = Reconciliation {
            schema: "chinwag.bus.wait-reconciliation.v1".into(),
            actor: f.grant.actor.clone(),
            delivery_id: "a".repeat(64),
            admission_request_id: "admreq-fixture".into(),
            expected_cursor_version: f.cursor().version,
            expires_at_unix: now() + 60,
            outcome: "NEVER_RECEIVED".into(),
            issuer_pubkey_ed25519: f.owner.public().to_string(),
            issuer_signature_ed25519: String::new(),
        };
        proof.issuer_signature_ed25519 = hex(&f
            .owner
            .sign(&owner_payload("chinwag-wait-reconciliation-v1|", &proof).unwrap())
            .to_bytes());
        let proof_file = f.root.join("owner-proof");
        std::fs::write(&proof_file, serde_json::to_vec(&proof).unwrap()).unwrap();
        std::fs::set_permissions(&proof_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let flags = Flags::from([(
            "--owner-proof-file".into(),
            proof_file.to_string_lossy().into(),
        )]);
        reconcile(&f.root, &f.grant.actor, &flags, f.owner.public()).unwrap();
        assert_eq!(f.cursor().turns_reserved, 1);
        wait(
            &f.root,
            &f.grant.actor,
            &Flags::new(),
            f.owner.public(),
            |_, _, _, _| Ok(false),
        )
        .unwrap();
        assert_eq!(f.cursor().turns_reserved, 1);
        assert!(reconcile(&f.root, &f.grant.actor, &flags, f.owner.public()).is_err()); // stale proof cannot be replayed.
    }
    #[test]
    #[ignore = "owner supplies preserved real native original through CHINWAG_INTEROP_FIXTURE"]
    fn preserved_original_drives_durable_handoff_without_resigning() {
        let bytes =
            std::fs::read_to_string(std::env::var("CHINWAG_INTEROP_FIXTURE").unwrap()).unwrap();
        let mut message = bytes
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|v| {
                serde_json::from_value::<BusMessage>(v.get("message").unwrap_or(&v).clone()).ok()
            })
            .find(|m| m.id == "bus-1794264873-2b8773b6")
            .unwrap();
        crate::bus_wait_message::verify_original(&message).unwrap();
        message.seq = 1;
        let f = Fixture::new(
            message.to.as_deref().unwrap(),
            &message.room,
            message.task_id.as_deref().unwrap(),
        );
        let mut line = serde_json::to_vec(&message).unwrap();
        line.push(b'\n');
        let path = f.root.join(".chinwag/bus/messages.jsonl");
        std::fs::write(path, &line).unwrap();
        let (code, envelope) = wait(
            &f.root,
            &f.grant.actor,
            &Flags::new(),
            f.owner.public(),
            |_, _, _, _| panic!("verified existing original must catch up"),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(
            envelope["messages"][0]["digest_sha256"],
            message.digest_sha256
        );
        assert_eq!(f.cursor().turns_reserved, 1);
        assert_eq!(f.cursor().turns_used, 0);
    }
    #[test]
    fn argv_tokens_and_duplicate_flags_refuse() {
        assert!(
            parse(&["--token".into(), "secret".into()])
                .unwrap_err()
                .contains("INSECURE")
        );
        assert!(parse(&["--json".into(), "--json".into()]).is_err());
    }
}
