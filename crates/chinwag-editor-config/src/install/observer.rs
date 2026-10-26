//! Readonly consistency observations. No variant grants completion or retry authority.
use super::{COMPLETED, Evidence, FixtureTarget, INTENT, LOCK, digest, fs::Image};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt};

const MAX_INTENT: usize = 4096;
const FIELDS: [&str; 8] = [
    "format",
    "target",
    "parent_dev",
    "parent_ino",
    "original_sha256",
    "staged_sha256",
    "staged_dev",
    "staged_ino",
];

/// Present facts only. Even matching installed bytes and inode do not prove fsync.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum ArtifactObservation {
    NoOperationArtifacts {
        target_sha256: Option<[u8; 32]>,
    },
    StagingOnly {
        staged_sha256: [u8; 32],
    },
    /// The intent records the original hash, not the original inode.
    IntentWithOriginalPreimage {
        evidence: Evidence,
    },
    IntentWithMatchingInstalledBytesAndInode {
        evidence: Evidence,
    },
    ChangedUnrecognizedOrAmbiguous {
        reason: &'static str,
    },
}
fn ambiguous(reason: &'static str) -> ArtifactObservation {
    ArtifactObservation::ChangedUnrecognizedOrAmbiguous { reason }
}

struct Fields<'a>(BTreeMap<String, &'a RawValue>);
impl<'de> Deserialize<'de> for Fields<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldsVisitor;
        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = Fields<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("exactly the eight unique intent fields")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !FIELDS.contains(&key.as_str()) || fields.contains_key(&key) {
                        return Err(serde::de::Error::custom(
                            "Unknown or duplicate intent field",
                        ));
                    }
                    fields.insert(key, map.next_value::<&'de RawValue>()?);
                }
                if fields.len() != FIELDS.len() {
                    return Err(serde::de::Error::custom("Missing intent field"));
                }
                Ok(Fields(fields))
            }
        }
        deserializer.deserialize_map(FieldsVisitor)
    }
}
fn hash(raw: &RawValue) -> Result<[u8; 32], &'static str> {
    let text: &str = serde_json::from_str(raw.get()).map_err(|_| "intent_hash_type")?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("intent_hash_encoding");
    }
    let mut result = [0; 32];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(result)
}
fn parse(bytes: &[u8], target: &'static str) -> Result<Evidence, &'static str> {
    if bytes.len() > MAX_INTENT {
        return Err("intent_limit");
    }
    let fields: Fields<'_> = serde_json::from_slice(bytes).map_err(|_| "intent_schema")?;
    let get = |name| fields.0.get(name).copied().ok_or("intent_schema");
    let format: &str = serde_json::from_str(get("format")?.get()).map_err(|_| "intent_format")?;
    let name: &str = serde_json::from_str(get("target")?.get()).map_err(|_| "intent_target")?;
    if format != "chinwag-private-config-intent/v1" || name != target {
        return Err("intent_format_or_target");
    }
    let original = get("original_sha256")?;
    let evidence = Evidence {
        target_basename: target,
        parent_dev: serde_json::from_str(get("parent_dev")?.get()).map_err(|_| "intent_device")?,
        parent_ino: serde_json::from_str(get("parent_ino")?.get()).map_err(|_| "intent_inode")?,
        original_sha256: if original.get() == "null" {
            None
        } else {
            Some(hash(original)?)
        },
        staged_sha256: hash(get("staged_sha256")?)?,
        staged_dev: serde_json::from_str(get("staged_dev")?.get()).map_err(|_| "intent_device")?,
        staged_ino: serde_json::from_str(get("staged_ino")?.get()).map_err(|_| "intent_inode")?,
    };
    if evidence.parent_ino == 0 || evidence.staged_ino == 0 {
        return Err("intent_zero_inode");
    }
    Ok(evidence)
}

#[derive(PartialEq, Eq)]
struct Snapshot {
    target: Option<Image>,
    staging: Option<Image>,
    intent: Option<Image>,
    completed: Option<Image>,
}
impl Snapshot {
    fn read(target: &FixtureTarget) -> Result<Self, &'static str> {
        Ok(Self {
            target: target.inner.anchor.read(target.inner.name)?,
            staging: target.inner.anchor.read(LOCK)?,
            intent: target.inner.anchor.read_bounded(INTENT, MAX_INTENT)?,
            completed: target.inner.anchor.read_bounded(COMPLETED, MAX_INTENT)?,
        })
    }
}
fn matches_staged(image: &Image, evidence: &Evidence) -> bool {
    image.id.dev == evidence.staged_dev
        && image.id.ino == evidence.staged_ino
        && digest(&image.bytes) == evidence.staged_sha256
}

/// Reads only the four fixed names. Retained guards remain in place in every case.
pub fn observe(target: &FixtureTarget) -> ArtifactObservation {
    observe_inner(target, || {})
}
fn observe_inner(target: &FixtureTarget, between_snapshots: impl FnOnce()) -> ArtifactObservation {
    let snapshot = (|| {
        let parent = target.inner.anchor.check()?;
        let before = Snapshot::read(target)?;
        between_snapshots();
        target.inner.anchor.check()?;
        let after = Snapshot::read(target)?;
        if before != after || target.inner.anchor.check()? != parent {
            return Err("observation_changed");
        }
        Ok::<_, &'static str>((parent, before))
    })();
    let (parent, snapshot) = match snapshot {
        Ok(value) => value,
        Err(reason) => return ambiguous(reason),
    };
    if snapshot.completed.is_some() {
        return ambiguous("completion_artifact_present_no_authority");
    }
    let Some(intent) = snapshot.intent else {
        return match snapshot.staging {
            None => ArtifactObservation::NoOperationArtifacts {
                target_sha256: snapshot.target.as_ref().map(|image| digest(&image.bytes)),
            },
            Some(image) => ArtifactObservation::StagingOnly {
                staged_sha256: digest(&image.bytes),
            },
        };
    };
    let evidence = match parse(&intent.bytes, target.inner.name) {
        Ok(value) => value,
        Err(reason) => return ambiguous(reason),
    };
    if evidence.parent_dev != parent.dev || evidence.parent_ino != parent.ino {
        return ambiguous("intent_parent_mismatch");
    }
    match (snapshot.staging, snapshot.target) {
        (Some(staging), original)
            if matches_staged(&staging, &evidence)
                && original.as_ref().map(|image| digest(&image.bytes))
                    == evidence.original_sha256 =>
        {
            ArtifactObservation::IntentWithOriginalPreimage { evidence }
        }
        (None, Some(installed)) if matches_staged(&installed, &evidence) => {
            ArtifactObservation::IntentWithMatchingInstalledBytesAndInode { evidence }
        }
        _ => ambiguous("intent_artifact_mismatch"),
    }
}

#[cfg(test)]
#[path = "observer_tests.rs"]
mod tests;
