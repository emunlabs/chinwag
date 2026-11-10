// Copyright (c) 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{Manifest, digest, model::MAX_INPUT, read_bounded};
use serde::{Deserialize, Serialize};
use std::path::Path;
pub const ACCOUNT: &str = "a9dce15ce0193da7d7f1d5dd3a53022b";
pub const BUCKET: &str = "chinwag-coordinator-history";
pub const SERVICE: &str = "chinwag-coordinator-history-r2-readonly";
pub const CREDENTIAL_REF: &str = "macos-keychain:chinwag-coordinator-history-r2-readonly";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectSpec {
    pub key: String,
    pub sha256: String,
    pub size_bytes: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullPlan {
    pub schema: u32,
    pub manifest: Manifest,
    pub credential_ref: String,
    pub jsonl: ObjectSpec,
    pub parquet: ObjectSpec,
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b"abcdef".contains(&b))
}
impl PullPlan {
    pub fn load(path: &Path, expected: &str) -> Result<Self, String> {
        if !hash(expected) {
            return Err("invalid approved plan digest".into());
        }
        let bytes = read_bounded(path)?;
        if digest(&bytes) != expected {
            return Err("pull plan differs from approved digest".into());
        }
        let plan: Self = serde_json::from_slice(&bytes).map_err(|_| "invalid pull plan")?;
        plan.validate()?;
        Ok(plan)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.manifest.validate()?;
        if self.schema != 1 || self.credential_ref != CREDENTIAL_REF {
            return Err("unsupported pull credential binding".into());
        }
        let prefix = format!(
            "datasets/{}/{}",
            self.manifest.dataset_id, self.jsonl.sha256
        );
        if self.jsonl.key != format!("{prefix}.jsonl")
            || self.parquet.key != format!("{prefix}.parquet")
        {
            return Err("object is not in exact immutable dataset allowlist".into());
        }
        for object in [&self.jsonl, &self.parquet] {
            if !hash(&object.sha256) || object.size_bytes == 0 || object.size_bytes > MAX_INPUT {
                return Err("object outside byte/hash bound".into());
            }
        }
        Ok(())
    }
    pub fn url(&self, object: &ObjectSpec) -> Result<String, String> {
        self.validate()?;
        if object.key != self.jsonl.key && object.key != self.parquet.key {
            return Err("unapproved object".into());
        }
        let key = object.key.replace(':', "%3A");
        Ok(format!(
            "https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/r2/buckets/{BUCKET}/objects/{key}"
        ))
    }
    pub fn describe(&self) -> Result<serde_json::Value, String> {
        self.validate()?;
        Ok(
            serde_json::json!({"classification":"offline_pull_configuration","dataset_id":self.manifest.dataset_id,"account_id":ACCOUNT,"bucket":BUCKET,"credential_ref":CREDENTIAL_REF,"objects":[self.jsonl,self.parquet],"network":"disabled_without_explicit_flag","scope_verification":"requires_approved_bucket_readonly_credential_enrollment"}),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> PullPlan {
        PullPlan {
            schema: 1,
            manifest: Manifest {
                schema: 1,
                dataset_id: "dataset-1".into(),
                bucket: BUCKET.into(),
                account_id: ACCOUNT.into(),
                coordinator_chat_id: "chat-1".into(),
                approved_events: Default::default(),
            },
            credential_ref: CREDENTIAL_REF.into(),
            jsonl: ObjectSpec {
                key: format!("datasets/dataset-1/{}.jsonl", "a".repeat(64)),
                sha256: "a".repeat(64),
                size_bytes: 1,
            },
            parquet: ObjectSpec {
                key: format!("datasets/dataset-1/{}.parquet", "a".repeat(64)),
                sha256: "b".repeat(64),
                size_bytes: 1,
            },
        }
    }
    #[test]
    fn rejects_scope_path_size_and_credential_substitution() {
        let good = plan();
        assert!(good.validate().is_ok());
        let mut bad = good.clone();
        bad.manifest.bucket = "shared".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.manifest.account_id = "elsewhere".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.jsonl.key = "https://elsewhere/private".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.parquet.key = bad.parquet.key.replace("dataset-1", "dataset-2");
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.jsonl.size_bytes = MAX_INPUT + 1;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.credential_ref = "oauth-default".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.jsonl.sha256 = "../escape".into();
        assert!(bad.validate().is_err());
    }
}
