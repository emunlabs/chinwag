// Copyright (c) 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    ObjectSpec, PullPlan, digest, ingest,
    store::{connect, events_bytes, literal, private_dir},
};
#[cfg(test)]
use std::os::unix::fs::DirBuilderExt;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use zeroize::Zeroizing;
struct Reply {
    status: u16,
    declared: Option<u64>,
    body: Box<dyn Read>,
}
trait Transport {
    fn get(&mut self, url: &str) -> Result<Reply, String>;
}
struct Http {
    client: reqwest::blocking::Client,
    authorization: reqwest::header::HeaderValue,
}
impl Http {
    fn keychain() -> Result<Self, String> {
        use crate::pull_plan::{ACCOUNT, SERVICE};
        let mut command = Command::new("/usr/bin/security");
        command.args(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"]);
        let secret = crate::bounded_child::run(&mut command, Duration::from_secs(5), 4096)?;
        let token = std::str::from_utf8(&secret)
            .map_err(|_| "invalid credential encoding")?
            .trim_end_matches(['\r', '\n']);
        if token.len() < 16
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-=".contains(&b))
        {
            return Err("invalid credential encoding".into());
        }
        let header = Zeroizing::new(format!("Bearer {token}"));
        let mut authorization = reqwest::header::HeaderValue::from_str(&header)
            .map_err(|_| "invalid credential encoding")?;
        authorization.set_sensitive(true);
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| "HTTP client unavailable")?;
        Ok(Self {
            client,
            authorization,
        })
    }
}
impl Transport for Http {
    fn get(&mut self, url: &str) -> Result<Reply, String> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .send()
            .map_err(|_| "R2 read failed")?;
        Ok(Reply {
            status: response.status().as_u16(),
            declared: response.content_length(),
            body: Box::new(response),
        })
    }
}
fn download(
    transport: &mut impl Transport,
    plan: &PullPlan,
    object: &ObjectSpec,
) -> Result<Vec<u8>, String> {
    let response = transport.get(&plan.url(object)?)?;
    if response.status != 200 || response.declared.is_some_and(|n| n != object.size_bytes) {
        return Err("R2 status or declared size rejected".into());
    }
    let mut bytes = Vec::new();
    response
        .body
        .take(object.size_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "R2 body read failed")?;
    if bytes.len() as u64 != object.size_bytes || digest(&bytes) != object.sha256 {
        return Err("R2 object failed exact size/hash verification".into());
    }
    Ok(bytes)
}
struct Quarantine(PathBuf);
static NEXT: AtomicU64 = AtomicU64::new(0);
impl Quarantine {
    fn new(parent: &Path) -> Result<Self, String> {
        private_dir(parent)?;
        let path = parent.join(format!(
            ".history-pull-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        crate::namespace::mkdir_private(&path)?;
        Ok(Self(path))
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
        let path = self.0.join(name);
        let mut file = crate::namespace::create_file(&path)?;
        file.write_all(bytes)
            .map_err(|_| "quarantine write failed")?;
        file.sync_all().map_err(|_| "quarantine sync failed")?;
        Ok(path)
    }
}
impl Drop for Quarantine {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn preflight(plan: &PullPlan, root: &Path) -> Result<(), String> {
    plan.validate()?;
    private_dir(root)?;
    private_dir(root.parent().ok_or("dataset parent required")?)?;
    if fs::read_dir(root)
        .map_err(|_| "dataset unavailable")?
        .next()
        .is_some()
    {
        return Err("pull requires an empty isolated dataset root".into());
    }
    Ok(())
}
fn pull_with(
    plan: &PullPlan,
    root: &Path,
    transport: &mut impl Transport,
) -> Result<serde_json::Value, String> {
    preflight(plan, root)?;
    let jsonl = download(transport, plan, &plan.jsonl)?;
    let parquet = download(transport, plan, &plan.parquet)?;
    let mut expected = BTreeMap::new();
    for event in events_bytes(&jsonl)? {
        expected.insert(event.id.clone(), plan.manifest.approve(&event)?);
    }
    let quarantine = Quarantine::new(root.parent().ok_or("dataset parent required")?)?;
    let jsonl_path = quarantine.write("events.jsonl", &jsonl)?;
    let parquet_path = quarantine.write("events.parquet", &parquet)?;
    let path = literal(parquet_path.to_str().ok_or("invalid local path")?);
    let db = connect(Path::new(":memory:"))?;
    db.execute(&format!("SET allowed_paths=[{path}]; SET enable_external_access=false; CREATE TABLE incoming AS SELECT id,ts,body,event_json FROM read_parquet({path}) LIMIT 10001;")).map_err(|_|"invalid bounded Parquet dataset")?;
    let rows = db
        .query_rows_varchar("SELECT id,ts,body,event_json FROM incoming ORDER BY id LIMIT 10001")
        .map_err(|_| "invalid bounded Parquet dataset")?;
    if rows.len() != expected.len() {
        return Err("mixed or incomplete Parquet dataset".into());
    }
    for row in rows {
        let event: crate::Event =
            serde_json::from_str(&row[3]).map_err(|_| "invalid Parquet event")?;
        let canonical = plan.manifest.approve(&event)?;
        if row[0] != event.id
            || row[1] != event.timestamp_utc
            || row[2] != event.text
            || expected.remove(&event.id) != Some(canonical)
        {
            return Err("mixed or altered Parquet dataset".into());
        }
    }
    if !expected.is_empty() {
        return Err("missing Parquet events".into());
    }
    let mut receipt = ingest(&plan.manifest, &jsonl_path, root)?;
    receipt["cloud_read"] = serde_json::json!({"verified":true,"jsonl_sha256":plan.jsonl.sha256,"parquet_sha256":plan.parquet.sha256,"credential_ref":plan.credential_ref,"scope":"fixed_account_bucket_objects","local_parquet":"rederived_from_approved_jsonl"});
    Ok(receipt)
}
pub fn pull(plan: &PullPlan, root: &Path, network: bool) -> Result<serde_json::Value, String> {
    preflight(plan, root)?;
    if !network {
        return Err("network disabled; explicit --network required".into());
    }
    pull_with(plan, root, &mut Http::keychain()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Archive, Event, Manifest,
        model::{Channel, Role},
        pull_plan::{ACCOUNT, BUCKET, CREDENTIAL_REF},
    };
    use std::io::Cursor;
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let parent = PathBuf::from(std::env::var("TMPDIR").expect("owned TMPDIR required"));
            private_dir(&parent).unwrap();
            let p = parent.join(format!(
                "pull-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
        fn empty(&self, name: &str) -> PathBuf {
            let p = self.0.join(name);
            fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            p
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct Fake {
        jsonl: Vec<u8>,
        parquet: Vec<u8>,
        status: u16,
        declared_extra: u64,
    }
    impl Transport for Fake {
        fn get(&mut self, url: &str) -> Result<Reply, String> {
            assert!(url.starts_with("https://api.cloudflare.com/client/v4/accounts/a9dce15ce0193da7d7f1d5dd3a53022b/r2/buckets/chinwag-coordinator-history/objects/datasets/"));
            assert!(!url.contains("%2F"));
            let body = if url.ends_with(".jsonl") {
                self.jsonl.clone()
            } else {
                self.parquet.clone()
            };
            Ok(Reply {
                status: self.status,
                declared: Some(body.len() as u64 + self.declared_extra),
                body: Box::new(Cursor::new(body)),
            })
        }
    }
    fn fixture(s: &Scratch, chat: &str, name: &str) -> (PullPlan, Vec<u8>, Vec<u8>) {
        let event = Event {
            id: "event-1".into(),
            chat_id: chat.into(),
            timestamp_utc: "2026-11-10T00:00:00Z".into(),
            role: Role::Assistant,
            channel: Channel::Final,
            text: "verified fixture".into(),
            evidence: vec![],
            supersedes: None,
        };
        let canonical = event.canonical().unwrap();
        let bytes = format!("{canonical}\n").into_bytes();
        let manifest = Manifest {
            schema: 1,
            dataset_id: name.into(),
            bucket: BUCKET.into(),
            account_id: ACCOUNT.into(),
            coordinator_chat_id: chat.into(),
            approved_events: BTreeMap::from([(event.id.clone(), digest(canonical.as_bytes()))]),
        };
        let source = s.0.join(format!("{name}.jsonl"));
        fs::write(&source, &bytes).unwrap();
        let root = s.empty(name);
        ingest(&manifest, &source, &root).unwrap();
        let h = digest(&bytes);
        let parquet = fs::read(root.join("objects").join(format!("{h}.parquet"))).unwrap();
        let plan = PullPlan {
            schema: 1,
            manifest,
            credential_ref: CREDENTIAL_REF.into(),
            jsonl: ObjectSpec {
                key: format!("datasets/{name}/{h}.jsonl"),
                sha256: h.clone(),
                size_bytes: bytes.len() as u64,
            },
            parquet: ObjectSpec {
                key: format!("datasets/{name}/{h}.parquet"),
                sha256: digest(&parquet),
                size_bytes: parquet.len() as u64,
            },
        };
        (plan, bytes, parquet)
    }
    #[test]
    fn verified_pull_and_negative_inputs_leave_canonical_root_empty() {
        let s = Scratch::new();
        let (plan, jsonl, parquet) = fixture(&s, "chat-1", "dataset-1");
        let make = || Fake {
            jsonl: jsonl.clone(),
            parquet: parquet.clone(),
            status: 200,
            declared_extra: 0,
        };
        let root = s.empty("offline");
        assert!(pull(&plan, &root, false).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        for (status, extra) in [(302, 0), (307, 0), (403, 0), (200, 1)] {
            let root = s.empty(&format!("status-{status}-{extra}"));
            let mut fake = make();
            fake.status = status;
            fake.declared_extra = extra;
            assert!(pull_with(&plan, &root, &mut fake).is_err());
            assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        }
        for (name, mut fake) in [("tamper", make()), ("short", make()), ("oversize", make())] {
            if name == "tamper" {
                fake.jsonl[0] ^= 1;
            } else if name == "short" {
                fake.parquet.pop();
            } else {
                fake.jsonl.push(0);
            }
            let root = s.empty(name);
            assert!(pull_with(&plan, &root, &mut fake).is_err());
            assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        }
        let (_, other_jsonl, other_parquet) = fixture(&s, "other-seat", "dataset-2");
        let root = s.empty("mixed-parquet");
        let mut bad = plan.clone();
        bad.parquet.sha256 = digest(&other_parquet);
        bad.parquet.size_bytes = other_parquet.len() as u64;
        let mut fake = make();
        fake.parquet = other_parquet;
        assert!(pull_with(&bad, &root, &mut fake).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        let root = s.empty("mixed-jsonl");
        let mut bad = plan.clone();
        bad.jsonl.sha256 = digest(&other_jsonl);
        bad.jsonl.size_bytes = other_jsonl.len() as u64;
        bad.jsonl.key = format!("datasets/dataset-1/{}.jsonl", bad.jsonl.sha256);
        bad.parquet.key = format!("datasets/dataset-1/{}.parquet", bad.jsonl.sha256);
        let mut fake = make();
        fake.jsonl = other_jsonl;
        assert!(pull_with(&bad, &root, &mut fake).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        let root = s.empty("success");
        let receipt = pull_with(&plan, &root, &mut make()).unwrap();
        assert_eq!(receipt["cloud_read"]["verified"], true);
        assert_eq!(
            Archive::open(&root)
                .unwrap()
                .read_event("event-1")
                .unwrap()
                .text,
            "verified fixture"
        );
    }
}
