#![forbid(unsafe_code)]

//! Supervised P0 publisher, not an authorization service or recovery tool.
//! Its admission must already be accepted by the human/review workflow. Checked
//! fsync calls do not promise survival of every hardware failure. Safe owned-FD
//! destruction closes handles but cannot report close errors. Same-UID parent
//! replacement is excluded by the admitted cooperative publisher boundary.

use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, renameat, statat, unlinkat};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_REQUEST: usize = 32 * 1024;
const MAX_TASKS: u64 = 1024 * 1024;
const ACTOR: &str = "GEMINI-PM#f19f151a-f4e0-4ba0-88e4-6b4270e71f44";
const BASELINE: &str = "c4f8395af729fd7aecf5365f6a4b261a824d83ce";
const LEGACY_SHA: &str = "a9c6c014f56942a374344b9e5c8e2d5b2e8c37ead40ee6327752c02955e66e8a";
const PACKAGE_SHA: &str = "142c504a5f85210670c78e3671b453f0a5866383764a4b8306c4f5eac416e528";
const LOCK: &str = "tasks-writer.lock.d";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl Identity {
    fn of(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Directory {
    path: String,
    identity: Identity,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilePin {
    name: String,
    identity: Identity,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: u8,
    operation_id: String,
    actor: String,
    issued_unix_ms: u64,
    deadline_unix_ms: u64,
    baseline_commit: String,
    legacy_source_sha256: String,
    package_sha256: String,
    development_admission_sha256: String,
    review_bundle_sha256: String,
    repo: Directory,
    stage: Directory,
    journal: Directory,
    source: FilePin,
    postimage: FilePin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    LockCreated,
    OwnerSynced,
    IntentSynced,
    StageWritten,
    ModeSet,
    FileSynced,
    StageClosed,
    BeforeRename,
    Renamed,
    StageDirSynced,
    RepoDirSynced,
    ReceiptWritten,
    ReceiptSynced,
    BeforeRelease,
}

#[derive(Default)]
struct Hooks {
    #[cfg(test)]
    fail: Option<Step>,
    #[cfg(test)]
    expire: Option<Step>,
    #[cfg(test)]
    forced_now: Option<u64>,
    #[cfg(test)]
    sync_fault: Option<Step>,
    #[cfg(test)]
    callback: Option<Box<dyn FnMut(Step) -> io::Result<()>>>,
}

impl Hooks {
    fn sync(&self, file: &File, step: Step) -> io::Result<()> {
        let _ = step;
        #[cfg(test)]
        if self.sync_fault == Some(step) {
            return Err(io::Error::other("controlled fsync-result failure"));
        }
        file.sync_all()
    }

    fn hit(&mut self, step: Step) -> io::Result<()> {
        let _ = step;
        #[cfg(test)]
        {
            if let Some(callback) = &mut self.callback {
                callback(step)?;
            }
            if self.expire == Some(step) {
                self.forced_now = Some(u64::MAX);
            }
            if self.fail == Some(step) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "controlled fixture fault",
                ));
            }
        }
        Ok(())
    }

    fn deadline(&self, a: &Admission) -> io::Result<()> {
        let now = now_ms()?;
        #[cfg(test)]
        let now = self.forced_now.unwrap_or(now);
        require(
            now >= a.issued_unix_ms && now < a.deadline_unix_ms,
            "original admission expired or not yet valid",
        )
    }
}

#[derive(Default)]
struct Progress {
    mutated: bool,
    renamed: bool,
    receipt_durable: bool,
}

#[derive(Debug, Serialize)]
struct Held {
    operation_id: String,
    outcome: &'static str,
    error: String,
}

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn now_ms() -> io::Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    u64::try_from(duration.as_millis()).map_err(io::Error::other)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn component(s: &str) -> io::Result<()> {
    require(
        !s.is_empty()
            && s.len() <= 128
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid single-component name",
    )
}

fn directory(path: &str) -> io::Result<File> {
    require(
        path.starts_with('/') && path.len() <= 4096 && path != "/",
        "invalid absolute directory",
    )?;
    let parts: Vec<_> = path[1..].split('/').collect();
    require(
        parts.len() <= 64
            && parts
                .iter()
                .all(|p| !p.is_empty() && *p != "." && *p != ".."),
        "noncanonical directory spelling",
    )?;
    let mut fd = File::open("/")?;
    for part in parts {
        fd = File::from(openat(
            &fd,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
    }
    Ok(fd)
}

fn pinned_directory(pin: &Directory) -> io::Result<File> {
    let fd = directory(&pin.path)?;
    let m = fd.metadata()?;
    require(
        m.is_dir() && Identity::of(&m) == pin.identity,
        "directory identity drift",
    )?;
    require(
        m.uid() == rustix::process::geteuid().as_raw() && m.mode() & 0o7777 == 0o700,
        "directory must be private and owned",
    )?;
    Ok(fd)
}

fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    Identity::of(a) == Identity::of(b)
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && (a.mtime(), a.mtime_nsec(), a.ctime(), a.ctime_nsec())
            == (b.mtime(), b.mtime_nsec(), b.ctime(), b.ctime_nsec())
}

fn read_file(dir: &File, pin: &FilePin, limit: u64) -> io::Result<(Vec<u8>, Metadata)> {
    component(&pin.name)?;
    require(
        pin.bytes > 0 && pin.bytes <= limit && hex(&pin.sha256, 64),
        "invalid file bounds or hash",
    )?;
    let entry = statat(dir, pin.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
    require(
        (entry.st_mode as u32) & 0o170000 == 0o100000,
        "input is not a regular file",
    )?;
    let mut file = File::from(openat(
        dir,
        pin.name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let before = file.metadata()?;
    require(
        before.is_file()
            && before.nlink() == 1
            && before.len() == pin.bytes
            && Identity::of(&before) == pin.identity,
        "file identity, links or length drift",
    )?;
    require(
        before.uid() == rustix::process::geteuid().as_raw() && before.mode() & 0o022 == 0,
        "unowned or externally writable file",
    )?;
    require(
        before.dev() == entry.st_dev as u64 && before.ino() == entry.st_ino as u64,
        "entry changed during open",
    )?;
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    require(
        unchanged(&before, &after)
            && bytes.len() as u64 == pin.bytes
            && digest(&bytes) == pin.sha256,
        "file changed or digest mismatch",
    )?;
    Ok((bytes, after))
}

fn absent(dir: &File, name: &str) -> io::Result<()> {
    component(name)?;
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "existing operation artifact; no replay or recovery",
        )),
    }
}

fn write_all_checked<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes)
}

fn exclusive(dir: &File, name: &str, bytes: &[u8]) -> io::Result<File> {
    component(name)?;
    let mut file = File::from(openat(
        dir,
        name,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    write_all_checked(&mut file, bytes)?;
    file.sync_all()?;
    let m = file.metadata()?;
    require(
        m.is_file()
            && m.nlink() == 1
            && m.len() == bytes.len() as u64
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o7777 == 0o600,
        "exclusive record metadata drift",
    )?;
    Ok(file)
}

fn inactive(bytes: &[u8]) -> io::Result<()> {
    let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
    require(!text.contains('\r'), "task bytes must use LF")?;
    require(
        !text.lines().any(|line| {
            let line = line.trim();
            line.starts_with("### ") && (line.contains("[IN_PROGRESS]") || line.contains("[READY]"))
        }),
        "legacy active heading would permit unintended work",
    )
}

fn validate(a: &Admission, hooks: &Hooks) -> io::Result<()> {
    require(
        a.schema == 1 && a.actor == ACTOR && hex(&a.operation_id, 32),
        "wrong schema, publisher actor or operation ID",
    )?;
    require(
        a.baseline_commit == BASELINE && a.legacy_source_sha256 == LEGACY_SHA,
        "unsupported source contract",
    )?;
    require(
        a.package_sha256 == PACKAGE_SHA
            && hex(&a.development_admission_sha256, 64)
            && hex(&a.review_bundle_sha256, 64),
        "missing admitted package/decision/review binding",
    )?;
    require(
        a.source.name == "TASKS.md" && a.postimage.name != "TASKS.md",
        "wrong canonical or postimage name",
    )?;
    require(
        a.deadline_unix_ms > a.issued_unix_ms && a.deadline_unix_ms - a.issued_unix_ms <= 300_000,
        "admission window exceeds five minutes",
    )?;
    require(
        rustix::process::geteuid().as_raw() != 0,
        "root publication is not admitted",
    )?;
    require(
        a.stage.path == format!("{}/.chinwag", a.repo.path),
        "stage must be the admitted repo .chinwag directory",
    )?;
    require(
        a.repo.identity.dev == a.stage.identity.dev
            && a.repo.identity.ino != a.stage.identity.ino
            && a.journal.identity != a.repo.identity
            && a.journal.identity != a.stage.identity,
        "directory roles overlap or cross-device stage",
    )?;
    hooks.deadline(a)
}

fn perform(
    a: &Admission,
    admission_sha: &str,
    hooks: &mut Hooks,
    p: &mut Progress,
) -> io::Result<Value> {
    validate(a, hooks)?;
    require(hex(admission_sha, 64), "invalid admission digest")?;
    let repo = pinned_directory(&a.repo)?;
    let stage = pinned_directory(&a.stage)?;
    let journal = pinned_directory(&a.journal)?;
    let stage_name = format!("TASKS.md.stage.{}", a.operation_id);
    let intent_name = format!("tasks-intent-{}.json", a.operation_id);
    let receipt_name = format!("tasks-receipt-{}.json", a.operation_id);
    require(
        ![intent_name.as_str(), receipt_name.as_str()].contains(&a.postimage.name.as_str()),
        "postimage aliases an operation artifact",
    )?;
    for (dir, name) in [
        (&stage, LOCK),
        (&stage, stage_name.as_str()),
        (&journal, intent_name.as_str()),
        (&journal, receipt_name.as_str()),
    ] {
        absent(dir, name)?;
    }
    let (old, old_meta) = read_file(&repo, &a.source, MAX_TASKS)?;
    let (post, _) = read_file(&journal, &a.postimage, MAX_TASKS)?;
    inactive(&old)?;
    inactive(&post)?;
    hooks.deadline(a)?;
    mkdirat(&stage, LOCK, Mode::RWXU)?;
    p.mutated = true;
    hooks.hit(Step::LockCreated)?;
    hooks.deadline(a)?;
    let lock = File::from(openat(
        &stage,
        LOCK,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let lock_identity = Identity::of(&lock.metadata()?);
    let owner = serde_json::to_vec(&json!({"operation_id":a.operation_id,"actor":a.actor,"admission_sha256":admission_sha,"deadline_unix_ms":a.deadline_unix_ms})).map_err(io::Error::other)?;
    let owner_file = exclusive(&lock, "owner.json", &owner)?;
    let owner_pin = FilePin {
        name: "owner.json".to_owned(),
        identity: Identity::of(&owner_file.metadata()?),
        bytes: owner.len() as u64,
        sha256: digest(&owner),
    };
    lock.sync_all()?;
    stage.sync_all()?;
    hooks.hit(Step::OwnerSynced)?;
    hooks.deadline(a)?;
    let intent = serde_json::to_vec(
        &json!({"admission":a,"admission_sha256":admission_sha,"stage_name":stage_name}),
    )
    .map_err(io::Error::other)?;
    exclusive(&journal, &intent_name, &intent)?;
    hooks.sync(&journal, Step::IntentSynced)?;
    hooks.hit(Step::IntentSynced)?;
    hooks.deadline(a)?;
    let mut staged = File::from(openat(
        &stage,
        stage_name.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?);
    write_all_checked(&mut staged, &post)?;
    hooks.hit(Step::StageWritten)?;
    hooks.deadline(a)?;
    rustix::fs::fchmod(&staged, Mode::RUSR)?;
    hooks.hit(Step::ModeSet)?;
    hooks.sync(&staged, Step::FileSynced)?;
    hooks.hit(Step::FileSynced)?;
    let staged_meta = staged.metadata()?;
    require(
        staged_meta.is_file()
            && staged_meta.nlink() == 1
            && staged_meta.mode() & 0o7777 == 0o400
            && staged_meta.ino() != old_meta.ino(),
        "staging is not a fresh closed-readonly candidate",
    )?;
    let staged_pin = FilePin {
        name: stage_name.clone(),
        identity: Identity::of(&staged_meta),
        bytes: a.postimage.bytes,
        sha256: a.postimage.sha256.clone(),
    };
    drop(staged);
    hooks.hit(Step::StageClosed)?;
    stage.sync_all()?;
    read_file(&stage, &staged_pin, MAX_TASKS)?;
    hooks.hit(Step::BeforeRename)?;
    hooks.deadline(a)?;
    pinned_directory(&a.repo)?;
    pinned_directory(&a.stage)?;
    pinned_directory(&a.journal)?;
    read_file(&repo, &a.source, MAX_TASKS)?;
    read_file(&stage, &staged_pin, MAX_TASKS)?;
    hooks.deadline(a)?;
    renameat(&stage, stage_name.as_str(), &repo, "TASKS.md")?;
    p.renamed = true;
    hooks.hit(Step::Renamed)?;
    hooks.sync(&stage, Step::StageDirSynced)?;
    hooks.hit(Step::StageDirSynced)?;
    hooks.sync(&repo, Step::RepoDirSynced)?;
    hooks.hit(Step::RepoDirSynced)?;
    let published_pin = FilePin {
        name: "TASKS.md".to_owned(),
        ..staged_pin
    };
    read_file(&repo, &published_pin, MAX_TASKS)?;
    hooks.deadline(a)?;
    let receipt = serde_json::to_vec(&json!({
        "schema":1,"operation_id":a.operation_id,"actor":a.actor,"admission_sha256":admission_sha,
        "preimage_sha256":a.source.sha256,"postimage_sha256":a.postimage.sha256,
        "published_identity":published_pin.identity,"bytes":a.postimage.bytes,"publication":"COMMITTED",
        "original_deadline_unix_ms":a.deadline_unix_ms,
        "durability_scope":"checked file and directory fsync; not universal hardware-failure durability; safe FD drop does not report close errors"
    })).map_err(io::Error::other)?;
    exclusive(&journal, &receipt_name, &receipt)?;
    hooks.hit(Step::ReceiptWritten)?;
    hooks.sync(&journal, Step::ReceiptSynced)?;
    p.receipt_durable = true;
    hooks.hit(Step::ReceiptSynced)?;
    hooks.hit(Step::BeforeRelease)?;
    hooks.deadline(a)?;
    let named_lock = File::from(openat(
        &stage,
        LOCK,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    require(
        Identity::of(&named_lock.metadata()?) == lock_identity,
        "lock identity changed; cannot release",
    )?;
    read_file(&lock, &owner_pin, MAX_REQUEST as u64)?;
    unlinkat(&lock, "owner.json", AtFlags::empty())?;
    lock.sync_all()?;
    unlinkat(&stage, LOCK, AtFlags::REMOVEDIR)?;
    stage.sync_all()?;
    drop(owner_file);
    Ok(
        json!({"operation_id":a.operation_id,"outcome":"PUBLISHED","receipt_name":receipt_name,"receipt_sha256":digest(&receipt),"postimage_sha256":a.postimage.sha256,"lock_released":true}),
    )
}

fn publish(a: &Admission, admission_sha: &str, hooks: &mut Hooks) -> Result<Value, Held> {
    let mut p = Progress::default();
    perform(a, admission_sha, hooks, &mut p).map_err(|error| Held {
        operation_id: a.operation_id.clone(),
        outcome: if p.receipt_durable {
            "COMMITTED_CLEANUP_HELD"
        } else if p.renamed {
            "UNKNOWN_AFTER_RENAME_HELD"
        } else if p.mutated {
            "INCOMPLETE_OPERATION_HELD"
        } else if error.kind() == io::ErrorKind::AlreadyExists {
            "EXISTING_OPERATION_HELD"
        } else {
            "REJECTED"
        },
        error: error.to_string(),
    })
}

fn decode_admission(bytes: &[u8], expected: &str) -> io::Result<Admission> {
    require(
        !bytes.is_empty()
            && bytes.len() <= MAX_REQUEST
            && hex(expected, 64)
            && digest(bytes) == expected,
        "admission length or exact digest mismatch",
    )?;
    serde_json::from_slice(bytes).map_err(io::Error::other)
}

fn load_admission(path: &Path, expected: &str) -> io::Result<Admission> {
    let parent = path
        .parent()
        .and_then(Path::to_str)
        .ok_or_else(|| io::Error::other("admission requires absolute UTF-8 path"))?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::other("invalid admission filename"))?;
    component(name)?;
    let dir = directory(parent)?;
    let entry = statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
    require(
        (entry.st_mode as u32) & 0o170000 == 0o100000,
        "admission must be a regular file",
    )?;
    let mut f = File::from(openat(
        &dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let before = f.metadata()?;
    require(
        before.is_file()
            && before.nlink() == 1
            && before.uid() == rustix::process::geteuid().as_raw()
            && before.mode() & 0o7777 == 0o600
            && before.len() <= MAX_REQUEST as u64
            && before.ino() == entry.st_ino as u64
            && before.dev() == entry.st_dev as u64,
        "admission metadata refused",
    )?;
    let mut bytes = Vec::new();
    (&mut f)
        .take(MAX_REQUEST as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(
        unchanged(&before, &f.metadata()?),
        "admission changed during read",
    )?;
    decode_admission(&bytes, expected)
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 2 && args[1] == "--help" {
        println!(
            "p0-task-publish --publish ABSOLUTE_ADMISSION_JSON SHA256\nSupervised once-only publisher. No recovery command. Prior exact review/admission is required."
        );
        return;
    }
    let result = (|| -> io::Result<Value> {
        require(
            args.len() == 4 && args[1] == "--publish",
            "usage: p0-task-publish --publish ABSOLUTE_ADMISSION_JSON SHA256",
        )?;
        let expected = args[3]
            .to_str()
            .ok_or_else(|| io::Error::other("invalid admission digest argument"))?;
        let a = load_admission(&PathBuf::from(&args[2]), expected)?;
        match publish(&a, expected, &mut Hooks::default()) {
            Ok(value) => Ok(value),
            Err(held) => {
                println!(
                    "{}",
                    serde_json::to_string(&held).map_err(io::Error::other)?
                );
                std::process::exit(78);
            }
        }
    })();
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            println!(
                "{}",
                json!({"outcome":"REJECTED","error":error.to_string()})
            );
            std::process::exit(78);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    struct Fixture {
        _tmp: TempDir,
        a: Admission,
        old: Vec<u8>,
        new: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir_in("/private/tmp").unwrap();
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let repo = tmp.path().join("repo");
            let stage = repo.join(".chinwag");
            let journal = tmp.path().join("journal");
            for p in [&repo, &stage, &journal] {
                fs::create_dir(p).unwrap();
                fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let old = b"### `[DONE]` TASK-26\nHistorical accepted task.\n".to_vec();
            let new = b"### [todo] P0-01\nSupervised registration fixture only.\n".to_vec();
            fs::write(repo.join("TASKS.md"), &old).unwrap();
            fs::set_permissions(repo.join("TASKS.md"), fs::Permissions::from_mode(0o644)).unwrap();
            fs::write(journal.join("postimage.txt"), &new).unwrap();
            fs::set_permissions(
                journal.join("postimage.txt"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let d = |p: &Path| Directory {
                path: p.to_str().unwrap().to_owned(),
                identity: Identity::of(&fs::metadata(p).unwrap()),
            };
            let pin = |p: &Path, name: &str, bytes: &[u8]| FilePin {
                name: name.to_owned(),
                identity: Identity::of(&fs::metadata(p).unwrap()),
                bytes: bytes.len() as u64,
                sha256: digest(bytes),
            };
            let now = now_ms().unwrap();
            let a = Admission {
                schema: 1,
                operation_id: "a".repeat(32),
                actor: ACTOR.to_owned(),
                issued_unix_ms: now.saturating_sub(1),
                deadline_unix_ms: now + 299_000,
                baseline_commit: BASELINE.to_owned(),
                legacy_source_sha256: LEGACY_SHA.to_owned(),
                package_sha256: PACKAGE_SHA.to_owned(),
                development_admission_sha256: digest(b"controlled admission fixture"),
                review_bundle_sha256: digest(b"controlled exact review bundle"),
                repo: d(&repo),
                stage: d(&stage),
                journal: d(&journal),
                source: pin(&repo.join("TASKS.md"), "TASKS.md", &old),
                postimage: pin(&journal.join("postimage.txt"), "postimage.txt", &new),
            };
            Self {
                _tmp: tmp,
                a,
                old,
                new,
            }
        }
        fn source(&self) -> PathBuf {
            Path::new(&self.a.repo.path).join("TASKS.md")
        }
        fn lock(&self) -> PathBuf {
            Path::new(&self.a.stage.path).join(LOCK)
        }
        fn stage(&self) -> PathBuf {
            Path::new(&self.a.stage.path).join(format!("TASKS.md.stage.{}", self.a.operation_id))
        }
        fn intent(&self) -> PathBuf {
            Path::new(&self.a.journal.path)
                .join(format!("tasks-intent-{}.json", self.a.operation_id))
        }
        fn receipt(&self) -> PathBuf {
            Path::new(&self.a.journal.path)
                .join(format!("tasks-receipt-{}.json", self.a.operation_id))
        }
        fn run(&self, hooks: &mut Hooks) -> Result<Value, Held> {
            publish(
                &self.a,
                &digest(&serde_json::to_vec(&self.a).unwrap()),
                hooks,
            )
        }
        fn assert_old(&self) {
            assert_eq!(fs::read(self.source()).unwrap(), self.old);
        }
        fn post(&mut self, bytes: &[u8]) {
            let p = Path::new(&self.a.journal.path).join("postimage.txt");
            fs::write(&p, bytes).unwrap();
            self.a.postimage.bytes = bytes.len() as u64;
            self.a.postimage.sha256 = digest(bytes);
        }
    }

    #[test]
    fn p0_publish_success_is_fresh_readonly_and_correlated() {
        let f = Fixture::new();
        let old_ino = fs::metadata(f.source()).unwrap().ino();
        let output = f.run(&mut Hooks::default()).unwrap();
        assert_eq!(output["outcome"], "PUBLISHED");
        assert_eq!(fs::read(f.source()).unwrap(), f.new);
        let m = fs::metadata(f.source()).unwrap();
        assert_ne!(m.ino(), old_ino);
        assert_eq!(m.mode() & 0o7777, 0o400);
        assert_eq!(m.nlink(), 1);
        assert!(
            fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(f.source())
                .is_err()
        );
        assert!(!f.lock().exists());
        assert!(f.intent().exists());
        let receipt: Value = serde_json::from_slice(&fs::read(f.receipt()).unwrap()).unwrap();
        assert_eq!(receipt["operation_id"], f.a.operation_id);
        assert_eq!(receipt["postimage_sha256"], digest(&f.new));
        assert_eq!(
            output["receipt_sha256"],
            digest(&fs::read(f.receipt()).unwrap())
        );
    }

    #[test]
    fn p0_publish_rejects_replay_and_preexisting_artifacts_without_mutation() {
        for target in 0..4 {
            let f = Fixture::new();
            let p = match target {
                0 => f.lock(),
                1 => f.intent(),
                2 => f.stage(),
                _ => f.receipt(),
            };
            if target == 0 {
                fs::create_dir(&p).unwrap();
            } else {
                fs::write(&p, b"original").unwrap();
            }
            assert_eq!(
                f.run(&mut Hooks::default()).unwrap_err().outcome,
                "EXISTING_OPERATION_HELD"
            );
            f.assert_old();
            assert!(p.exists());
            if target != 0 {
                assert_eq!(fs::read(p).unwrap(), b"original");
            }
        }
        let f = Fixture::new();
        f.run(&mut Hooks::default()).unwrap();
        let before = fs::read(f.receipt()).unwrap();
        assert_eq!(
            f.run(&mut Hooks::default()).unwrap_err().outcome,
            "EXISTING_OPERATION_HELD"
        );
        assert_eq!(fs::read(f.receipt()).unwrap(), before);
        assert_eq!(fs::read(f.source()).unwrap(), f.new);
    }

    #[test]
    fn p0_publish_rejects_wrong_authority_identity_bounds_and_expiry() {
        for case in 0..10 {
            let mut f = Fixture::new();
            match case {
                0 => f.a.actor = "WORKHORSE#wrong".into(),
                1 => f.a.operation_id = "../escape".into(),
                2 => f.a.schema = 2,
                3 => f.a.repo.identity.ino += 1,
                4 => f.a.source.identity.ino += 1,
                5 => f.a.source.sha256 = "0".repeat(64),
                6 => f.a.source.bytes += 1,
                7 => f.a.postimage.bytes = MAX_TASKS + 1,
                8 => f.a.deadline_unix_ms = f.a.issued_unix_ms,
                _ => f.a.baseline_commit = "0".repeat(40),
            }
            assert!(f.run(&mut Hooks::default()).is_err());
            f.assert_old();
            assert!(!f.lock().exists());
        }
    }

    #[test]
    fn p0_publish_strict_json_and_exact_admission_digest() {
        let f = Fixture::new();
        let bytes = serde_json::to_vec(&f.a).unwrap();
        assert!(decode_admission(&bytes, &digest(&bytes)).is_ok());
        assert!(decode_admission(&bytes, &"0".repeat(64)).is_err());
        let mut value = serde_json::to_value(&f.a).unwrap();
        value["unknown"] = json!(true);
        let bad = serde_json::to_vec(&value).unwrap();
        assert!(decode_admission(&bad, &digest(&bad)).is_err());
        let duplicate = String::from_utf8(bytes).unwrap().replacen(
            "\"schema\":1",
            "\"schema\":1,\"schema\":1",
            1,
        );
        assert!(decode_admission(duplicate.as_bytes(), &digest(duplicate.as_bytes())).is_err());
        let huge = vec![b' '; MAX_REQUEST + 1];
        assert!(decode_admission(&huge, &digest(&huge)).is_err());
    }

    #[test]
    fn p0_publish_admission_file_requires_private_exact_single_link_bytes() {
        let f = Fixture::new();
        let bytes = serde_json::to_vec(&f.a).unwrap();
        let path = Path::new(&f.a.journal.path).join("admission.json");
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_admission(&path, &digest(&bytes)).is_ok());
        assert!(load_admission(&path, &"0".repeat(64)).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_admission(&path, &digest(&bytes)).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = path.with_file_name("hardlink.json");
        fs::hard_link(&path, &alias).unwrap();
        assert!(load_admission(&path, &digest(&bytes)).is_err());
        fs::remove_file(alias).unwrap();
        let link = path.with_file_name("symlink.json");
        symlink(&path, &link).unwrap();
        assert!(load_admission(&link, &digest(&bytes)).is_err());
    }

    #[test]
    fn p0_publish_rejects_active_invalid_and_non_lf_postimages() {
        for bytes in [
            b"  ### TASK-X [READY]\n".as_slice(),
            b"\t### [IN_PROGRESS] P0-01\n".as_slice(),
            b"hello\r\n".as_slice(),
            &[0xffu8],
        ] {
            let mut f = Fixture::new();
            f.post(bytes);
            assert!(f.run(&mut Hooks::default()).is_err());
            f.assert_old();
            assert!(!f.lock().exists());
        }
    }

    #[test]
    fn p0_publish_rejects_symlinks_hardlinks_and_wrong_types() {
        for case in 0..5 {
            let mut f = Fixture::new();
            match case {
                0 => {
                    let p = f.source();
                    fs::remove_file(&p).unwrap();
                    symlink(Path::new(&f.a.journal.path).join("postimage.txt"), p).unwrap();
                }
                1 => {
                    let p = Path::new(&f.a.journal.path).join("postimage.txt");
                    fs::remove_file(&p).unwrap();
                    symlink(f.source(), p).unwrap();
                }
                2 => {
                    fs::hard_link(f.source(), Path::new(&f.a.repo.path).join("alias")).unwrap();
                }
                3 => {
                    fs::remove_file(f.source()).unwrap();
                    fs::create_dir(f.source()).unwrap();
                }
                _ => {
                    let real = Path::new(&f.a.journal.path).with_file_name("moved-journal");
                    fs::rename(&f.a.journal.path, &real).unwrap();
                    symlink(&real, &f.a.journal.path).unwrap();
                    f.a.journal.identity = Identity::of(&fs::metadata(real).unwrap());
                }
            }
            assert!(f.run(&mut Hooks::default()).is_err());
            assert!(!f.lock().exists());
        }
    }

    #[test]
    fn p0_publish_faults_before_rename_hold_original_artifacts() {
        for step in [
            Step::LockCreated,
            Step::OwnerSynced,
            Step::IntentSynced,
            Step::StageWritten,
            Step::ModeSet,
            Step::FileSynced,
            Step::StageClosed,
            Step::BeforeRename,
        ] {
            let f = Fixture::new();
            let mut h = Hooks {
                fail: Some(step),
                ..Hooks::default()
            };
            assert_eq!(
                f.run(&mut h).unwrap_err().outcome,
                "INCOMPLETE_OPERATION_HELD"
            );
            f.assert_old();
            assert!(f.lock().exists());
            assert_eq!(
                f.run(&mut Hooks::default()).unwrap_err().outcome,
                "EXISTING_OPERATION_HELD"
            );
        }
    }

    #[test]
    fn p0_publish_faults_after_rename_never_restore_preimage() {
        for step in [
            Step::Renamed,
            Step::StageDirSynced,
            Step::RepoDirSynced,
            Step::ReceiptWritten,
        ] {
            let f = Fixture::new();
            let mut h = Hooks {
                fail: Some(step),
                ..Hooks::default()
            };
            assert_eq!(
                f.run(&mut h).unwrap_err().outcome,
                "UNKNOWN_AFTER_RENAME_HELD"
            );
            assert_eq!(fs::read(f.source()).unwrap(), f.new);
            assert!(f.lock().exists());
            assert!(f.intent().exists());
            assert_eq!(
                f.run(&mut Hooks::default()).unwrap_err().outcome,
                "EXISTING_OPERATION_HELD"
            );
            assert_eq!(fs::read(f.source()).unwrap(), f.new);
        }
    }

    #[test]
    fn p0_publish_durable_receipt_cleanup_fault_is_distinct() {
        for step in [Step::ReceiptSynced, Step::BeforeRelease] {
            let f = Fixture::new();
            let mut h = Hooks {
                fail: Some(step),
                ..Hooks::default()
            };
            assert_eq!(f.run(&mut h).unwrap_err().outcome, "COMMITTED_CLEANUP_HELD");
            assert_eq!(fs::read(f.source()).unwrap(), f.new);
            assert!(f.lock().exists());
            assert_eq!(
                serde_json::from_slice::<Value>(&fs::read(f.receipt()).unwrap()).unwrap()["publication"],
                "COMMITTED"
            );
        }
    }

    #[test]
    fn p0_publish_never_releases_a_replaced_owner_record() {
        let f = Fixture::new();
        let owner = f.lock().join("owner.json");
        let mut h = Hooks {
            callback: Some(Box::new(move |step| {
                if step == Step::BeforeRelease {
                    let bytes = fs::read(&owner)?;
                    fs::remove_file(&owner)?;
                    fs::write(&owner, bytes)?;
                    fs::set_permissions(&owner, fs::Permissions::from_mode(0o600))?;
                }
                Ok(())
            })),
            ..Hooks::default()
        };
        assert_eq!(f.run(&mut h).unwrap_err().outcome, "COMMITTED_CLEANUP_HELD");
        assert!(f.lock().join("owner.json").exists());
        assert_eq!(fs::read(f.source()).unwrap(), f.new);
    }

    #[test]
    fn p0_publish_deadline_drift_before_commit_holds_without_publication() {
        let f = Fixture::new();
        let mut h = Hooks {
            expire: Some(Step::BeforeRename),
            ..Hooks::default()
        };
        assert_eq!(
            f.run(&mut h).unwrap_err().outcome,
            "INCOMPLETE_OPERATION_HELD"
        );
        f.assert_old();
        assert!(f.stage().exists());
    }

    #[test]
    fn p0_publish_checked_sync_errors_preserve_exact_commit_boundary() {
        for step in [
            Step::IntentSynced,
            Step::FileSynced,
            Step::StageDirSynced,
            Step::RepoDirSynced,
            Step::ReceiptSynced,
        ] {
            let f = Fixture::new();
            let mut h = Hooks {
                sync_fault: Some(step),
                ..Hooks::default()
            };
            let error = f.run(&mut h).unwrap_err();
            assert!(error.error.contains("fsync-result"));
            assert!(f.lock().exists());
            if matches!(
                step,
                Step::StageDirSynced | Step::RepoDirSynced | Step::ReceiptSynced
            ) {
                assert_eq!(error.outcome, "UNKNOWN_AFTER_RENAME_HELD");
                assert_eq!(fs::read(f.source()).unwrap(), f.new);
            } else {
                assert_eq!(error.outcome, "INCOMPLETE_OPERATION_HELD");
                f.assert_old();
            }
        }
    }

    #[test]
    fn p0_publish_real_permission_denial_preserves_preimage_and_claim() {
        let f = Fixture::new();
        let journal = PathBuf::from(&f.a.journal.path);
        let deny = journal.clone();
        let mut h = Hooks {
            callback: Some(Box::new(move |step| {
                if step == Step::OwnerSynced {
                    fs::set_permissions(&deny, fs::Permissions::from_mode(0o500))?;
                }
                Ok(())
            })),
            ..Hooks::default()
        };
        let result = f.run(&mut h);
        fs::set_permissions(journal, fs::Permissions::from_mode(0o700)).unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.outcome, "INCOMPLETE_OPERATION_HELD");
        assert!(error.error.contains("Permission denied"));
        f.assert_old();
        assert!(f.lock().exists());
        assert!(!f.intent().exists());
    }

    #[test]
    fn p0_publish_preserves_concurrent_third_state() {
        let f = Fixture::new();
        let path = f.source();
        let mut h = Hooks {
            callback: Some(Box::new(move |step| {
                if step == Step::BeforeRename {
                    fs::write(&path, b"unrelated legitimate change")?;
                }
                Ok(())
            })),
            ..Hooks::default()
        };
        assert_eq!(
            f.run(&mut h).unwrap_err().outcome,
            "INCOMPLETE_OPERATION_HELD"
        );
        assert_eq!(
            fs::read(f.source()).unwrap(),
            b"unrelated legitimate change"
        );
        assert!(f.lock().exists());
    }

    #[test]
    fn p0_publish_rejects_staged_byte_drift() {
        let f = Fixture::new();
        let path = f.stage();
        let mut h = Hooks {
            callback: Some(Box::new(move |step| {
                if step == Step::StageClosed {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                    fs::write(&path, b"changed stage")?;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
                }
                Ok(())
            })),
            ..Hooks::default()
        };
        assert!(f.run(&mut h).is_err());
        f.assert_old();
        assert!(f.lock().exists());
    }

    #[test]
    fn p0_publish_rejects_parent_rebinding_without_touching_replacement() {
        let f = Fixture::new();
        let root = PathBuf::from(&f.a.repo.path);
        let saved = root.with_file_name("old-repo");
        let mut h = Hooks {
            callback: Some(Box::new(move |step| {
                if step == Step::BeforeRename {
                    fs::rename(&root, &saved)?;
                    fs::create_dir(&root)?;
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                    fs::write(root.join("TASKS.md"), b"replacement tree")?;
                }
                Ok(())
            })),
            ..Hooks::default()
        };
        assert!(f.run(&mut h).is_err());
        assert_eq!(fs::read(f.source()).unwrap(), b"replacement tree");
    }

    #[test]
    fn p0_publish_detects_write_zero_and_handles_partial_writes() {
        struct Zero;
        impl Write for Zero {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Ok(0)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            write_all_checked(&mut Zero, b"must write")
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
        struct Partial(Vec<u8>);
        impl Write for Partial {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                let n = b.len().min(2);
                self.0.extend_from_slice(&b[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut p = Partial(Vec::new());
        write_all_checked(&mut p, b"complete bytes").unwrap();
        assert_eq!(p.0, b"complete bytes");
    }
}
