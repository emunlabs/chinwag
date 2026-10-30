use super::{
    NativeOpenReceipt, NativeOpenState, OnboardingError, message, receipt, valid_installation_id,
    valid_request_id,
};
use rustix::fs::{
    AtFlags, Dir, FlockOperation, Mode, OFlags, RenameFlags, flock, mkdirat, open, openat,
    renameat, renameat_with, unlinkat,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

pub(super) const MAX_RECORDS: usize = 256;
const MAX_RECORD_BYTES: u64 = 4096;
const LOCK_NAME: &str = "native-open.lock";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    receipt: NativeOpenReceipt,
}

pub(super) struct Journal {
    directory: File,
    _lock: File,
    records: BTreeMap<String, NativeOpenReceipt>,
    reserved: BTreeSet<String>,
    active: Option<String>,
    healthy: bool,
    #[cfg(test)]
    pub(super) fail_next_write: bool,
    #[cfg(test)]
    pub(super) fail_terminal_write: bool,
}

impl Journal {
    pub fn open(root: &Path) -> Result<Self, OnboardingError> {
        let directory = open_directory(root)?;
        let lock: File = openat(
            &directory,
            LOCK_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| OnboardingError::Storage)?
        .into();
        owned_file(&lock)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| OnboardingError::Unavailable)?;
        directory.sync_all().map_err(|_| OnboardingError::Storage)?;
        let mut records = BTreeMap::new();
        let mut reserved = BTreeSet::new();
        let mut ids_seen = BTreeSet::new();
        let entries = Dir::read_from(&directory).map_err(|_| OnboardingError::Storage)?;
        let mut examined = 0;
        for entry in entries {
            let entry = entry.map_err(|_| OnboardingError::Storage)?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| OnboardingError::Storage)?;
            if matches!(name, "." | ".." | LOCK_NAME) {
                continue;
            }
            examined += 1;
            if examined > MAX_RECORDS * 2 {
                return Err(OnboardingError::Storage);
            }
            let orphan = name
                .strip_prefix('.')
                .and_then(|name| name.strip_suffix("-write.tmp"));
            let id = orphan
                .or_else(|| name.strip_suffix(".json"))
                .filter(|id| valid_request_id(id))
                .ok_or(OnboardingError::Storage)?;
            ids_seen.insert(id.to_owned());
            if ids_seen.len() > MAX_RECORDS {
                return Err(OnboardingError::Storage);
            }
            let mut file: File = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| OnboardingError::Storage)?
            .into();
            owned_file(&file)?;
            if file.metadata().map_err(|_| OnboardingError::Storage)?.len() > MAX_RECORD_BYTES {
                return Err(OnboardingError::Storage);
            }
            // A recognized crash-left write reserves its ID even when bytes
            // are truncated. Its bytes are preserved, never replayed or treated
            // as an OS success. A validated canonical record below dominates.
            if orphan.is_some() {
                reserved.insert(id.to_owned());
                continue;
            }
            let mut raw = Vec::new();
            Read::by_ref(&mut file)
                .take(MAX_RECORD_BYTES + 1)
                .read_to_end(&mut raw)
                .map_err(|_| OnboardingError::Storage)?;
            if raw.len() as u64 > MAX_RECORD_BYTES {
                return Err(OnboardingError::Storage);
            }
            let record: Record =
                serde_json::from_slice(&raw).map_err(|_| OnboardingError::Storage)?;
            if record.schema != "chinwag-native-open-record/v1"
                || record.receipt.schema != "chinwag-native-open/v1"
                || record.receipt.request_id != id
                || !valid_installation_id(&record.receipt.installation_id)
                || record.receipt.message != message(&record.receipt.state)
            {
                return Err(OnboardingError::Storage);
            }
            records.insert(id.into(), record.receipt);
        }
        for id in records.keys() {
            reserved.remove(id);
        }
        if records.len() + reserved.len() > MAX_RECORDS {
            return Err(OnboardingError::Storage);
        }
        Ok(Self {
            directory,
            _lock: lock,
            records,
            reserved,
            active: None,
            healthy: true,
            #[cfg(test)]
            fail_next_write: false,
            #[cfg(test)]
            fail_terminal_write: false,
        })
    }

    pub fn available(&self) -> bool {
        self.healthy && self.records.len() + self.reserved.len() < MAX_RECORDS
    }

    pub fn lookup(&self, id: &str) -> Result<Option<NativeOpenReceipt>, OnboardingError> {
        if self.reserved.contains(id) {
            return Err(OnboardingError::Storage);
        }
        Ok(self.records.get(id).map(|stored| {
            if matches!(stored.state, NativeOpenState::Pending)
                && self.active.as_deref() != Some(id)
            {
                receipt(id, &stored.installation_id, NativeOpenState::Uncertain)
            } else {
                stored.clone()
            }
        }))
    }

    pub fn begin(&mut self, id: &str, installation_id: &str) -> Result<(), OnboardingError> {
        if !self.available() {
            return Err(OnboardingError::Storage);
        }
        if self.records.contains_key(id) || self.reserved.contains(id) {
            return Err(OnboardingError::Conflict);
        }
        let pending = receipt(id, installation_id, NativeOpenState::Pending);
        self.records.insert(id.into(), pending.clone());
        if self.persist(&pending, false).is_err() {
            self.records.insert(
                id.into(),
                receipt(id, installation_id, NativeOpenState::Uncertain),
            );
            return Err(OnboardingError::Storage);
        }
        self.active = Some(id.into());
        Ok(())
    }

    pub fn finish(
        &mut self,
        result: NativeOpenReceipt,
    ) -> Result<NativeOpenReceipt, OnboardingError> {
        self.active = None;
        let final_receipt = if self.persist(&result, true).is_err() {
            receipt(
                &result.request_id,
                &result.installation_id,
                NativeOpenState::Uncertain,
            )
        } else {
            result
        };
        self.records
            .insert(final_receipt.request_id.clone(), final_receipt.clone());
        Ok(final_receipt)
    }

    fn persist(
        &mut self,
        value: &NativeOpenReceipt,
        replacing_pending: bool,
    ) -> Result<(), OnboardingError> {
        self.healthy = false;
        #[cfg(test)]
        if self.fail_next_write {
            self.fail_next_write = false;
            return Err(OnboardingError::Storage);
        }
        #[cfg(test)]
        if self.fail_terminal_write && !matches!(value.state, NativeOpenState::Pending) {
            return Err(OnboardingError::Storage);
        }
        let raw = serde_json::to_vec(&Record {
            schema: "chinwag-native-open-record/v1".into(),
            receipt: value.clone(),
        })
        .map_err(|_| OnboardingError::Storage)?;
        if raw.len() as u64 > MAX_RECORD_BYTES {
            return Err(OnboardingError::Storage);
        }
        let temp = format!(".{}-write.tmp", value.request_id);
        let target = format!("{}.json", value.request_id);
        let mut created_temp = false;
        let result = (|| {
            // Recheck a preexisting target without following links. A directory,
            // symlink or hard link is never overwritten as an owned record.
            match openat(
                &self.directory,
                &target,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            ) {
                Ok(file) if replacing_pending => {
                    let mut file = File::from(file);
                    owned_file(&file)?;
                    if file.metadata().map_err(|_| OnboardingError::Storage)?.len()
                        > MAX_RECORD_BYTES
                    {
                        return Err(OnboardingError::Storage);
                    }
                    let mut raw = Vec::new();
                    Read::by_ref(&mut file)
                        .take(MAX_RECORD_BYTES + 1)
                        .read_to_end(&mut raw)
                        .map_err(|_| OnboardingError::Storage)?;
                    if raw.len() as u64 > MAX_RECORD_BYTES {
                        return Err(OnboardingError::Storage);
                    }
                    let previous: Record =
                        serde_json::from_slice(&raw).map_err(|_| OnboardingError::Storage)?;
                    if previous.schema != "chinwag-native-open-record/v1"
                        || previous.receipt
                            != receipt(
                                &value.request_id,
                                &value.installation_id,
                                NativeOpenState::Pending,
                            )
                    {
                        return Err(OnboardingError::Storage);
                    }
                }
                Err(error) if error == rustix::io::Errno::NOENT && !replacing_pending => (),
                Ok(_) => return Err(OnboardingError::Storage),
                Err(_) => return Err(OnboardingError::Storage),
            }
            let mut file: File = openat(
                &self.directory,
                &temp,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| OnboardingError::Storage)?
            .into();
            created_temp = true;
            owned_file(&file)?;
            file.write_all(&raw).map_err(|_| OnboardingError::Storage)?;
            file.sync_all().map_err(|_| OnboardingError::Storage)?;
            if replacing_pending {
                renameat(&self.directory, &temp, &self.directory, &target)
                    .map_err(|_| OnboardingError::Storage)?;
            } else {
                // Atomic first publication cannot overwrite a late canonical
                // file, even if it appeared after our existence check above.
                renameat_with(
                    &self.directory,
                    &temp,
                    &self.directory,
                    &target,
                    RenameFlags::NOREPLACE,
                )
                .map_err(|_| OnboardingError::Storage)?;
            }
            self.directory
                .sync_all()
                .map_err(|_| OnboardingError::Storage)?;
            Ok(())
        })();
        if result.is_err() {
            if created_temp {
                let _ = unlinkat(&self.directory, &temp, AtFlags::empty());
            }
            return Err(OnboardingError::Storage);
        }
        self.healthy = true;
        Ok(())
    }
}

fn owned_file(file: &File) -> Result<(), OnboardingError> {
    let metadata = file.metadata().map_err(|_| OnboardingError::Storage)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(OnboardingError::Storage);
    }
    Ok(())
}

fn open_directory(root: &Path) -> Result<File, OnboardingError> {
    if !root.is_absolute() || root.as_os_str().len() > 4096 {
        return Err(OnboardingError::Invalid);
    }
    let parts = root.components().collect::<Vec<_>>();
    if parts.len() < 2
        || parts
            .iter()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(OnboardingError::Invalid);
    }
    let mut directory: File = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| OnboardingError::Storage)?
    .into();
    for (index, part) in parts.iter().enumerate().skip(1) {
        let Component::Normal(name) = part else {
            return Err(OnboardingError::Invalid);
        };
        let name = *name;
        let next = match openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(next) => next,
            Err(error) if error == rustix::io::Errno::NOENT && index + 1 == parts.len() => {
                mkdirat(&directory, name, Mode::RWXU).map_err(|_| OnboardingError::Storage)?;
                directory.sync_all().map_err(|_| OnboardingError::Storage)?;
                openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| OnboardingError::Storage)?
            }
            Err(_) => return Err(OnboardingError::Storage),
        };
        directory = next.into();
    }
    let metadata = directory.metadata().map_err(|_| OnboardingError::Storage)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(OnboardingError::Storage);
    }
    Ok(directory)
}
