use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const MAX_BYTES: usize = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct DraftFile {
    path: PathBuf,
}

impl DraftFile {
    pub fn open(path: PathBuf) -> io::Result<(Self, HashMap<String, String>)> {
        if !path.is_absolute() {
            return Err(invalid("draft path must be absolute"));
        }
        let drafts = match fs::symlink_metadata(&path) {
            Ok(before) => {
                if !before.is_file() || before.file_type().is_symlink() {
                    return Err(invalid("draft file must be a regular non-symlink file"));
                }
                let mut file = File::open(&path)?;
                let opened = file.metadata()?;
                if !opened.is_file() || !same_file(&before, &opened) {
                    return Err(invalid("draft file changed while opening it"));
                }
                let mut bytes = Vec::new();
                Read::by_ref(&mut file)
                    .take((MAX_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > MAX_BYTES {
                    return Err(invalid("draft file exceeds 64 KiB"));
                }
                serde_json::from_slice(&bytes).map_err(|error| invalid(&error.to_string()))?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(error),
        };
        Ok((Self { path }, drafts))
    }

    pub fn save(&self, drafts: &HashMap<String, String>) -> io::Result<()> {
        check_target(&self.path)?;
        let bytes = serde_json::to_vec(drafts).map_err(|error| invalid(&error.to_string()))?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid(
                "drafts exceed the 64 KiB persistence limit; text remains in this window",
            ));
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("missing draft directory"))?;
        let filename = self
            .path
            .file_name()
            .ok_or_else(|| invalid("missing draft filename"))?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".{}.{}.{}.tmp",
            filename.to_string_lossy(),
            std::process::id(),
            sequence,
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            check_target(&self.path)?;
            fs::rename(&temporary, &self.path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn check_target(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => Err(invalid(
            "draft target must remain a regular non-symlink file",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn same_file(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    before.dev() == opened.dev() && before.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_file(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    before.len() == opened.len() && before.modified().ok() == opened.modified().ok()
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "chinwag-alpha-drafts-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("drafts.json")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn drafts_survive_reopen_including_whitespace_and_multiple_rooms() {
        let directory = TestDirectory::new();
        let (file, initial) = DraftFile::open(directory.file()).unwrap();
        assert!(initial.is_empty());
        let drafts = HashMap::from([
            ("#mgmt".into(), "Hey guys  \n".into()),
            ("#alpha".into(), "Unsent α draft".into()),
        ]);
        file.save(&drafts).unwrap();
        let (_, reopened) = DraftFile::open(directory.file()).unwrap();
        assert_eq!(reopened, drafts);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn oversized_or_malformed_input_is_not_replaced() {
        let directory = TestDirectory::new();
        fs::write(directory.file(), vec![b' '; MAX_BYTES + 1]).unwrap();
        assert!(DraftFile::open(directory.file()).is_err());
        fs::write(directory.file(), b"not JSON").unwrap();
        assert!(DraftFile::open(directory.file()).is_err());
        assert_eq!(fs::read(directory.file()).unwrap(), b"not JSON");
    }

    #[test]
    fn oversized_save_preserves_previous_file() {
        let directory = TestDirectory::new();
        let (file, _) = DraftFile::open(directory.file()).unwrap();
        file.save(&HashMap::from([("#alpha".into(), "original".into())]))
            .unwrap();
        let previous = fs::read(directory.file()).unwrap();
        let oversized = HashMap::from([("#alpha".into(), "x".repeat(MAX_BYTES))]);
        assert!(file.save(&oversized).is_err());
        assert_eq!(fs::read(directory.file()).unwrap(), previous);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_read_and_save_targets_are_rejected() {
        use std::os::unix::fs::symlink;
        let directory = TestDirectory::new();
        let target = directory.0.join("target.json");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, directory.file()).unwrap();
        assert!(DraftFile::open(directory.file()).is_err());
        fs::remove_file(directory.file()).unwrap();
        let (file, _) = DraftFile::open(directory.file()).unwrap();
        symlink(&target, directory.file()).unwrap();
        assert!(file.save(&HashMap::new()).is_err());
        assert_eq!(fs::read(target).unwrap(), b"{}");
    }
}
