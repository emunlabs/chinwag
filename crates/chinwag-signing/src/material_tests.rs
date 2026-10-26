use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = temporary.path().canonicalize().unwrap();
        Self {
            _temporary: temporary,
            root,
        }
    }
}

fn key() -> SigningSecret {
    SigningSecret::from_seed(Zeroizing::new([0xA5; 32]))
}

#[test]
fn created_directory_and_public_line_bind_the_same_synthetic_signer() {
    let f = Fixture::new();
    let path = f.root.join("identity");
    let directory = PrivateDirectory::create_new(&path).unwrap();
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    let signer = key();
    directory.write_new(OsStr::new("signer"), &signer).unwrap();
    directory
        .write_new_allowed_signers(OsStr::new("allowed"), "fixture@chinwag.invalid", &signer)
        .unwrap();
    let line = fs::read_to_string(path.join("allowed")).unwrap();
    assert_eq!(
        line,
        format!(
            "fixture@chinwag.invalid namespaces=\"git\" {}\n",
            signer.public_openssh().unwrap()
        )
    );
    let parsed = ssh_key::PublicKey::from_openssh(line.splitn(3, ' ').nth(2).unwrap()).unwrap();
    let loaded = directory
        .read_existing(OsStr::new("signer"), &signer.public_bytes())
        .unwrap();
    assert_eq!(
        parsed.key_data().ed25519().unwrap().0,
        loaded.public_bytes()
    );
    let public_metadata = fs::metadata(path.join("allowed")).unwrap();
    assert_eq!(public_metadata.mode() & 0o7777, 0o600);
    assert_eq!(public_metadata.nlink(), 1);
    assert_eq!(public_metadata.uid(), metadata.uid());
}

#[test]
fn existing_directory_file_and_symlink_are_preserved_by_exclusive_creation() {
    let f = Fixture::new();
    let directory = f.root.join("directory");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
    fs::write(directory.join("sentinel"), b"keep directory").unwrap();
    let file = f.root.join("file");
    fs::write(&file, b"keep file").unwrap();
    let link = f.root.join("link");
    symlink(&directory, &link).unwrap();
    for path in [&directory, &file, &link] {
        let before = fs::symlink_metadata(path).unwrap();
        assert!(matches!(
            PrivateDirectory::create_new(path),
            Err(Error::Exists)
        ));
        let after = fs::symlink_metadata(path).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.mode(), after.mode());
    }
    assert_eq!(
        fs::read(directory.join("sentinel")).unwrap(),
        b"keep directory"
    );
    assert_eq!(fs::read(file).unwrap(), b"keep file");
}

#[test]
fn unsafe_or_missing_parents_are_refused_without_creating_any_leaf() {
    let f = Fixture::new();
    symlink(&f.root, f.root.join("link")).unwrap();
    for path in [
        PathBuf::from("relative"),
        PathBuf::from("/"),
        f.root.join("link/leaf"),
        f.root.join("missing/leaf"),
        f.root.join("../leaf"),
    ] {
        assert!(matches!(
            PrivateDirectory::create_new(&path),
            Err(Error::Directory)
        ));
    }
    fs::set_permissions(&f.root, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        PrivateDirectory::create_new(&f.root.join("shared-parent-leaf")),
        Err(Error::Directory)
    ));
    fs::set_permissions(&f.root, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 1);
}

#[test]
fn created_but_unconfirmed_directory_is_retained_without_mode_repair() {
    let f = Fixture::new();
    let path = f.root.join("unconfirmed");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
    let original = fs::metadata(&path).unwrap();
    let parent = open(
        &f.root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    // Exercise the same post-mkdir confirmation boundary with a real unsafe inode.
    assert!(matches!(
        PrivateDirectory::confirm_created(&parent, OsStr::new("unconfirmed")),
        Err(Error::CreatedButUnconfirmed)
    ));
    let retained = fs::metadata(&path).unwrap();
    assert_eq!(retained.ino(), original.ino());
    assert_eq!(retained.mode() & 0o7777, 0o750);
}

#[test]
fn invalid_principals_and_names_create_no_public_file() {
    let f = Fixture::new();
    let directory = PrivateDirectory::open(&f.root).unwrap();
    let signer = key();
    for principal in [
        "",
        "*",
        "fixture",
        "fixture@localhost",
        "fixture@chinwag.invalid\nother",
        "fixture@chinwag.invalid,other@chinwag.invalid",
        "fixture @chinwag.invalid",
        "fixture@chinwag..invalid",
        "fixture@chinwag.invalid\0",
        "-fixture@chinwag.invalid",
    ] {
        assert_eq!(
            directory.write_new_allowed_signers(OsStr::new("allowed"), principal, &signer),
            Err(Error::Name)
        );
    }
    for name in [OsStr::new(""), OsStr::new(".."), OsStr::new("a/b")] {
        assert_eq!(
            directory.write_new_allowed_signers(name, "fixture@chinwag.invalid", &signer),
            Err(Error::Name)
        );
    }
    assert_eq!(
        directory.write_new_allowed_signers(
            OsStr::new("oversize"),
            &format!("{}@chinwag.invalid", "a".repeat(MAX_KEY_BYTES)),
            &signer,
        ),
        Err(Error::Format)
    );
    assert_eq!(fs::read_dir(&f.root).unwrap().count(), 0);
}

#[test]
fn loaded_key_comments_cannot_add_public_tokens_or_lines() {
    let f = Fixture::new();
    let directory = PrivateDirectory::open(&f.root).unwrap();
    for (index, comment) in ["synthetic comment", "synthetic\nsecond-line"]
        .into_iter()
        .enumerate()
    {
        let mut signer = key();
        signer.private.set_comment(comment);
        let key_name = format!("signer-{index}");
        directory.write_new(OsStr::new(&key_name), &signer).unwrap();
        let loaded = directory
            .read_existing(OsStr::new(&key_name), &signer.public_bytes())
            .unwrap();
        assert!(loaded.public_openssh().unwrap().contains(comment));
        let allowed_name = format!("allowed-{index}");
        assert_eq!(
            directory.write_new_allowed_signers(
                OsStr::new(&allowed_name),
                "fixture@chinwag.invalid",
                &loaded,
            ),
            Err(Error::Format)
        );
        assert!(!f.root.join(allowed_name).exists());
    }
}

#[test]
fn public_writer_preserves_existing_names_and_uses_the_held_directory() {
    let f = Fixture::new();
    let path = f.root.join("identity");
    let moved = f.root.join("moved");
    let directory = PrivateDirectory::create_new(&path).unwrap();
    let signer = key();
    directory
        .write_new_allowed_signers(OsStr::new("allowed"), "fixture@chinwag.invalid", &signer)
        .unwrap();
    let before = fs::metadata(path.join("allowed")).unwrap();
    let bytes = fs::read(path.join("allowed")).unwrap();
    symlink(path.join("allowed"), path.join("link")).unwrap();
    for name in ["allowed", "link"] {
        assert_eq!(
            directory.write_new_allowed_signers(OsStr::new(name), "other@chinwag.invalid", &signer),
            Err(Error::Exists)
        );
    }
    assert_eq!(fs::read(path.join("allowed")).unwrap(), bytes);
    assert_eq!(
        fs::metadata(path.join("allowed")).unwrap().ino(),
        before.ino()
    );
    fs::rename(&path, &moved).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    directory
        .write_new_allowed_signers(OsStr::new("second"), "second@chinwag.invalid", &signer)
        .unwrap();
    assert!(moved.join("second").is_file());
    assert!(!path.join("second").exists());
    fs::set_permissions(&moved, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        directory.write_new_allowed_signers(OsStr::new("third"), "third@chinwag.invalid", &signer),
        Err(Error::Directory)
    );
    assert!(!moved.join("third").exists());
    fs::set_permissions(&moved, fs::Permissions::from_mode(0o700)).unwrap();
}
