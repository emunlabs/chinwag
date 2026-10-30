use super::*;
use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt, symlink},
        net::UnixListener as StdListener,
    },
};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    alias_parent: PathBuf,
    physical_parent: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("cw-sock-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let alias_parent = root.join("alias");
        let physical_parent = root.join("physical");
        for parent in [&alias_parent, &physical_parent] {
            fs::create_dir(parent).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            _temp: temp,
            root,
            alias_parent,
            physical_parent,
        }
    }
    fn physical(&self) -> PathBuf {
        self.physical_parent.join("server.sock")
    }
    fn alias(&self) -> PathBuf {
        self.alias_parent.join("codex.sock")
    }
    fn listener(&self) -> StdListener {
        let listener = StdListener::bind(self.physical()).unwrap();
        fs::set_permissions(self.physical(), fs::Permissions::from_mode(0o600)).unwrap();
        listener
    }
}

#[test]
fn exact_private_socket_and_documented_final_alias_are_accepted() {
    let fixture = Fixture::new();
    let _listener = fixture.listener();
    let direct = SelectedSocket::observe(&fixture.physical()).unwrap();
    direct.verify().unwrap();
    assert!(direct.link.is_none());
    symlink(fixture.physical(), fixture.alias()).unwrap();
    let selected = SelectedSocket::observe(&fixture.alias()).unwrap();
    selected.verify().unwrap();
    assert_eq!(selected.target, fixture.physical());
    assert_eq!(selected.link.as_ref(), Some(&fixture.physical()));
    assert!(
        fs::symlink_metadata(fixture.alias())
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn relative_final_alias_within_private_parent_resolves_to_exact_physical_socket() {
    let fixture = Fixture::new();
    let path = fixture.alias_parent.join("physical.sock");
    let _listener = StdListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    symlink("physical.sock", fixture.alias()).unwrap();
    let selected = SelectedSocket::observe(&fixture.alias()).unwrap();
    assert_eq!(selected.target, path);
    assert_eq!(selected.link.as_deref(), Some(Path::new("physical.sock")));
    selected.verify().unwrap();
}

#[test]
fn retargeted_final_alias_and_replaced_physical_socket_reject_original_pin() {
    let fixture = Fixture::new();
    let _listener = fixture.listener();
    symlink(fixture.physical(), fixture.alias()).unwrap();
    let selected = SelectedSocket::observe(&fixture.alias()).unwrap();
    let other = fixture.physical_parent.join("other.sock");
    let _other_listener = StdListener::bind(&other).unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(fixture.alias()).unwrap();
    symlink(&other, fixture.alias()).unwrap();
    assert!(selected.verify().is_err());
    assert_eq!(fs::read_link(fixture.alias()).unwrap(), other);
    let direct = SelectedSocket::observe(&fixture.physical()).unwrap();
    fs::remove_file(fixture.physical()).unwrap();
    let _replacement = fixture.listener();
    assert!(direct.verify().is_err());
    assert!(
        fs::symlink_metadata(fixture.physical())
            .unwrap()
            .file_type()
            .is_socket()
    );
}

#[test]
fn public_parent_or_socket_mode_regular_file_and_chained_alias_are_rejected() {
    let fixture = Fixture::new();
    let _listener = fixture.listener();
    symlink(fixture.physical(), fixture.alias()).unwrap();
    fs::set_permissions(fixture.physical(), fs::Permissions::from_mode(0o660)).unwrap();
    assert!(SelectedSocket::observe(&fixture.alias()).is_err());
    fs::set_permissions(fixture.physical(), fs::Permissions::from_mode(0o600)).unwrap();
    for parent in [&fixture.alias_parent, &fixture.physical_parent] {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SelectedSocket::observe(&fixture.alias()).is_err());
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let regular = fixture.alias_parent.join("regular");
    fs::write(&regular, b"not a listener").unwrap();
    fs::set_permissions(&regular, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(SelectedSocket::observe(&regular).is_err());
    assert_eq!(fs::read(&regular).unwrap(), b"not a listener");
    let chained = fixture.alias_parent.join("chained.sock");
    symlink(fixture.alias(), &chained).unwrap();
    assert!(
        SelectedSocket::observe(&chained).is_err(),
        "only the declared final alias is supported"
    );
}

#[test]
fn private_parent_replacement_and_ancestor_symlink_cannot_redirect_a_pin() {
    let fixture = Fixture::new();
    let _listener = fixture.listener();
    symlink(fixture.physical(), fixture.alias()).unwrap();
    let selected = SelectedSocket::observe(&fixture.alias()).unwrap();
    fs::rename(&fixture.alias_parent, fixture.root.join("old-alias")).unwrap();
    fs::create_dir(&fixture.alias_parent).unwrap();
    fs::set_permissions(&fixture.alias_parent, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(fixture.physical(), fixture.alias()).unwrap();
    assert!(selected.verify().is_err());
    let directory_alias = fixture.root.join("dir-link");
    symlink(&fixture.alias_parent, &directory_alias).unwrap();
    assert!(SelectedSocket::observe(&directory_alias.join("codex.sock")).is_err());
}

#[tokio::test]
async fn synthetic_connection_checks_actual_peer_uid_without_sending_protocol_bytes() {
    for through_alias in [false, true] {
        let fixture = Fixture::new();
        let listener = tokio::net::UnixListener::bind(fixture.physical()).unwrap();
        fs::set_permissions(fixture.physical(), fs::Permissions::from_mode(0o600)).unwrap();
        let path = if through_alias {
            symlink(fixture.physical(), fixture.alias()).unwrap();
            fixture.alias()
        } else {
            fixture.physical()
        };
        let selected = SelectedSocket::observe(&path).unwrap();
        let (client, accepted) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(selected.connect(), listener.accept())
        })
        .await
        .unwrap();
        let client = client.unwrap();
        let (peer, _) = accepted.unwrap();
        assert_eq!(
            client.peer_cred().unwrap().uid(),
            rustix::process::geteuid().as_raw()
        );
        assert_eq!(
            peer.peer_cred().unwrap().uid(),
            rustix::process::geteuid().as_raw()
        );
        let mut byte = [0_u8; 1];
        assert!(
            matches!(peer.try_read(&mut byte), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

#[tokio::test]
async fn changed_pin_is_rejected_before_connecting_to_replacement_listener() {
    let fixture = Fixture::new();
    let _listener = fixture.listener();
    let selected = SelectedSocket::observe(&fixture.physical()).unwrap();
    fs::remove_file(fixture.physical()).unwrap();
    let replacement = tokio::net::UnixListener::bind(fixture.physical()).unwrap();
    fs::set_permissions(fixture.physical(), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(selected.connect().await.is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), replacement.accept())
            .await
            .is_err()
    );
}

#[test]
fn selected_work_directory_allows_owned_nonwritable_scope_and_rejects_replacement() {
    let fixture = Fixture::new();
    let cwd = fixture.root.join("work");
    fs::create_dir(&cwd).unwrap();
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o755)).unwrap();
    let pin = SelectedDirectory::observe(&cwd).unwrap();
    pin.verify().unwrap();
    fs::write(cwd.join("ordinary-output.txt"), b"new artifact").unwrap();
    pin.verify().unwrap();
    fs::rename(&cwd, fixture.root.join("old-work")).unwrap();
    fs::create_dir(&cwd).unwrap();
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(pin.verify().is_err());
}

#[test]
fn selected_work_directory_rejects_parent_alias_and_shared_write_permission() {
    let fixture = Fixture::new();
    let cwd = fixture.root.join("work");
    fs::create_dir(&cwd).unwrap();
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(SelectedDirectory::observe(&cwd).is_err());
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o755)).unwrap();
    let alias = fixture.root.join("work-alias");
    symlink(&cwd, &alias).unwrap();
    assert!(SelectedDirectory::observe(&alias).is_err());
}
