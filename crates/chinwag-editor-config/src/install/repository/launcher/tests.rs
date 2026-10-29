use super::Launcher;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};

fn fixture(name: &str, mode: u32) -> PathBuf {
    let root = chinwag_test_fixtures::namespace("CHINWAG_PACKAGED_ALIAS_QA_ROOT");
    assert!(root.is_absolute() && root.is_dir());
    let path = root.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.join("chinwag"))
        .unwrap();
    target.write_all(b"owned launcher fixture\n").unwrap();
    target.sync_all().unwrap();
    fs::set_permissions(path.join("chinwag"), fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn packaged_alias_direct_and_four_exact_sibling_links_complete_checked_finish() {
    for name in [
        "chinwag",
        "git-chinwag",
        "git-emun",
        "gh-chinwag",
        "gh-emun",
    ] {
        let root = fixture(&format!("positive-{name}"), 0o500);
        if name != "chinwag" {
            symlink("chinwag", root.join(name)).unwrap();
        }
        let launcher = Launcher::capture_path(root.join(name)).unwrap();
        assert_eq!(launcher.command(), root.join("chinwag").to_str().unwrap());
        let (files, directories) = launcher.finish().unwrap();
        assert_eq!(files, 1);
        assert!(directories > 0);
    }
}

#[test]
fn packaged_alias_foreign_names_absolute_parent_and_other_targets_refuse() {
    let root = fixture("foreign-name", 0o500);
    symlink("chinwag", root.join("shortcut")).unwrap();
    assert_eq!(
        Launcher::capture_path(root.join("shortcut")).err(),
        Some("unsafe_current_executable_alias")
    );
    for (name, target) in [
        ("absolute-target", "/foreign/chinwag"),
        ("parent-target", "../chinwag"),
        ("other-target", "foreign"),
    ] {
        let root = fixture(name, 0o500);
        symlink(target, root.join("git-chinwag")).unwrap();
        assert!(Launcher::capture_path(root.join("git-chinwag")).is_err());
    }
}

#[test]
fn packaged_alias_target_chains_and_hardlinks_refuse() {
    let root = fixture("target-chain", 0o500);
    fs::rename(root.join("chinwag"), root.join("real-target")).unwrap();
    symlink("real-target", root.join("chinwag")).unwrap();
    symlink("chinwag", root.join("git-emun")).unwrap();
    assert_eq!(
        Launcher::capture_path(root.join("git-emun")).err(),
        Some("open_current_executable")
    );
    let root = fixture("target-hardlink", 0o500);
    fs::hard_link(root.join("chinwag"), root.join("another-name")).unwrap();
    symlink("chinwag", root.join("git-emun")).unwrap();
    assert_eq!(
        Launcher::capture_path(root.join("git-emun")).err(),
        Some("unsafe_current_executable")
    );
}

#[test]
fn packaged_alias_same_target_link_replacement_refuses_original_finish() {
    let root = fixture("alias-replaced", 0o500);
    let alias = root.join("gh-chinwag");
    symlink("chinwag", &alias).unwrap();
    let launcher = Launcher::capture_path(alias.clone()).unwrap();
    // Preserve the original inode under another name so it cannot be reused.
    fs::rename(&alias, root.join("original-alias")).unwrap();
    symlink("chinwag", &alias).unwrap();
    assert_eq!(
        launcher.finish().err(),
        Some("current_executable_alias_changed")
    );
}

#[test]
fn packaged_alias_same_bytes_target_replacement_refuses_original_finish() {
    let root = fixture("target-replaced", 0o500);
    symlink("chinwag", root.join("gh-emun")).unwrap();
    let launcher = Launcher::capture_path(root.join("gh-emun")).unwrap();
    let body = fs::read(root.join("chinwag")).unwrap();
    let replacement = root.join("replacement");
    fs::write(&replacement, body).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o500)).unwrap();
    fs::rename(root.join("chinwag"), root.join("original-target")).unwrap();
    fs::rename(&replacement, root.join("chinwag")).unwrap();
    assert_eq!(launcher.finish().err(), Some("current_executable_changed"));
}

#[test]
fn packaged_alias_held_target_byte_change_refuses_original_finish() {
    let root = fixture("target-bytes", 0o700);
    symlink("chinwag", root.join("git-chinwag")).unwrap();
    let launcher = Launcher::capture_path(root.join("git-chinwag")).unwrap();
    let mut target = OpenOptions::new()
        .write(true)
        .open(root.join("chinwag"))
        .unwrap();
    target.write_all(b"X").unwrap();
    target.sync_all().unwrap();
    assert_eq!(
        launcher.finish().err(),
        Some("current_executable_bytes_changed")
    );
}
