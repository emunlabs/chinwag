use super::*;

pub(super) fn validate_layout(entries: &[Entry], principal: &str) -> Result<(), &'static str> {
    if entries
        .iter()
        .any(|entry| entry.key.starts_with("include.") || entry.key.starts_with("includeif."))
    {
        return Err("signing_include");
    }
    if entries
        .iter()
        .any(|entry| entry.key.starts_with("extensions.") || entry.key == "core.worktree")
    {
        return Err("signing_unsupported");
    }
    match singles(entries, "core.bare") {
        ValueSet::Absent | ValueSet::One(Some("false")) => {}
        _ => return Err("signing_unsupported"),
    }
    match singles(entries, "core.repositoryformatversion") {
        ValueSet::Absent | ValueSet::One(Some("0")) => {}
        _ => return Err("signing_unsupported"),
    }
    match singles(entries, "user.email") {
        ValueSet::One(Some(value)) if value == principal => {}
        _ => return Err("signing_email"),
    }
    Ok(())
}

pub(super) fn planned_sets(
    entries: &[Entry],
    key_path: &str,
    allowed_path: &str,
) -> Result<Vec<(String, String)>, &'static str> {
    let wanted = [
        ("gpg.format", "ssh"),
        ("commit.gpgsign", "true"),
        ("user.signingkey", key_path),
        ("gpg.ssh.allowedsignersfile", allowed_path),
    ];
    let mut sets = Vec::new();
    for (key, value) in wanted {
        match singles(entries, key) {
            ValueSet::Absent => sets.push((key.to_owned(), value.to_owned())),
            ValueSet::One(Some(found)) if found == value => {}
            _ => return Err("signing_conflict"),
        }
    }
    Ok(sets)
}

pub(super) fn exact_managed(
    entries: &[Entry],
    key_path: &str,
    allowed_path: &str,
) -> Result<(), &'static str> {
    if !planned_sets(entries, key_path, allowed_path)?.is_empty() {
        return Err("signing_conflict");
    }
    Ok(())
}

enum ValueSet<'a> {
    Absent,
    One(Option<&'a str>),
    Many,
}

fn singles<'a>(entries: &'a [Entry], key: &str) -> ValueSet<'a> {
    let mut found = Vec::new();
    for entry in entries {
        if entry.key == key {
            found.push(entry.value.as_deref());
        }
    }
    match found.as_slice() {
        [] => ValueSet::Absent,
        [one] => ValueSet::One(*one),
        _ => ValueSet::Many,
    }
}

pub(super) fn unmanaged(entries: &[Entry]) -> Vec<Entry> {
    entries
        .iter()
        .filter(|entry| !MANAGED.contains(&entry.key.as_str()))
        .cloned()
        .collect()
}

pub(super) fn parse_null(bytes: &[u8]) -> Result<Vec<Entry>, &'static str> {
    if bytes.len() > MAX_BYTES || (!bytes.is_empty() && bytes.last() != Some(&0)) {
        return Err("signing_unsupported");
    }
    let mut entries = Vec::new();
    for record in bytes.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        let text = std::str::from_utf8(record).map_err(|_| "signing_format")?;
        let entry = match text.split_once('\n') {
            Some((key, value)) => Entry {
                key: key.to_owned(),
                value: Some(value.to_owned()),
            },
            None => Entry {
                key: text.to_owned(),
                value: None,
            },
        };
        if entry.key.is_empty() || entries.len() == 4096 {
            return Err("signing_format");
        }
        entries.push(entry);
    }
    Ok(entries)
}

pub(super) fn allowed_line(principal: &str, openssh: &str) -> Result<String, &'static str> {
    let token = openssh.trim_end_matches(['\n', '\r']);
    let parts: Vec<_> = token.split_ascii_whitespace().collect();
    if parts.len() != 2 || parts[0] != "ssh-ed25519" || token.contains(['\n', '\r']) {
        return Err("signing_format");
    }
    Ok(format!("{principal} namespaces=\"git\" {token}\n"))
}

pub(super) fn read_exact_public(
    dir: &PrivateDirectory,
    name: &OsStr,
    expected: &[u8],
) -> Result<(), &'static str> {
    validate_component(name)?;
    let fd = openat(
        dir.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "signing_file")?;
    let stat = fstat(&fd).map_err(|_| "signing_file")?;
    let id = identity(&stat)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || id.uid != rustix::process::geteuid().as_raw()
        || id.nlink != 1
        || supported_mode(id.mode).is_none()
        || id.size != expected.len() as u64
    {
        return Err("signing_file");
    }
    let mut file = File::from(fd);
    let body = read_limited(&mut file)?;
    let after = identity(&fstat(&file).map_err(|_| "signing_file")?)?;
    let named = identity(
        &statat(dir.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| "signing_file")?,
    )?;
    if body != expected || !same_id(&id, &after) || !same_id(&after, &named) {
        Err("signing_conflict")
    } else {
        Ok(())
    }
}

pub(super) fn exclusive_file(dir: &OwnedFd, name: &str) -> Result<File, &'static str> {
    let fd = openat(
        dir,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| "signing_create")?;
    Ok(File::from(fd))
}

pub(super) fn read_named(dir: &OwnedFd, name: &str) -> Result<(Id, Vec<u8>), &'static str> {
    let fd = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "signing_file")?;
    let stat = fstat(&fd).map_err(|_| "signing_file")?;
    let id = identity(&stat)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || id.nlink != 1
        || id.size > MAX_BYTES as u64
    {
        return Err("signing_file");
    }
    if id.uid != rustix::process::geteuid().as_raw() {
        return Err("signing_file");
    }
    let mut file = File::from(fd);
    let body = read_limited(&mut file)?;
    let after = identity(&fstat(&file).map_err(|_| "signing_file")?)?;
    let named =
        identity(&statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| "signing_file")?)?;
    if body.len() as u64 != id.size || !same_id(&id, &after) || !same_id(&after, &named) {
        return Err("signing_race");
    }
    Ok((id, body))
}

pub(super) fn read_limited(file: &mut File) -> Result<Vec<u8>, &'static str> {
    file.seek(SeekFrom::Start(0)).map_err(|_| "signing_io")?;
    let mut body = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| "signing_io")?;
    if body.len() > MAX_BYTES {
        Err("signing_unsupported")
    } else {
        Ok(body)
    }
}

pub(super) fn open_absolute_dir(path: &Path) -> Result<OwnedFd, &'static str> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err("signing_directory");
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = open("/", flags, Mode::empty()).map_err(|_| "signing_directory")?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err("signing_directory");
        };
        fd = openat(&fd, name, flags, Mode::empty()).map_err(|_| "signing_directory")?;
    }
    let stat = fstat(&fd).map_err(|_| "signing_directory")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o022 != 0
        || stat.st_mode & 0o200 == 0
    {
        return Err("signing_unsupported");
    }
    Ok(fd)
}

pub(super) fn refuse_present(dir: &OwnedFd, name: &str) -> Result<(), &'static str> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Err("signing_unsupported"),
        Err(Errno::NOENT) => Ok(()),
        Err(_) => Err("signing_directory"),
    }
}

pub(super) fn identity(stat: &Stat) -> Result<Id, &'static str> {
    if stat.st_size < 0 {
        return Err("signing_file");
    }
    Ok(Id {
        dev: stat.st_dev,
        ino: stat.st_ino,
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode,
        nlink: u64::from(stat.st_nlink),
        size: stat.st_size as u64,
    })
}

pub(super) fn same_id(left: &Id, right: &Id) -> bool {
    left.dev == right.dev
        && left.ino == right.ino
        && left.uid == right.uid
        && left.gid == right.gid
        && left.mode == right.mode
        && left.nlink == right.nlink
        && left.size == right.size
}

pub(super) fn supported_mode(mode: u16) -> Option<u16> {
    let bits = mode & 0o7777;
    matches!(bits, 0o600 | 0o640 | 0o644).then_some(bits)
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    let hashed = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hashed);
    out
}

pub(super) fn validate_token(value: &str) -> Result<(), &'static str> {
    crate::validate_principal(value).map_err(|_| "signing_name")
}

pub(crate) fn validate_component(name: &OsStr) -> Result<(), &'static str> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
        || bytes.contains(&b'\n')
        || bytes.contains(&b'\r')
        || bytes.contains(&b'-') && bytes[0] == b'-'
    {
        Err("signing_name")
    } else {
        Ok(())
    }
}

pub(crate) fn path_text(path: &Path) -> Result<String, &'static str> {
    let text = path.to_str().ok_or("signing_directory")?;
    if !path.is_absolute() || text.contains(['\n', '\r']) || text.contains('\0') {
        Err("signing_directory")
    } else {
        Ok(text.to_owned())
    }
}

pub(super) fn join_component(directory: &str, name: &OsStr) -> Result<String, &'static str> {
    let name = name.to_str().ok_or("signing_name")?;
    if name.contains('/') || name.contains(['\n', '\r']) {
        return Err("signing_name");
    }
    Ok(format!("{directory}/{name}"))
}
