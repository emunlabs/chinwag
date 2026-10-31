use crate::{
    api::valid_id,
    json,
    private::{self, FileLock},
    *,
};
use rustix::fs::{Dir, Mode, OFlags, open, openat};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    schema: String,
    members: Vec<DeclaredMember>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredMember {
    id: String,
    label: String,
    provider: Provider,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Provider {
    Codex {
        owner_socket: PathBuf,
        workdir: PathBuf,
        runtime_policy: String,
    },
    Claude {
        binary: PathBuf,
        sha256: String,
        workdir: PathBuf,
        startup_policy: String,
    },
    Gemini {
        binary: PathBuf,
        sha256: String,
        workdir: PathBuf,
        startup_policy: String,
    },
}
pub(crate) struct StateLease {
    path: PathBuf,
    directory: File,
    lock: FileLock,
    manifest: File,
    bytes: Vec<u8>,
}
impl StateLease {
    pub(crate) fn verify(&self) -> Result<()> {
        private::verify_root(&self.path, &self.directory)?;
        private::named_file(&self.directory, "team.lock", &self.lock.0)?;
        private::named_file(&self.directory, "launch.json", &self.manifest)?;
        if private::read_bounded(&self.manifest, 16384)? != self.bytes {
            return Err(TeamError::Storage);
        }
        Ok(())
    }
}
pub(crate) struct Loaded {
    pub(crate) lease: StateLease,
    pub(crate) members: Vec<Member>,
    pub(crate) actions: PathBuf,
}
fn invalid(_: impl std::fmt::Display) -> TeamError {
    TeamError::InvalidInput
}
fn storage(_: impl std::fmt::Display) -> TeamError {
    TeamError::Storage
}
pub(crate) fn load(config_path: &Path, state_root: &Path) -> Result<Loaded> {
    if !config_path.is_absolute() {
        return Err(TeamError::InvalidInput);
    }
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file: File = open(config_path, flags, Mode::empty())
        .map_err(invalid)?
        .into();
    let original = private::read_bounded(&file, 16384)?;
    let parsed: Launch = json::decode(&original, 16384)?;
    let named: File = open(config_path, flags, Mode::empty())
        .map_err(invalid)?
        .into();
    private::same_file(&file, &named)?;
    if private::read_bounded(&file, 16384)? != original {
        return Err(TeamError::Storage);
    }
    validate(&parsed)?;
    let bytes = serde_json::to_vec(&parsed).map_err(invalid)?;
    if bytes.len() > 16384 {
        return Err(TeamError::InvalidInput);
    }
    let (directory, _, _) = private::open_root(state_root, true)?;
    let lock = private::lock(&directory, "team.lock")?;
    let manifest = match openat(&directory, "launch.json", flags, Mode::empty()) {
        Ok(fd) => {
            let f: File = fd.into();
            if private::read_bounded(&f, 16384)? != bytes {
                return Err(TeamError::Storage);
            }
            private::named_file(&directory, "launch.json", &f)?;
            f
        }
        Err(e) if e == rustix::io::Errno::NOENT => {
            for item in Dir::read_from(&directory).map_err(storage)? {
                let item = item.map_err(storage)?;
                if !matches!(item.file_name().to_bytes(), b"." | b".." | b"team.lock") {
                    return Err(TeamError::Storage);
                }
            }
            private::write_new(&directory, "launch.json", &bytes)?
        }
        Err(_) => return Err(TeamError::Storage),
    };
    let lease = StateLease {
        path: state_root.into(),
        directory,
        lock,
        manifest,
        bytes,
    };
    lease.verify()?;
    let members_root = state_root.join("members");
    private::open_root(&members_root, true)?;
    let actions = state_root.join("actions");
    let (ad, _, _) = private::open_root(&actions, true)?;
    let mut roots = vec![ad];
    let mut members = Vec::new();
    for m in parsed.members {
        lease.verify()?;
        let mr = members_root.join(&m.id);
        private::open_root(&mr, true)?;
        let native = mr.join("native");
        let (nd, _, _) = private::open_root(&native, true)?;
        for old in &roots {
            let a = nd.metadata().map_err(storage)?;
            let b = old.metadata().map_err(storage)?;
            if a.dev() == b.dev() && a.ino() == b.ino() {
                return Err(TeamError::InvalidInput);
            }
        }
        roots.push(nd);
        let port = match m.provider {
            Provider::Codex {
                owner_socket,
                workdir,
                ..
            } => {
                let c=chinwag_codex_steer::WorkConfig::new(&owner_socket,&workdir,&native,chinwag_codex_steer::RuntimePolicyDeclaration::DedicatedRuntimeWithExplicitLogin).map_err(invalid)?;
                HeldWorkPort::Codex(
                    chinwag_codex_steer::open_work_service(c)
                        .map_err(|_| TeamError::Unavailable)?,
                )
            }
            Provider::Claude {
                binary,
                sha256,
                workdir,
                ..
            } => {
                let c = chinwag_claude_control::WorkConfig::new(
                    &binary,
                    &sha256,
                    &workdir,
                    &native,
                    chinwag_claude_control::StartupPolicyDeclaration::ManagedPolicyProseOnly,
                )
                .map_err(invalid)?;
                HeldWorkPort::Claude(
                    chinwag_claude_control::open_work_service(c)
                        .map_err(|_| TeamError::Unavailable)?,
                )
            }
            Provider::Gemini {
                binary,
                sha256,
                workdir,
                ..
            } => {
                let c=chinwag_gemini_control::WorkConfig::new(&binary,&sha256,&workdir,&native,chinwag_gemini_control::StartupPolicyDeclaration::ConfiguredRuntimeEffectsManualModeExtensionsDisabled).map_err(invalid)?;
                HeldWorkPort::Gemini(
                    chinwag_gemini_control::open_work_service(c)
                        .map_err(|_| TeamError::Unavailable)?,
                )
            }
        };
        members.push(Member {
            id: m.id,
            label: m.label,
            port,
        });
    }
    lease.verify()?;
    Ok(Loaded {
        lease,
        members,
        actions,
    })
}
fn validate(l: &Launch) -> Result<()> {
    if l.schema != "chinwag-team-launch/v1" || l.members.is_empty() || l.members.len() > MAX_MEMBERS
    {
        return Err(TeamError::InvalidInput);
    }
    let mut ids = BTreeSet::new();
    let placeholder = Path::new("/owner/team/member/native");
    for m in &l.members {
        if !valid_id(&m.id)
            || !ids.insert(&m.id)
            || m.label.trim().is_empty()
            || m.label.len() > 64
            || m.label.chars().any(char::is_control)
        {
            return Err(TeamError::InvalidInput);
        }
        match &m.provider {
            Provider::Codex {
                owner_socket,
                workdir,
                runtime_policy,
            } => {
                if runtime_policy != "dedicated_runtime_with_explicit_login" {
                    return Err(TeamError::InvalidInput);
                }
                chinwag_codex_steer::WorkConfig::new(owner_socket,workdir,placeholder,chinwag_codex_steer::RuntimePolicyDeclaration::DedicatedRuntimeWithExplicitLogin).map_err(invalid)?;
            }
            Provider::Claude {
                binary,
                sha256,
                workdir,
                startup_policy,
            } => {
                if startup_policy != "managed_policy_prose_only" {
                    return Err(TeamError::InvalidInput);
                }
                chinwag_claude_control::WorkConfig::new(
                    binary,
                    sha256,
                    workdir,
                    placeholder,
                    chinwag_claude_control::StartupPolicyDeclaration::ManagedPolicyProseOnly,
                )
                .map_err(invalid)?;
            }
            Provider::Gemini {
                binary,
                sha256,
                workdir,
                startup_policy,
            } => {
                if startup_policy != "configured_runtime_effects_manual_mode_extensions_disabled" {
                    return Err(TeamError::InvalidInput);
                }
                chinwag_gemini_control::WorkConfig::new(binary,sha256,workdir,placeholder,chinwag_gemini_control::StartupPolicyDeclaration::ConfiguredRuntimeEffectsManualModeExtensionsDisabled).map_err(invalid)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
