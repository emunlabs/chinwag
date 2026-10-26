//! Fixed Git environment; callers validate operator paths before spawning.
use crate::bundle_io::prefixed;
use tokio::process::Command;

pub(crate) fn command(
    cwd: &std::path::Path,
    templates: &std::path::Path,
    signers: &std::path::Path,
) -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", templates)
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_ATTR_NOSYSTEM", "1");
    for setting in [
        prefixed("core.hooksPath=", templates),
        prefixed("gpg.ssh.allowedSignersFile=", signers),
    ] {
        command.arg("-c").arg(setting);
    }
    for setting in [
        "core.fsmonitor=false",
        "core.sshCommand=",
        "credential.helper=",
        "protocol.allow=never",
        "gpg.format=ssh",
        "gpg.ssh.program=/usr/bin/ssh-keygen",
        "gpg.ssh.revocationFile=/dev/null",
        "gc.auto=0",
        "maintenance.auto=false",
    ] {
        command.arg("-c").arg(setting);
    }
    command
}
