use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CandidateState, ClientCandidate, ClientFamily, Coverage, DiscoveryError, ProcessBirth,
    ProcessRole,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservedProcess {
    pub birth: ProcessBirth,
    pub parent_pid: u32,
    pub uid: u32,
    pub process_group: u32,
    pub executable: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathMatch {
    Named(ClientFamily, ProcessRole, Option<String>),
    Interpreter,
    Other,
}

pub(crate) fn classify_path(path: &str) -> PathMatch {
    if !path.starts_with('/') || path.contains('\0') {
        return PathMatch::Other;
    }
    if let Some((prefix, inside)) = path.split_once(".app/Contents/") {
        // Only the outer public application boundary is considered. An embedded
        // CodexCLI.app under ChatGPT.app is a component of ChatGPT, not a new app.
        let bundle = format!("{prefix}.app");
        let Some((directory, name)) = bundle.rsplit_once('/') else {
            return PathMatch::Other;
        };
        let public_directory = directory == "/Applications"
            || directory
                .strip_prefix("/Users/")
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(user, tail)| !user.is_empty() && tail == "Applications");
        if !public_directory {
            return PathMatch::Other;
        }
        let (family, main_executable) = match name {
            "Grok Bot.app" => (ClientFamily::GrokBot, "Grok Bot"),
            "Claude.app" => (ClientFamily::ClaudeDesktop, "Claude"),
            "ChatGPT.app" => (ClientFamily::ChatgptDesktop, "ChatGPT"),
            "Codex.app" => (ClientFamily::CodexDesktop, "Codex"),
            "Gemini.app" => (ClientFamily::GeminiDesktop, "Gemini"),
            "Antigravity.app" => (ClientFamily::GoogleAntigravity, "Antigravity"),
            "Cursor.app" => (ClientFamily::Cursor, "Cursor"),
            "Windsurf.app" => (ClientFamily::Windsurf, "Electron"),
            "Visual Studio Code.app" => (ClientFamily::VisualStudioCode, "Code"),
            "Zed.app" => (ClientFamily::Zed, "zed"),
            "Warp.app" => (ClientFamily::Warp, "stable"),
            "Kiro.app" => (ClientFamily::Kiro, "Kiro"),
            "LM Studio.app" => (ClientFamily::LmStudio, "LM Studio"),
            "Ollama.app" => (ClientFamily::Ollama, "Ollama"),
            "Goose.app" => (ClientFamily::Goose, "Goose"),
            "Jan.app" => (ClientFamily::Jan, "Jan"),
            "Msty.app" => (ClientFamily::Msty, "Msty"),
            "Cherry Studio.app" => (ClientFamily::CherryStudio, "Cherry Studio"),
            "BoltAI.app" => (ClientFamily::Boltai, "BoltAI"),
            "Chatbox.app" => (ClientFamily::Chatbox, "Chatbox"),
            "GPT4All.app" => (ClientFamily::Gpt4all, "GPT4All"),
            "AnythingLLM.app" => (ClientFamily::AnythingLlm, "AnythingLLM"),
            "Perplexity.app" => (ClientFamily::Perplexity, "Perplexity"),
            _ => return PathMatch::Other,
        };
        let role = match inside.strip_prefix("MacOS/") {
            Some(binary) if binary == main_executable => ProcessRole::MainApplication,
            _ => ProcessRole::BundledComponent,
        };
        return PathMatch::Named(family, role, Some(bundle));
    }
    let basename = path.rsplit('/').next().unwrap_or("");
    // Native Claude installations use a version-number executable, not `claude`.
    let claude_version = path
        .strip_prefix("/Users/")
        .and_then(|rest| rest.split_once('/'))
        .and_then(|(_, rest)| rest.strip_prefix(".local/share/claude/versions/"))
        .is_some_and(|version| {
            !version.is_empty()
                && !version.contains('/')
                && version.chars().all(|c| c.is_ascii_digit() || c == '.')
        });
    let family = match basename {
        "codex" => ClientFamily::CodexCli,
        "claude" => ClientFamily::ClaudeCode,
        _ if claude_version => ClientFamily::ClaudeCode,
        "gemini" => ClientFamily::GeminiCli,
        "opencode" | "opencode.exe" => ClientFamily::Opencode,
        "aider" => ClientFamily::Aider,
        "copilot" => ClientFamily::GithubCopilot,
        "kiro" => ClientFamily::Kiro,
        "q" => ClientFamily::AmazonQ,
        "cursor" => ClientFamily::Cursor,
        "windsurf" => ClientFamily::Windsurf,
        "ollama" => ClientFamily::Ollama,
        "lms" => ClientFamily::LmStudio,
        "goose" => ClientFamily::Goose,
        "amp" => ClientFamily::Amp,
        "droid" => ClientFamily::Droid,
        "continue" | "cn" => ClientFamily::Continue,
        "cline" => ClientFamily::Cline,
        "roo" => ClientFamily::RooCode,
        "mistral-vibe" | "vibe" => ClientFamily::MistralVibe,
        "warp" => ClientFamily::Warp,
        "zed" => ClientFamily::Zed,
        "node" | "node_repl" | "python" | "python3" | "bun" | "deno" => {
            return PathMatch::Interpreter;
        }
        _ => return PathMatch::Other,
    };
    PathMatch::Named(family, ProcessRole::CommandLine, None)
}

pub(crate) fn candidate_from_pair(
    first: ObservedProcess,
    second: ObservedProcess,
) -> Option<ClientCandidate> {
    if first != second {
        return None;
    }
    let PathMatch::Named(family, role, outer_application) = classify_path(&first.executable) else {
        return None;
    };
    Some(ClientCandidate {
        family,
        role,
        state: CandidateState::DetectedUnverified,
        birth: first.birth,
        parent_pid: first.parent_pid,
        uid: first.uid,
        process_group: first.process_group,
        executable: first.executable,
        outer_application,
        sampled_parent_birth: None,
        instance_root: None,
    })
}

pub(crate) fn finish_candidates(
    mut candidates: Vec<ClientCandidate>,
    coverage: &mut Coverage,
    cap: usize,
) -> Vec<ClientCandidate> {
    candidates.sort_by_key(|candidate| candidate.birth.pid);
    coverage.omitted_candidate_count = candidates.len().saturating_sub(cap);
    coverage.candidate_capacity_reached = candidates.len() >= cap;
    candidates.truncate(cap);
    let indices: BTreeMap<u32, usize> = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| (candidate.birth.pid, index))
        .collect();
    for index in 0..candidates.len() {
        let candidate = &candidates[index];
        let parent = indices
            .get(&candidate.parent_pid)
            .and_then(|&parent| candidates.get(parent))
            .filter(|parent| valid_parent(candidate, parent));
        let sampled_parent_birth = parent.map(|parent| parent.birth);
        let instance_root = resolve_root(index, &candidates, &indices);
        candidates[index].sampled_parent_birth = sampled_parent_birth;
        candidates[index].instance_root = instance_root;
    }
    candidates
}

fn valid_parent(child: &ClientCandidate, parent: &ClientCandidate) -> bool {
    child.birth.pid != parent.birth.pid
        && child.uid == parent.uid
        && (parent.birth.start_seconds, parent.birth.start_microseconds)
            <= (child.birth.start_seconds, child.birth.start_microseconds)
}

fn resolve_root(
    index: usize,
    candidates: &[ClientCandidate],
    indices: &BTreeMap<u32, usize>,
) -> Option<ProcessBirth> {
    let original = &candidates[index];
    if original.role != ProcessRole::BundledComponent {
        return Some(original.birth);
    }
    let mut current = original;
    let mut visited = BTreeSet::new();
    while visited.insert(current.birth.pid) {
        let parent = indices
            .get(&current.parent_pid)
            .and_then(|&parent| candidates.get(parent))?;
        if !valid_parent(current, parent)
            || parent.family != original.family
            || parent.outer_application != original.outer_application
        {
            return None;
        }
        if parent.role == ProcessRole::MainApplication {
            return Some(parent.birth);
        }
        current = parent;
    }
    None
}

/// `proc_listpids` returns a byte count, unlike `proc_listallpids`.
pub(crate) fn decode_pid_list(
    returned: i32,
    buffer: &[i32],
) -> Result<(Vec<i32>, bool, usize), DiscoveryError> {
    let returned = usize::try_from(returned)
        .map_err(|_| DiscoveryError::InvalidSnapshot("negative PID byte count"))?;
    let capacity = std::mem::size_of_val(buffer);
    if returned == 0 || returned > capacity || !returned.is_multiple_of(size_of::<i32>()) {
        return Err(DiscoveryError::InvalidSnapshot("invalid PID byte count"));
    }
    let mut seen = BTreeSet::new();
    let mut pids = Vec::new();
    let mut zeros = 0;
    for &pid in &buffer[..returned / size_of::<i32>()] {
        if pid == 0 {
            zeros += 1;
            continue;
        }
        if pid < 0 || !seen.insert(pid) {
            return Err(DiscoveryError::InvalidSnapshot("invalid or duplicate PID"));
        }
        pids.push(pid);
    }
    Ok((pids, returned == capacity, zeros))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, parent: u32, path: &str) -> ObservedProcess {
        ObservedProcess {
            birth: ProcessBirth {
                pid,
                start_seconds: u64::from(pid),
                start_microseconds: 1,
            },
            parent_pid: parent,
            uid: 501,
            process_group: pid,
            executable: path.to_owned(),
        }
    }

    fn candidate(process: ObservedProcess) -> ClientCandidate {
        candidate_from_pair(process.clone(), process).unwrap()
    }

    #[test]
    fn pid_reuse_path_uid_and_parent_changes_reject_the_observation() {
        let original = process(30, 20, "/usr/local/bin/codex");
        let mut changes = [
            original.clone(),
            original.clone(),
            original.clone(),
            original.clone(),
        ];
        changes[0].birth.start_seconds += 1;
        changes[1].executable = "/usr/local/bin/claude".to_owned();
        changes[2].uid = 502;
        changes[3].parent_pid = 21;
        for changed in changes {
            assert!(candidate_from_pair(original.clone(), changed).is_none());
        }
    }

    #[test]
    fn nested_codex_is_a_chatgpt_component_with_verified_ancestry_only() {
        let main = candidate(process(
            10,
            1,
            "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
        ));
        let worker = candidate(process(
            20,
            10,
            "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex",
        ));
        let mut coverage = Coverage::default();
        let rows = finish_candidates(vec![worker.clone(), main.clone()], &mut coverage, 128);
        assert_eq!(rows[1].family, ClientFamily::ChatgptDesktop);
        assert_eq!(rows[1].role, ProcessRole::BundledComponent);
        assert_eq!(rows[1].sampled_parent_birth, Some(main.birth));
        assert_eq!(rows[1].instance_root, Some(main.birth));
        let orphan = finish_candidates(vec![worker], &mut coverage, 128);
        assert_eq!(orphan[0].instance_root, None);
        assert_eq!(orphan[0].sampled_parent_birth, None);
    }

    #[test]
    fn independent_mains_and_clis_stay_separate_and_cross_uid_helpers_do_not_group() {
        let main = candidate(process(
            10,
            1,
            "/Applications/Claude.app/Contents/MacOS/Claude",
        ));
        let another = candidate(process(
            11,
            1,
            "/Applications/Claude.app/Contents/MacOS/Claude",
        ));
        let mut helper = candidate(process(
            20,
            10,
            "/Applications/Claude.app/Contents/Frameworks/Helper",
        ));
        helper.uid = 502;
        let cli = candidate(process(30, 10, "/usr/local/bin/claude"));
        let rows = finish_candidates(
            vec![main.clone(), another.clone(), helper, cli.clone()],
            &mut Coverage::default(),
            128,
        );
        assert_eq!(rows[0].instance_root, Some(main.birth));
        assert_eq!(rows[1].instance_root, Some(another.birth));
        assert_eq!(rows[2].instance_root, None);
        assert_eq!(rows[3].instance_root, Some(cli.birth));
    }

    #[test]
    fn direct_macos_sibling_is_a_component_and_cannot_self_root_when_orphaned() {
        let main = candidate(process(
            10,
            1,
            "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
        ));
        let direct = candidate(process(
            20,
            10,
            "/Applications/ChatGPT.app/Contents/MacOS/codex",
        ));
        let rows = finish_candidates(
            vec![main.clone(), direct.clone()],
            &mut Coverage::default(),
            128,
        );
        assert_eq!(rows[1].role, ProcessRole::BundledComponent);
        assert_eq!(rows[1].instance_root, Some(main.birth));
        let orphan = finish_candidates(vec![direct], &mut Coverage::default(), 128);
        assert_eq!(orphan[0].role, ProcessRole::BundledComponent);
        assert_eq!(orphan[0].instance_root, None);
        assert!(matches!(
            classify_path("/Applications/ChatGPT.app/Contents/MacOS/crashpad_handler"),
            PathMatch::Named(
                ClientFamily::ChatgptDesktop,
                ProcessRole::BundledComponent,
                _
            )
        ));
    }

    #[test]
    fn candidate_and_pid_caps_are_independent_and_missing_main_does_not_create_an_agent() {
        let rows = vec![
            candidate(process(10, 1, "/usr/local/bin/codex")),
            candidate(process(
                20,
                30,
                "/Applications/Grok Bot.app/Contents/Frameworks/Helper",
            )),
            candidate(process(
                30,
                1,
                "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot",
            )),
        ];
        let mut coverage = Coverage::default();
        let retained = finish_candidates(rows, &mut coverage, 2);
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[1].instance_root, None);
        assert!(coverage.candidate_capacity_reached);
        assert_eq!(coverage.omitted_candidate_count, 1);
        assert!(!coverage.pid_capacity_reached);
        assert_eq!(
            decode_pid_list(8, &[10, 20]).unwrap(),
            (vec![10, 20], true, 0)
        );
        assert_eq!(
            decode_pid_list(8, &[10, 0, 0]).unwrap(),
            (vec![10], false, 1)
        );
    }

    #[test]
    fn malformed_pid_counts_and_duplicates_do_not_claim_complete_coverage() {
        for count in [-1, 0, 1, 3, 9, i32::MAX] {
            assert!(decode_pid_list(count, &[10, 20]).is_err());
        }
        assert!(decode_pid_list(8, &[10, 10]).is_err());
        assert!(decode_pid_list(8, &[10, -1]).is_err());
    }

    #[test]
    fn exact_app_boundaries_and_generic_interpreters_do_not_invent_families() {
        for path in [
            "/Applications/notChatGPT.app/Contents/MacOS/ChatGPT",
            "/Applications/CursorFake.app/Contents/MacOS/Cursor",
            "/Applications/Unrelated.app/Contents/Resources/ChatGPT.app/Contents/MacOS/ChatGPT",
            "/tmp/ChatGPT.app/Contents/MacOS/ChatGPT",
            "codex",
        ] {
            assert_eq!(classify_path(path), PathMatch::Other);
        }
        assert_eq!(
            classify_path("/opt/homebrew/bin/node"),
            PathMatch::Interpreter
        );
        assert_eq!(classify_path("/usr/bin/python3"), PathMatch::Interpreter);
        assert_eq!(
            classify_path("/Users/brian/.memo/bin/gemini.js"),
            PathMatch::Other
        );
        assert_eq!(
            classify_path("/Users/brian/.local/share/claude/versions/2.1.311"),
            PathMatch::Named(ClientFamily::ClaudeCode, ProcessRole::CommandLine, None)
        );
    }

    #[test]
    fn cycles_and_younger_parents_do_not_create_helper_ownership() {
        let mut first = candidate(process(
            10,
            20,
            "/Applications/Grok Bot.app/Contents/Frameworks/One",
        ));
        let mut second = candidate(process(
            20,
            10,
            "/Applications/Grok Bot.app/Contents/Frameworks/Two",
        ));
        first.birth.start_seconds = 1;
        second.birth.start_seconds = 1;
        let rows = finish_candidates(vec![first, second], &mut Coverage::default(), 128);
        assert!(rows.iter().all(|row| row.instance_root.is_none()));
        let helper = candidate(process(
            10,
            20,
            "/Applications/Grok Bot.app/Contents/Frameworks/One",
        ));
        let main = candidate(process(
            20,
            1,
            "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot",
        ));
        let rows = finish_candidates(vec![helper, main], &mut Coverage::default(), 128);
        assert_eq!(rows[0].sampled_parent_birth, None);
        assert_eq!(rows[0].instance_root, None);
    }

    #[test]
    fn serialized_candidate_never_claims_authentication_or_readiness() {
        let row = candidate(process(10, 1, "/usr/local/bin/codex"));
        let json = serde_json::to_value(row).unwrap();
        assert_eq!(json["state"], "detected_unverified");
        assert_eq!(json["family"], "codex_cli");
        assert!(json.get("connected").is_none());
        assert!(json.get("bundle_id").is_none());
    }
}
