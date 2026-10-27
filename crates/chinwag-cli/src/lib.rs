#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invocation {
    Chinwag,
    GitChinwag,
    GitEmun,
    GhChinwag,
    GhEmun,
}

impl Invocation {
    fn from_program(program: &OsStr) -> Option<Self> {
        let basename = Path::new(program).file_name()?;
        if basename == "chinwag" {
            Some(Self::Chinwag)
        } else if basename == "git-chinwag" {
            Some(Self::GitChinwag)
        } else if basename == "git-emun" {
            Some(Self::GitEmun)
        } else if basename == "gh-chinwag" {
            Some(Self::GhChinwag)
        } else if basename == "gh-emun" {
            Some(Self::GhEmun)
        } else {
            None
        }
    }

    fn help(self) -> &'static str {
        match self {
            Self::Chinwag => {
                "Usage: chinwag [--help | --version]\n       chinwag init --help\n       chinwag mcp-serve --repo <absolute-path> [--transport stdio|http]\n       chinwag configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nLocal Git SSH signing and an offline store for a new repository.\n"
            }
            Self::GitChinwag => {
                "Usage: git chinwag [--help | --version]\n       git chinwag init --help\n       git chinwag mcp-serve --repo <absolute-path> [--transport stdio|http]\n       git chinwag configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nLocal Git SSH signing and an offline store for a new repository.\n"
            }
            Self::GitEmun => {
                "Usage: git emun [--help | --version]\n       git emun init --help\n       git emun mcp-serve --repo <absolute-path> [--transport stdio|http]\n       git emun configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nLocal Git SSH signing and an offline store for a new repository.\n"
            }
            Self::GhChinwag => {
                "Usage: gh chinwag [--help | --version]\n       gh chinwag init --help\n       gh chinwag mcp-serve --repo <absolute-path> [--transport stdio|http]\n       gh chinwag configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nLocal Git SSH signing and an offline store for a new repository.\n"
            }
            Self::GhEmun => {
                "Usage: gh emun [--help | --version]\n       gh emun init --help\n       gh emun mcp-serve --repo <absolute-path> [--transport stdio|http]\n       gh emun configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nLocal Git SSH signing and an offline store for a new repository.\n"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    UnknownInvocation,
    NotInThisCandidate,
    InvalidArguments,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Help(Invocation),
    Version,
    InitHelp(Invocation),
    ServeHelp(Invocation),
    ConfigureHelp(Invocation),
    AgentDispatchHelp(Invocation),
    MemoryHelp(Invocation),
    Rejected(Rejection),
}

impl Exit {
    pub fn code(self) -> u8 {
        match self {
            Self::Help(_)
            | Self::Version
            | Self::InitHelp(_)
            | Self::ServeHelp(_)
            | Self::ConfigureHelp(_)
            | Self::AgentDispatchHelp(_)
            | Self::MemoryHelp(_) => 0,
            Self::Rejected(_) => 2,
        }
    }

    pub fn stdout(self) -> &'static str {
        match self {
            Self::Help(invocation) => invocation.help(),
            Self::InitHelp(invocation) => invocation.init_help(),
            Self::ServeHelp(invocation) => invocation.serve_help(),
            Self::ConfigureHelp(invocation) => invocation.configure_help(),
            Self::AgentDispatchHelp(invocation) => invocation.agent_dispatch_help(),
            Self::MemoryHelp(invocation) => invocation.memory_help(),
            Self::Version => concat!(
                "chinwag ",
                env!("CARGO_PKG_VERSION"),
                " (uncommitted candidate)\n"
            ),
            Self::Rejected(_) => "",
        }
    }

    pub fn stderr(self) -> &'static str {
        match self {
            Self::Help(_)
            | Self::Version
            | Self::InitHelp(_)
            | Self::ServeHelp(_)
            | Self::ConfigureHelp(_)
            | Self::AgentDispatchHelp(_)
            | Self::MemoryHelp(_) => "",
            Self::Rejected(Rejection::UnknownInvocation) => "chinwag: unknown_invocation\n",
            Self::Rejected(Rejection::NotInThisCandidate) => "chinwag: not_in_this_candidate\n",
            Self::Rejected(Rejection::InvalidArguments) => "chinwag: invalid_arguments\n",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InitRepository {
    CurrentDirectory,
    Explicit(PathBuf),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InitPrincipal {
    Explicit(String),
    FromLocalConfig,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InitRequest {
    pub(crate) repo: InitRepository,
    pub(crate) private_leaf: Option<PathBuf>,
    pub(crate) principal: InitPrincipal,
    pub(crate) reuse: Option<[u8; 32]>,
    pub(crate) editor: Option<EditorSelection>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Dispatch {
    Immediate(Exit),
    Init(InitRequest),
    Serve(ServeRequest),
    ServeHttp(ServeRequest),
    Configure(ConfigureRequest),
    AgentDispatch(AgentDispatchRequest),
    Memory(MemoryRequest),
}

#[derive(Debug, PartialEq, Eq)]
pub struct AgentDispatchRequest {
    pub(crate) agent: Option<String>,
    pub(crate) item: Option<String>,
    pub(crate) sender: Option<String>,
    pub(crate) body: Option<String>,
    pub(crate) crdb: Option<PathBuf>,
    pub(crate) stdin_json: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MemoryAction {
    Retain {
        id: Option<String>,
        bank: String,
        context: String,
        content: String,
        commit: Option<String>,
        file_scope: Option<String>,
        agent: Option<String>,
        tags: Option<String>,
    },
    Recall {
        query: String,
        limit: usize,
        bank: Option<String>,
        file_scope: Option<String>,
    },
    Tombstone {
        id: String,
        file_scope: String,
        reason: String,
        commit: Option<String>,
        attempted_action: Option<String>,
        failure: Option<String>,
        alternative: Option<String>,
    },
    Stats {
        bank: Option<String>,
    },
    MigrateHindsight {
        url: Option<String>,
        bank: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct MemoryRequest {
    pub(crate) action: MemoryAction,
    pub(crate) crdb: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServeRequest {
    pub(crate) repo: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EditorSelection {
    ClaudeCode,
    Cursor,
    Codex,
}
#[cfg(target_os = "macos")]
impl EditorSelection {
    pub(crate) fn into_editor(self) -> chinwag_editor_config_private::Editor {
        match self {
            Self::ClaudeCode => chinwag_editor_config_private::Editor::ClaudeCode,
            Self::Cursor => chinwag_editor_config_private::Editor::Cursor,
            Self::Codex => chinwag_editor_config_private::Editor::Codex,
        }
    }
}
fn editor_selection(value: &str) -> Option<EditorSelection> {
    match value {
        "claude-code" => Some(EditorSelection::ClaudeCode),
        "cursor" => Some(EditorSelection::Cursor),
        "codex" => Some(EditorSelection::Codex),
        _ => None,
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigureRequest {
    repo: PathBuf,
    editor: EditorSelection,
}
impl Invocation {
    fn configure_help(self) -> &'static str {
        match self {
            Self::GitChinwag => {
                "Usage: git chinwag configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nConfigure one editor for this initialized repository.\n"
            }
            Self::GitEmun => {
                "Usage: git emun configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nConfigure one editor for this initialized repository.\n"
            }
            Self::GhChinwag => {
                "Usage: gh chinwag configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nConfigure one editor for this initialized repository.\n"
            }
            Self::GhEmun => {
                "Usage: gh emun configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nConfigure one editor for this initialized repository.\n"
            }
            Self::Chinwag => {
                "Usage: chinwag configure-editor --repo <absolute-path> --editor <claude-code|cursor|codex>\n\nConfigure one editor for this initialized repository.\n"
            }
        }
    }
}

impl Invocation {
    fn serve_help(self) -> &'static str {
        match self {
            Self::Chinwag => {
                "Usage: chinwag mcp-serve --repo <absolute-path> [--transport stdio|http]\n\nServe this initialized repository context over MCP stdio by default.\nHTTP reads exactly 32 secret bytes and EOF from piped stdin, binds a fresh IPv4 loopback port,\nand prints a token-free endpoint receipt. Send the lowercase hex secret as a Bearer header.\nCtrl-C stops the original listener and checks its worker before success.\n"
            }
            Self::GitChinwag => {
                "Usage: git chinwag mcp-serve --repo <absolute-path> [--transport stdio|http]\n\nServe this initialized repository context over MCP stdio by default.\nHTTP reads exactly 32 secret bytes and EOF from piped stdin, binds a fresh IPv4 loopback port,\nand prints a token-free endpoint receipt. Send the lowercase hex secret as a Bearer header.\nCtrl-C stops the original listener and checks its worker before success.\n"
            }
            Self::GitEmun => {
                "Usage: git emun mcp-serve --repo <absolute-path> [--transport stdio|http]\n\nServe this initialized repository context over MCP stdio by default.\nHTTP reads exactly 32 secret bytes and EOF from piped stdin, binds a fresh IPv4 loopback port,\nand prints a token-free endpoint receipt. Send the lowercase hex secret as a Bearer header.\nCtrl-C stops the original listener and checks its worker before success.\n"
            }
            Self::GhChinwag => {
                "Usage: gh chinwag mcp-serve --repo <absolute-path> [--transport stdio|http]\n\nServe this initialized repository context over MCP stdio by default.\nHTTP reads exactly 32 secret bytes and EOF from piped stdin, binds a fresh IPv4 loopback port,\nand prints a token-free endpoint receipt. Send the lowercase hex secret as a Bearer header.\nCtrl-C stops the original listener and checks its worker before success.\n"
            }
            Self::GhEmun => {
                "Usage: gh emun mcp-serve --repo <absolute-path> [--transport stdio|http]\n\nServe this initialized repository context over MCP stdio by default.\nHTTP reads exactly 32 secret bytes and EOF from piped stdin, binds a fresh IPv4 loopback port,\nand prints a token-free endpoint receipt. Send the lowercase hex secret as a Bearer header.\nCtrl-C stops the original listener and checks its worker before success.\n"
            }
        }
    }
}

impl Invocation {
    fn init_help(self) -> &'static str {
        match self {
            Self::Chinwag => {
                "Usage: chinwag init [--principal <email>] [--repo <absolute-path>] [--private-dir <absolute-path>] [--editor <claude-code|cursor|codex>]\n\nInitialize local Git SSH signing and an offline store in <repo>/.chinwag.\nRun from the repository root or pass --repo. Without --principal, use exactly one\nrepo-local user.email. Global and included identity profiles are unavailable.\n--private-dir defaults to\n<repo>/.chinwag and must name that directory. --editor configures one editor after local\ninitialization, with the original live identity retained. Existing identities cannot be reused\n(--reuse-public is unavailable). Hosted registration is not available.\n"
            }
            Self::GitChinwag => {
                "Usage: git chinwag init [--principal <email>] [--repo <absolute-path>] [--private-dir <absolute-path>] [--editor <claude-code|cursor|codex>]\n\nInitialize local Git SSH signing and an offline store in <repo>/.chinwag.\nRun from the repository root or pass --repo. Without --principal, use exactly one\nrepo-local user.email. Global and included identity profiles are unavailable.\n--private-dir defaults to\n<repo>/.chinwag and must name that directory. --editor configures one editor after local\ninitialization, with the original live identity retained. Existing identities cannot be reused\n(--reuse-public is unavailable). Hosted registration is not available.\n"
            }
            Self::GitEmun => {
                "Usage: git emun init [--principal <email>] [--repo <absolute-path>] [--private-dir <absolute-path>] [--editor <claude-code|cursor|codex>]\n\nInitialize local Git SSH signing and an offline store in <repo>/.chinwag.\nRun from the repository root or pass --repo. Without --principal, use exactly one\nrepo-local user.email. Global and included identity profiles are unavailable.\n--private-dir defaults to\n<repo>/.chinwag and must name that directory. --editor configures one editor after local\ninitialization, with the original live identity retained. Existing identities cannot be reused\n(--reuse-public is unavailable). Hosted registration is not available.\n"
            }
            Self::GhChinwag => {
                "Usage: gh chinwag init [--principal <email>] [--repo <absolute-path>] [--private-dir <absolute-path>] [--editor <claude-code|cursor|codex>]\n\nInitialize local Git SSH signing and an offline store in <repo>/.chinwag.\nRun from the repository root or pass --repo. Without --principal, use exactly one\nrepo-local user.email. Global and included identity profiles are unavailable.\n--private-dir defaults to\n<repo>/.chinwag and must name that directory. --editor configures one editor after local\ninitialization, with the original live identity retained. Existing identities cannot be reused\n(--reuse-public is unavailable). Hosted registration is not available.\n"
            }
            Self::GhEmun => {
                "Usage: gh emun init [--principal <email>] [--repo <absolute-path>] [--private-dir <absolute-path>] [--editor <claude-code|cursor|codex>]\n\nInitialize local Git SSH signing and an offline store in <repo>/.chinwag.\nRun from the repository root or pass --repo. Without --principal, use exactly one\nrepo-local user.email. Global and included identity profiles are unavailable.\n--private-dir defaults to\n<repo>/.chinwag and must name that directory. --editor configures one editor after local\ninitialization, with the original live identity retained. Existing identities cannot be reused\n(--reuse-public is unavailable). Hosted registration is not available.\n"
            }
        }
    }
}

pub fn dispatch<I, S>(program: &OsStr, args: I) -> Dispatch
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let Some(invocation) = Invocation::from_program(program) else {
        return Dispatch::Immediate(Exit::Rejected(Rejection::UnknownInvocation));
    };
    let args: Vec<OsString> = args.into_iter().map(|s| s.as_ref().to_owned()).collect();
    if args.first().is_some_and(|arg| arg == "configure-editor") {
        if args.len() == 2 && args[1] == "--help" {
            return Dispatch::Immediate(Exit::ConfigureHelp(invocation));
        }
        return match parse_configure(&args[1..]) {
            Some(request) => Dispatch::Configure(request),
            None => Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments)),
        };
    }
    if args.first().is_some_and(|arg| arg == "mcp-serve") {
        if args.len() == 2 && args[1] == "--help" {
            return Dispatch::Immediate(Exit::ServeHelp(invocation));
        }
        return match parse_serve(&args[1..]) {
            Some((request, false)) => Dispatch::Serve(request),
            Some((request, true)) => Dispatch::ServeHttp(request),
            None => Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments)),
        };
    }
    if args.first().is_some_and(|arg| arg == "init") {
        if args.len() == 2 && args[1] == "--help" {
            return Dispatch::Immediate(Exit::InitHelp(invocation));
        }
        return match parse_init(&args[1..]) {
            Some(request) => Dispatch::Init(request),
            None => Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments)),
        };
    }
    if args.first().is_some_and(|arg| arg == "agent-dispatch") {
        if args.len() == 2 && args[1] == "--help" {
            return Dispatch::Immediate(Exit::AgentDispatchHelp(invocation));
        }
        return match parse_agent_dispatch(&args[1..]) {
            Some(request) => Dispatch::AgentDispatch(request),
            None => Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments)),
        };
    }
    if args.first().is_some_and(|arg| arg == "memory") {
        if args.len() == 1 || (args.len() == 2 && args[1] == "--help") {
            return Dispatch::Immediate(Exit::MemoryHelp(invocation));
        }
        return match parse_memory(&args[1..]) {
            Some(request) => Dispatch::Memory(request),
            None => Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments)),
        };
    }
    let result = match args.as_slice() {
        [] => Exit::Help(invocation),
        [arg] if arg == "--help" => Exit::Help(invocation),
        [arg] if arg == "--version" => Exit::Version,
        _ => Exit::Rejected(Rejection::NotInThisCandidate),
    };
    Dispatch::Immediate(result)
}

fn parse_configure(args: &[OsString]) -> Option<ConfigureRequest> {
    if args.len() != 4 {
        return None;
    }
    let (mut repo, mut editor) = (None, None);
    for pair in args.chunks_exact(2) {
        let flag = pair[0].to_str()?;
        let value = pair[1].to_str()?;
        if value.len() > 4096 || value.contains(['\0', '\r', '\n']) || value.contains("${") {
            return None;
        }
        match flag {
            "--repo" if repo.is_none() => repo = Some(absolute_path(value)?),
            "--editor" if editor.is_none() => editor = Some(editor_selection(value)?),
            _ => return None,
        }
    }
    Some(ConfigureRequest {
        repo: repo?,
        editor: editor?,
    })
}

fn parse_serve(args: &[OsString]) -> Option<(ServeRequest, bool)> {
    if !matches!(args.len(), 2 | 4) {
        return None;
    }
    let (mut repo, mut http) = (None, None);
    for pair in args.chunks_exact(2) {
        match pair[0].to_str()? {
            "--repo" if repo.is_none() => {
                let path = pair[1].to_str()?;
                if path.len() > 4096 || path.contains(['\0', '\r', '\n']) {
                    return None;
                }
                repo = Some(absolute_path(path)?);
            }
            "--transport" if http.is_none() => {
                http = Some(match pair[1].to_str()? {
                    "stdio" => false,
                    "http" => true,
                    _ => return None,
                });
            }
            _ => return None,
        }
    }
    Some((ServeRequest { repo: repo? }, http.unwrap_or(false)))
}

fn parse_init(args: &[OsString]) -> Option<InitRequest> {
    if args.len() > 10 {
        return None;
    }
    let (mut repo, mut private_leaf, mut principal, mut reuse, mut editor) =
        (None, None, None, None, None);
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].to_str()?;
        let (flag, value) = if let Some(pair) = flag.split_once('=') {
            pair
        } else {
            index += 1;
            (flag, args.get(index)?.to_str()?)
        };
        if value.is_empty() || value.contains(['\0', '\r', '\n']) {
            return None;
        }
        match flag {
            "--repo" if repo.is_none() => repo = Some(absolute_path(value)?),
            "--private-dir" if private_leaf.is_none() => private_leaf = Some(absolute_path(value)?),
            "--principal" if principal.is_none() => principal = Some(value.to_owned()),
            "--reuse-public" if reuse.is_none() => reuse = Some(public_pin(value)?),
            "--editor" if editor.is_none() => editor = Some(editor_selection(value)?),
            _ => return None,
        }
        index += 1;
    }
    Some(InitRequest {
        repo: repo.map_or(InitRepository::CurrentDirectory, InitRepository::Explicit),
        private_leaf,
        principal: principal.map_or(InitPrincipal::FromLocalConfig, InitPrincipal::Explicit),
        reuse,
        editor,
    })
}

fn absolute_path(value: &str) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    (path.is_absolute() && !path.components().any(|part| part == Component::ParentDir))
        .then_some(path)
}

fn public_pin(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut pin = [0; 32];
    for (i, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(pin)
}

impl Invocation {
    fn agent_dispatch_help(self) -> &'static str {
        match self {
            Self::Chinwag => {
                "Usage: chinwag agent-dispatch --agent <HANDLE> [--item <ITEM_KEY>] [--sender <SENDER>] --body <BODY> [--crdb <PATH>] [--stdin]\n\nNative Rust multi-engine agent comms & dispatch backed by .chinwag/state.crdb.\n"
            }
            Self::GitChinwag => {
                "Usage: git chinwag agent-dispatch --agent <HANDLE> [--item <ITEM_KEY>] [--sender <SENDER>] --body <BODY> [--crdb <PATH>] [--stdin]\n\nNative Rust multi-engine agent comms & dispatch backed by .chinwag/state.crdb.\n"
            }
            Self::GitEmun => {
                "Usage: git emun agent-dispatch --agent <HANDLE> [--item <ITEM_KEY>] [--sender <SENDER>] --body <BODY> [--crdb <PATH>] [--stdin]\n\nNative Rust multi-engine agent comms & dispatch backed by .chinwag/state.crdb.\n"
            }
            Self::GhChinwag => {
                "Usage: gh chinwag agent-dispatch --agent <HANDLE> [--item <ITEM_KEY>] [--sender <SENDER>] --body <BODY> [--crdb <PATH>] [--stdin]\n\nNative Rust multi-engine agent comms & dispatch backed by .chinwag/state.crdb.\n"
            }
            Self::GhEmun => {
                "Usage: gh emun agent-dispatch --agent <HANDLE> [--item <ITEM_KEY>] [--sender <SENDER>] --body <BODY> [--crdb <PATH>] [--stdin]\n\nNative Rust multi-engine agent comms & dispatch backed by .chinwag/state.crdb.\n"
            }
        }
    }

    fn memory_help(self) -> &'static str {
        let _ = self;
        "Usage: chinwag memory retain --bank <bank> --context <ctx> --content <text> [--commit <sha>] [--file-scope <glob>] [--id <id>]\n       chinwag memory recall --query <q> [--limit <n>] [--bank <bank>] [--file-scope <glob>]\n       chinwag memory tombstone --id <id> --file-scope <glob> --reason <why-killed> [--commit <sha>] [--alternative <alt>]\n       chinwag memory stats [--bank <bank>]\n       chinwag memory migrate-hindsight [--url <url>] [--bank <bank>]\n\nNative Chinwag 3-Tier Memory (Verified Invariants + Negative Architectural Tombstones + Commit-Anchored LEANN CSR Graph in .chinwag/state.crdb).\n"
    }
}

fn parse_agent_dispatch(args: &[OsString]) -> Option<AgentDispatchRequest> {
    let mut agent = None;
    let mut item = None;
    let mut sender = None;
    let mut body = None;
    let mut crdb = None;
    let mut stdin_json = false;
    let mut idx = 0;
    while idx < args.len() {
        let flag = args[idx].to_str()?;
        if flag == "--stdin" || flag == "--stdin-json" {
            stdin_json = true;
            idx += 1;
            continue;
        }
        idx += 1;
        let val = args.get(idx)?.to_str()?.to_owned();
        match flag {
            "--agent" => agent = Some(val),
            "--item" | "--item-key" => item = Some(val),
            "--sender" => sender = Some(val),
            "--body" | "--message" => body = Some(val),
            "--crdb" | "--repo" => crdb = Some(PathBuf::from(val)),
            _ => return None,
        }
        idx += 1;
    }
    if !stdin_json && (agent.is_none() || body.is_none()) {
        return None;
    }
    Some(AgentDispatchRequest {
        agent,
        item,
        sender,
        body,
        crdb,
        stdin_json,
    })
}

fn parse_memory(args: &[OsString]) -> Option<MemoryRequest> {
    let sub = args.first()?.to_str()?;
    let rest = &args[1..];
    let mut id = None;
    let mut bank = None;
    let mut context = None;
    let mut content = None;
    let mut commit = None;
    let mut file_scope = None;
    let mut agent = None;
    let mut tags = None;
    let mut query = None;
    let mut limit: Option<usize> = None;
    let mut reason = None;
    let mut attempted_action = None;
    let mut failure = None;
    let mut alternative = None;
    let mut url = None;
    let mut crdb = None;

    let mut idx = 0;
    while idx < rest.len() {
        let raw_flag = rest[idx].to_str()?;
        let (flag, val) = if let Some((f, v)) = raw_flag.split_once('=') {
            idx += 1;
            (f, v.to_owned())
        } else {
            idx += 1;
            let v = rest.get(idx)?.to_str()?.to_owned();
            idx += 1;
            (raw_flag, v)
        };
        match flag {
            "--id" => id = Some(val),
            "--bank" => bank = Some(val),
            "--context" | "--ctx" | "--category" => context = Some(val),
            "--content" | "--text" | "--body" => content = Some(val),
            "--commit" | "--source-commit" => commit = Some(val),
            "--file-scope" | "--file-path" | "--scope" => file_scope = Some(val),
            "--agent" | "--author" => agent = Some(val),
            "--tags" => tags = Some(val),
            "--query" | "-q" => query = Some(val),
            "--limit" | "-n" => limit = Some(val.parse().ok()?),
            "--reason" | "--why-killed" => reason = Some(val),
            "--attempted-action" | "--action" => attempted_action = Some(val),
            "--failure" => failure = Some(val),
            "--alternative" | "--alt" => alternative = Some(val),
            "--url" => url = Some(val),
            "--crdb" | "--repo" => crdb = Some(PathBuf::from(val)),
            _ => return None,
        }
    }

    let action = match sub {
        "retain" => MemoryAction::Retain {
            id,
            bank: bank.unwrap_or_else(|| "spector-fleet".to_owned()),
            context: context.unwrap_or_else(|| "chinwag-memory".to_owned()),
            content: content?,
            commit,
            file_scope,
            agent,
            tags,
        },
        "recall" => MemoryAction::Recall {
            query: query.unwrap_or_else(|| file_scope.clone().unwrap_or_default()),
            limit: limit.unwrap_or(10),
            bank,
            file_scope,
        },
        "tombstone" => MemoryAction::Tombstone {
            id: id?,
            file_scope: file_scope?,
            reason: reason.or(content)?,
            commit,
            attempted_action,
            failure,
            alternative,
        },
        "stats" => MemoryAction::Stats { bank },
        "migrate-hindsight" => MemoryAction::MigrateHindsight { url, bank },
        _ => return None,
    };

    Some(MemoryRequest { action, crdb })
}

#[cfg(target_os = "macos")]
mod agent_dispatch_run;
#[cfg(target_os = "macos")]
pub use agent_dispatch_run::run_agent_dispatch;
#[cfg(not(target_os = "macos"))]
pub fn run_agent_dispatch(
    _request: AgentDispatchRequest,
    _input: &mut dyn std::io::Read,
    _out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    let _ = err.write_all(b"chinwag: unsupported_os\n");
    2
}

#[cfg(target_os = "macos")]
mod memory_run;
#[cfg(target_os = "macos")]
pub use memory_run::run_memory;
#[cfg(not(target_os = "macos"))]
pub fn run_memory(
    _request: MemoryRequest,
    _out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    let _ = err.write_all(b"chinwag: unsupported_os\n");
    2
}

#[cfg(target_os = "macos")]
mod init_run;
#[cfg(target_os = "macos")]
pub use init_run::run_init;

#[cfg(not(target_os = "macos"))]
pub fn run_init(
    _request: InitRequest,
    _out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    let _ = err.write_all(b"chinwag: unsupported_os\n");
    2
}

#[cfg(target_os = "macos")]
mod serve_run;
#[cfg(target_os = "macos")]
pub use serve_run::run_mcp_stdio;

#[cfg(not(target_os = "macos"))]
pub fn run_mcp_stdio(_request: ServeRequest, err: &mut dyn std::io::Write) -> u8 {
    let _ = err.write_all(b"chinwag: unsupported_os\n");
    2
}

#[cfg(target_os = "macos")]
mod configure_run;
#[cfg(target_os = "macos")]
pub use configure_run::run_configure;
#[cfg(not(target_os = "macos"))]
pub fn run_configure(
    _request: ConfigureRequest,
    _out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    let _ = err.write_all(b"chinwag: unsupported_os\n");
    2
}

#[cfg(target_os = "macos")]
mod http_run;
#[cfg(target_os = "macos")]
pub use http_run::run_mcp_http;
#[cfg(not(target_os = "macos"))]
pub fn run_mcp_http(
    _request: ServeRequest,
    _input: &mut dyn std::io::Read,
    _out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    let _ = writeln!(err, "chinwag: context_http_unsupported_platform");
    1
}
