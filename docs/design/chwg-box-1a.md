# CHWG-BOX-1A — Lease-bound macOS containment
Date: 2026-10-28  
Status: DRAFT  
Author: ARCHITECT

## 1. Decision and evidence boundary

Compile authenticated, live file authority into a deterministic Seatbelt profile.
The trusted host prepares a private APFS CoW workspace and starts a verified
`chinwag-contain-trampoline`; only that helper applies the profile and execs the agent.
The host remains outside containment. No error may fall back to an uncontained launch.
This is a design spike, not an implementation or an enforcement attestation.

**Critical finding:** the supplied checkout does not implement the PRD's described
`git chinwag spawn`, APFS CoW spawn path, or signed `leased_globs` database authority.
Those are implementation prerequisites, not existing integration points to call.
The PRD's `source_commit` and the checkout HEAD both identify
`55b6936d60f6f2acd52b9bd9e95324af4d3b6377`; matching that identifier does not resolve
the discrepancy between prose and code. Working files were inspected read-only;
this is not a claim that every working file equals HEAD or that another run is idle.

**Notation:** VERIFIED means observed in the supplied source or cited platform material.
PROPOSED specifies new behavior. ASSUMPTION labels an unverified prerequisite or
platform behavior. Every new type, path convention, flag, and phase below is PROPOSED,
not a claim that it already exists. No runtime or kernel experiment was performed.

### 1.1 Source map: actual behavior today

All repository-relative paths in this document are under
`/Users/brianspector/WORKSPACE/chinwag`; links identify the files actually inspected.

| Evidence | Verified symbol and implication |
|---|---|
| [Workspace manifest](/Users/brianspector/WORKSPACE/chinwag/Cargo.toml:1) | Twelve member crates; no containment or CoW crate. Workspace version is `0.0.1`, not proof of a published release version. |
| [CLI dispatch](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-cli/src/lib.rs:307) | `dispatch`, `Dispatch`, `Invocation::GitChinwag`: init, MCP serving, editor configuration, agent dispatch and memory; no Spawn variant. Unrecognized commands return `Rejection::NotInThisCandidate`, exit 2. Reading help strings did not execute the binary. |
| [Claim contract](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-claim/src/lib.rs:144) | `ClaimRequestUnsigned.files: Vec<String>`; actor, session, nonce, expected_revision, issued, expiry. `ClaimReceiptUnsigned` carries files, revision, request digest and coordinator. There is no `leased_globs` field. |
| [Claim policy](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-claim/src/lib.rs:112) | `ClaimPolicy::authorize` uses exact set membership. Module documentation explicitly leaves atomic exclusivity to a future store. A signed historical receipt alone is not current authority. |
| [Path validation](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-claim/src/lib.rs:569) | `validate_one_path`, `validate_files`: at most 32 sorted, unique ASCII paths, each at most 160 bytes; no absolute path, whitespace/control, backslash, colon, empty/dot/parent component. Any component equal ignoring ASCII case to `.git`, `.chinwag`, `.grok`, `.codex` is refused. |
| [Live lease](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-swarm/src/room/claim_slot/lease.rs:21) | Private `ActiveLease` has actor, session, issued, expiry and monotonic deadline. `WriteWitness::validate` checks the current attached session and both clocks against one exact `CLAIM_FILE`. |
| [Claim owner](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-swarm/src/room/claim_slot.rs:86) | `ClaimService` owns `Option<ActiveLease>` in memory. `authorize_local_write` lends a witness. `CLAIM_FILE` is `crates/chinwag-seed/src/main.rs`; activation checks PR-01, revision 1 and a 1–60 second span. Shutdown clears the lease. |
| [Write capability](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-seed/src/write_gate.rs:12) | Opaque `WritePermit` wraps the live witness; `decide_write(ClaimTaskReport)` always denies. `EditRuntime::write_file` in `edit_mcp.rs` uses that witness-backed path. |
| [File boundary](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-seed/src/workspace.rs:53) | `Workspace::open`, `parent`, `replace_if`: anchored directory descriptors, NOFOLLOW traversal, protected components, preimage checks; `regular` rejects nonregular files and link count other than one. These checks do not confine arbitrary shell commands. |
| [Database schema](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-snapshot-session/src/schema.rs:48) | `TABLES`: `agent_claims` has file_path, owner_key_id, authority_event_hash; `leases` has claim_id, owner_key_id, authority_event_hash and observed expiry. Comments say replicated observations never mint grants. No leased_globs, authenticated lease payload, or active-grant query is defined. |
| [Snapshot ownership](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-snapshot-read-owner/src/lib.rs:74) | `ReadOwner::acquire_existing_private_fixture` creates an exclusive lock marker even for a read. `SnapshotSession::from_owner`, `tombstones`, `verified_invariants`, `finish` validate a held image; there is no public active-lease query. None of these APIs was invoked during this spike. |
| [MCP boundary](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-mcp/src/owner.rs:130) | `read_session` combines ReadOwner and SnapshotSession. The inspected context server is not the PRD's future Unix socket spawn broker. |
| [Child spawn](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-host-process/src/owned_spawn.rs:190) | `spawn_at(program, args, env, directory, SpawnStdio)` uses child-only fchdir, explicit env and POSIX_SPAWN_CLOEXEC_DEFAULT; currently inherits only stdio. `OwnedChild` retains exact wait ownership and quarantines unknown results. It creates no worktree and applies no sandbox. |
| [Git admission](/Users/brianspector/WORKSPACE/chinwag/crates/chinwag-signing/src/repo.rs:333) | Existing signing admission refuses `commondir` and `config.worktree`. `RepositoryAdmission::open` in snapshot-read-owner anchors a `.git` directory. Linked-worktree support must be a new, separately reviewed admission path. |

### 1.2 What was not found

Source/manifests searched under `crates/` contain no `clonefile`, `clonefileat`,
`fclonefileat`, `sandbox_init`, `sandbox-exec`, `globset`, `glob::`, or `leased_globs`.
The tracked spawn/lease filenames identify owned_spawn and the process-local lease,
not a CLI CoW implementation. No `.github/` or `scripts/` signing workflow exists
in this checkout; the two `SIGNING_TEST_*` pins were not found in inspected source.
README claims about globs and leases are broader than these implementation contracts.

**ASSUMPTION A1:** a deployed CLI or another checkout may implement CLI-13 differently.
RUST must obtain its source path and commit from Gemini-PM before claiming reuse.
There is consequently no verified current APFS worktree location to report here.
Do not probe an installed binary, production database, keys, or pristine runs to fill this gap.

## 2. Authority, workspace and lease-to-SBPL compilation

### 2.1 Authority admission before any profile exists

Add a host-owned `LeaseAdmission` adapter that returns an opaque `AdmittedLease`.
It must verify actor/coordinator signatures, repository identity, current session,
claim identity, complete path scope, accepted revision, expiry and monotonic deadline.
Read `.chinwag/state.crdb` through its ownership discipline, but treat lease rows as
observations that must bind to verified authority events; a SQL SELECT is insufficient.
Never manufacture authority by serializing a `WriteWitness`, report, or ReadReceipt.
The existing witness can support an exact-file development adapter inside its owner;
it cannot be rebuilt from the DB or silently generalized to arbitrary agents.

New product authority storage must define atomic overlap checks, renewal CAS, revocation,
replay handling and stale replica behavior before a DB-backed contained spawn ships.
The module-level future-store requirements in `chinwag-claim` are the starting contract.
`verified_invariants` rows likewise require their own evidence validation; a row name
does not prove CI or authorize new read/write scope. Policy may narrow a grant only.

The launch snapshot binds actor, session, claim/revision, source commit, authority-event
digest, policy digest, workspace identity, compiler version and minimum expiry.
Recheck the live authority immediately before spawning the helper; abort on any change.
Never refresh by silently widening a running process's lease or by reading its copied DB.

### 2.2 APFS CoW workspace: a new prerequisite

**PROPOSED path convention**, not a discovered implementation:
`<canonical host TMPDIR>/chinwag-box-<128-bit-random>/{worktree,tmp,control}`.
Call these run root R, worktree W, private scratch T, protected host state C.
R is created exclusively mode 0700 by the host; host directory descriptors bind its
device/inode identity. Resolve `/var` and `/tmp` aliases to `/private/...` first.
Never grant the caller's entire TMPDIR, `/private/tmp`, R, or a parent of W/T.
The runtime TMPDIR is T, not the host TMPDIR used to choose R's location.

Prepare W using descriptor-based traversal of admitted source content and APFS
`clonefileat`/equivalent CoW copies of regular files, with source/destination identity
checks and symlinks inspected without traversal. APFS clones share blocks, not writable
inode identities; hard links are not a CoW substitute. Require the supported APFS mode
for the first release; a future full-copy fallback must be explicit and equivalently tested.
Do not recursively clone live `.chinwag`, credential files, sockets, devices or all of `.git`.
Copy a host-chosen source snapshot and verify it; concurrent source edits must not yield
a mixed, unaudited baseline. Record whether uncommitted source edits are included.

Create required directory parents before containment. Reject source mount crossings,
multiply-linked writable files and symlinked grant ancestors. Host-created parents are
not themselves leased. The sandbox must not remove/replace W, T or their pinned ancestors.
T also contains an empty private HOME, caches and build outputs; choose CARGO_TARGET_DIR
inside T. HOME inside T is private per run, not a promise of isolation between its tools.

### 2.3 Git directory and linked-worktree handling

Default v0.1.2 uses a standalone CoW working copy with a host-prepared private `.git`
directory, not `git worktree add` against the source common directory. Populate only
needed objects/refs and sanitized config; no secrets, hooks, credentials or object alternates.
Host Git operations disable global/system config, include files, hooks and external helpers.
Git-object contents can themselves contain historical secrets; repository admission must
approve the readable history. CoW must not hard-link loose objects or mutable metadata.

If CLI-13 requires a linked worktree, resolve W/.git's `gitdir:` relative to W; then resolve
gitdir/commondir relative to gitdir. Canonicalize and hold all identities, refuse cycles,
unexpected layouts, escaping indirections and object alternates. No agent write grant
may cover either the worktree gitdir or common gitdir. Shared .git/worktrees registration
and cleanup remain host operations. This new mode waits for v0.2.0 admission tests.

In either mode the agent gets only the selected Git metadata read surface; `.git/hooks`
and config/credential material are denied. In v0.1.2, ordinary `git status`/diff may be
supported with optional locks disabled; add/commit/checkout are host-mediated operations.
Do not grant `.git/index.lock`, objects, refs or hooks just to make Git commands pass.
Host-mediated Git validates the final diff against current authority and protected paths;
the host must never execute contained hooks or trust agent-selected config.

### 2.4 Exact syntax: current paths and a versioned future glob language

VERIFIED: current claims compare complete path strings, without glob expansion.
The validator does not reject `*`, `?` or brackets; they are still literal characters
under `ClaimPolicy::authorize`. Never reinterpret an existing signed string as a glob.
Existing v1 receipts compile only to `Exact` selectors, subject to safety admission.
Ambiguous metacharacter-bearing legacy paths are refused for contained spawn v0.1.2.

PROPOSED signed scope version `lease-paths/v2` distinguishes `Exact(path)`,
`Tree(directory)` and `Glob(pattern)`. Changing representation requires a new signature
domain and coordinator enforcement using the same matcher. No caller-chosen SBPL/regex.
v0.1.2 supports Exact only; Tree can join that release only with authenticated v2 authority.
General Glob is v0.2.0 and must not be advertised before the semantic tests pass.

| Selector | Exact target meaning | SBPL selector |
|---|---|---|
| `Exact("src/lib.rs")` | One nondirectory path, existing or a missing final leaf with existing parent | `(literal "W/src/lib.rs")`; no descendants or sibling write grant |
| `Tree("src")`, display `src/**` | Existing directory and its descendants, with the directory root's identity pinned | `(subpath "W/src")`, then deny create/unlink on literal root |
| `Glob("src/*.rs")` | Exactly one component after src; `*` matches zero or more non-slash characters, final component nonempty | anchored regex over W; see compiler rules below |
| `Glob("src/?.rs")` | Exactly one non-slash ASCII byte before `.rs` | anchored regex containing `[^/]` |
| `Glob("src/**/test_*.rs")` | Zero or more complete intermediate components | anchored regex containing `([^/]+/)*` |
| `Glob("src/**")` | Explicit tree shorthand | Normalize to Tree, with the same pinned root and protected subtraction |

Version 2 starts with the current ASCII/length/component restrictions; no braces,
classes, extglobs, negation, backslash escapes, `~`, `$VAR`, absolute paths or `..`.
`**` is legal only as a whole component. A glob never matches an empty component;
dotfiles have ordinary matching semantics, followed by the mandatory secret exclusion.
Final `**` is accepted only after a fully literal existing-directory prefix, as Tree;
other recursive globs require an intermediate `**/` followed by a final file component.
No implicit directory-recursion for `src/`, `src/*`, `src`, or a literal directory.
Reject bare `**`, root Tree and scopes with no fixed directory prefix in v0.2.0.

Compile an AST, not string substitutions on untrusted profile text:
1. Validate and bind the canonical fixed prefix inside W using held directory handles.
2. Escape every regex metacharacter in literal spans, including the entire W prefix.
3. Emit `*` as `[^/]*`, except a component made solely of `*` emits `[^/]+`;
   emit `?` as `[^/]` and intermediate `**/` as `([^/]+/)*`.
4. Anchor both ends with `^` and `$`; enforce nonempty components in both matchers.
5. Example: `src/*.rs` becomes `^<escaped-W>/src/[^/]*[.]rs$`.
6. Encode that regex as a Scheme string using a separate serializer; regex escaping
   and string escaping are distinct. No raw interpolation, imports or parameters.
7. Reject unsupported characters or an expression that the tested Seatbelt dialect
   cannot represent exactly. Do not widen to a directory when regex validation fails.

**ASSUMPTION A2:** this SBPL regex subset and exact pathname behavior hold across the
chosen OS matrix. Golden text is insufficient; differential kernel tests gate Glob.
Do not expand globs by enumerating only current files: that loses newly created matches.
Glob authority also needs atomic overlap detection; textual-prefix comparison is unsound.

### 2.5 Canonicalization, aliases and protected namespace

Resolve existing W, T, executable/runtime trees, gitdir and fixed grant ancestors with
realpath plus no-follow descriptor traversal; record device/inode identities and original
spellings. Canonicalization is validation, never permission to follow a symlink outside W.
For a new exact file, canonicalize/hold its existing parent and append the validated leaf.
For glob suffixes, anchor at the existing canonical fixed prefix; do not realpath wildcards.
Revalidate identities before apply. Refuse unrepresentable/non-UTF-8 host paths in v0.1.2.

Default APFS commonly folds case; ASCII-only claims do not make filesystem case aliases
safe. Refuse colliding spellings, compare existing names against volume behavior, and
deny protected ASCII names with explicit case-folded patterns. Qualify both case-sensitive
and case-insensitive APFS. Unicode normalization/case behavior beyond this subset is
**ASSUMPTION A3**, excluded until tested; never silently normalize a signed path string.

Subtract the following from every writable selector, including broad trees/globs:
any `.git`, `.chinwag`, `.grok`, `.codex` component; any `TOMBSTONES.md` component;
all host-selected active policy files and their containing control directory C.
Protect W/.git itself whether directory or indirection file, and external gitdir/common
gitdir by canonical paths. Protect each granted tree root and its ancestors against
rename/remove/replacement. Do not rely solely on a last deny overriding an allow:
render positive grants with `require-all`/`require-not` exclusions as well as explicit
deny rules, and regression-test the ordering on each OS. No later permissive overrides.

Deny secret file reads/writes for any `.env` or `.env.*` component (case-folded),
`.chinwag`, `.ssh`, `.aws`, `.gnupg`, agent credential stores and operator home by
default absence of grants. Do not grant broad `/Users`, `/Library`, home or keychain access.
`.env.example` is denied too unless a future explicit, reviewed public-fixture policy exists.
A readable file can contain a secret under any name: path filtering is not secret detection.

### 2.6 Deny-default runtime and operation policy

Start `(version 1)` and `(deny default)`. Add only reviewed read grants for selected
macOS runtime paths: `/System/Library`, canonical `/usr/lib`, selected system tools,
and the exact canonical Homebrew Cellar package versions the harness/toolchain needs.
Do not grant the whole Cellar by default. Resolve `/opt/homebrew/bin` symlinks to those
versions; toolchain updates require a new runtime manifest, never broadening on error.
Executable scripts also require their interpreter and install-tree reads to be declared.

Read the admitted W excluding secret/control paths; source checkout reads stay denied.
Add ancestor metadata literals only, not ancestor data subpaths. Include literal runtime
configuration files only after review. T has read/write authority; `/dev/null` may get
the explicit read/write device exception. Inherited stdout/stderr pipes are intentional
output channels. An interactive TTY needs a separate tested capability, not `/dev/**`.
Keep lease writes, scratch writes and device exceptions distinct in the launch receipt.

`file-write*` is permitted only under the effective leased selector or T; it does not
implicitly grant reads, execution, networking or arbitrary parent-directory mutation.
Exact-file atomic-save siblings remain denied: use host-mediated `replace_if` or a
separately leased staging path. Never grant the parent directory for editor convenience.
If literal create/unlink requires broader parent rights on an OS, refuse that mode until
an equally narrow solution passes; in-place edits of an existing exact file can ship first.

Allow `process-fork` and explicit executable literals/runtime mapping as needed.
Leaf builds additionally map/execute outputs in declared T build directories; executing
untrusted generated code is permitted functionality with the same filesystem boundary.
Runtime syscall, sysctl and Mach rules are a versioned, tested manifest, not an `allow default`.
**ASSUMPTION A4:** the precise minimal runtime/Mach rules vary by harness and macOS;
no complete real harness bootstrap has been validated in this spike.

Agent mode may connect only to the single host-created broker Unix socket, e.g.
`C/run/chinwag-box.sock`; grant its literal network-outbound endpoint, not C file reads.
Leaf mode has no broker socket grant and no network grants. Unrelated Mach lookups,
Apple Events, debug/task ports and outbound network remain denied by default.
The broker enforces per-run authority on every request; it cannot be an unrestricted
filesystem/shell proxy. BOX-1B supplies future model egress; BOX-1A alone is offline.

### 2.7 Worked example: lease input to generated `.sb` text

This synthetic example exercises PROPOSED v2 Tree, not the existing exact-file receipt.
Admitted input: actor A, session S, claim C1/revision 7, unexpired verified authority;
`Tree("crates/chinwag-mcp")`, displayed as `crates/chinwag-mcp/**`.
W=`/private/tmp/chwg-example/worktree`, T=`/private/tmp/chwg-example/tmp`.
Selected active policy is W/POLICY.md; .git is a private host-prepared directory.
The executable is `/bin/cat`; this is an offline leaf fixture, not an agent harness.
`/private/tmp/chwg-example` is an illustrative exclusive run root, not a location touched.

The generated text below is the candidate complete macOS 26 profile for this fixture;
runtime needs beyond these rules are **ASSUMPTION A4**, to be resolved by kernel CI.
The forbidden-component expression matches mixed ASCII case and component boundaries.
It protects future nested control names too, rather than enumerating existing files.

```scheme
(version 1)
(deny default)
(deny process-info*)
(allow process-info* (target self))
(allow process-fork)
(allow process-exec (literal "/bin/cat"))
(allow file-map-executable (literal "/bin/cat")
  (subpath "/System/Library") (subpath "/usr/lib"))
(allow file-read* (literal "/bin/cat")
  (subpath "/System/Library") (subpath "/usr/lib"))
(allow file-read-metadata
  (literal "/") (literal "/private") (literal "/private/tmp")
  (literal "/private/tmp/chwg-example"))
(allow file-read*
  (require-all
    (subpath "/private/tmp/chwg-example/worktree")
    (require-not
      (regex #"^/private/tmp/chwg-example/worktree/(.*/)?([.]([Gg][Ii][Tt]|[Cc][Hh][Ii][Nn][Ww][Aa][Gg]|[Ss][Ss][Hh]|[Aa][Ww][Ss]|[Gg][Nn][Uu][Pp][Gg]|[Cc][Oo][Dd][Ee][Xx]|[Gg][Rr][Oo][Kk])|[.][Ee][Nn][Vv]([.][^/]*)?)(/|$)"))))
(allow file-write*
  (require-all
    (subpath "/private/tmp/chwg-example/worktree/crates/chinwag-mcp")
    (require-not
      (regex #"^/private/tmp/chwg-example/worktree/(.*/)?([.]([Gg][Ii][Tt]|[Cc][Hh][Ii][Nn][Ww][Aa][Gg]|[Gg][Rr][Oo][Kk]|[Cc][Oo][Dd][Ee][Xx]|[Ss][Ss][Hh]|[Aa][Ww][Ss]|[Gg][Nn][Uu][Pp][Gg])|[Tt][Oo][Mm][Bb][Ss][Tt][Oo][Nn][Ee][Ss][.][Mm][Dd]|[.][Ee][Nn][Vv]([.][^/]*)?)(/|$)"))
    (require-not (literal "/private/tmp/chwg-example/worktree/POLICY.md"))))
(allow file-read* file-write* (subpath "/private/tmp/chwg-example/tmp"))
(allow file-read* file-write* (literal "/dev/null"))
(deny file-write*
  (subpath "/private/tmp/chwg-example/control")
  (subpath "/private/tmp/chwg-example/worktree/.git")
  (subpath "/private/tmp/chwg-example/worktree/.chinwag")
  (literal "/private/tmp/chwg-example/worktree/TOMBSTONES.md")
  (literal "/private/tmp/chwg-example/worktree/POLICY.md")
  (regex #"^/private/tmp/chwg-example/worktree/(.*/)?([.]([Gg][Ii][Tt]|[Cc][Hh][Ii][Nn][Ww][Aa][Gg]|[Gg][Rr][Oo][Kk]|[Cc][Oo][Dd][Ee][Xx]|[Ss][Ss][Hh]|[Aa][Ww][Ss]|[Gg][Nn][Uu][Pp][Gg])|[Tt][Oo][Mm][Bb][Ss][Tt][Oo][Nn][Ee][Ss][.][Mm][Dd]|[.][Ee][Nn][Vv]([.][^/]*)?)(/|$)"))
(deny file-write-create file-write-unlink
  (literal "/private/tmp/chwg-example")
  (literal "/private/tmp/chwg-example/worktree")
  (literal "/private/tmp/chwg-example/worktree/crates")
  (literal "/private/tmp/chwg-example/worktree/crates/chinwag-mcp")
  (literal "/private/tmp/chwg-example/tmp"))
(deny file-link file-mknod file-mount file-mount-update file-unmount file-chroot)
(deny fs-snapshot-create fs-snapshot-delete fs-snapshot-mount fs-snapshot-revert)
(deny file-graft file-ungraft)
```

Expected: read ordinary W source; mutate/create descendants of the leased crate;
deny writes to W/README.md and sibling crates; deny all access to W/.chinwag/state.crdb;
deny nested control-plane and .env writes even inside the leased crate; allow T scratch.
Reading an existing benign file in that crate with `/bin/cat` is the startup fixture.
This fixture intentionally has no Git reads; product Git support adds only its declared
safe metadata grants. The final two graft operation names are macOS 26-specific and
must be omitted on a qualified older OS that does not define them.
For today's authenticated exact claim, replace the crate subpath write selector with
`(literal "/private/tmp/chwg-example/worktree/crates/chinwag-seed/src/main.rs")`;
remove the now-unused leased-directory root pin, retaining W/T/ancestor protections.
No subpath permission is inferred from that exact file.

## 3. Launcher contract and host verification

### 3.1 Choose `sandbox_init` inside the helper

Use `sandbox_init(profile_c_string, 0, &error)` followed by `execve`, never in the host.
The zero flag for custom SBPL is an explicitly unsupported usage to qualify in CI:
the installed SDK header documents only SANDBOX_NAMED, marks sandbox_init and
sandbox_free_error deprecated, and says other flags are reserved.
The C symbol is declared, but custom-profile behavior is private/undocumented-ish SPI;
this choice does not turn it into a supported Apple API.

`sandbox-exec -f` is also deprecated, as the installed manual explicitly states.
It adds another executable, profile pathname reopen and less controlled failure reporting.
The small helper gives one auditable apply→exec transition, digest-bound profile bytes,
explicit descriptors and machine-readable setup outcomes. Do not auto-switch mechanisms.
If Apple removes support or a tested profile stops compiling, refuse contained spawn.
Apple DTS confirms that custom SBPL is undocumented for third-party use:
[Apple's sandbox support explanation](https://developer.apple.com/forums/thread/661939).

### 3.2 Private ABI v1: argv, descriptors and environment

```text
chinwag-contain-trampoline --abi 1 --profile-fd 3 --profile-sha256 <hex64>
  --launch-fd 4 --launch-sha256 <hex64> --status-fd 5 --exec /absolute/program
```

Host-only interface: reject missing, duplicate, unknown flags, fd aliasing, fds 0–2,
invalid lowercase digests and relative executable paths. No shell command string,
PATH search, user-supplied profile file, stdin profile or `--no-sandbox` option.
The launch record carries a bounded argv byte-vector including argv[0], sanitized
target environment, mode, run/lease digests and admitted directory identities.
Encode Unix bytes explicitly rather than lossy UTF-8; path restrictions remain stricter.
`--exec` must equal launch-record argv[0]. Application arguments are never CLI/log output.

FD 3: read-only, unlinked regular file containing exact SBPL bytes, maximum 256 KiB.
FD 4: same transport for canonical versioned launch record, maximum 128 KiB.
Host writes, closes all writable handles, reopens read-only, unlinks and passes those
descriptors; the helper checks read-only access mode, offset zero, regular-file type,
exact length and EOF.
These are immutable-by-contract host snapshots, not a claim of Linux-style memfd seals.
The helper copies bounded bytes to memory, hashes before parsing and rejects NUL SBPL.
FD 5: dedicated setup-status pipe, write end CLOEXEC after trampoline startup.
FDs 0–2: explicitly supplied streams. Cwd is the admitted W established by child fchdir.
No source-directory, key, database, broker, listener or other ambient FD is inherited.

Extend `owned_spawn::spawn_at` with a separate typed `spawn_contained_at` API supporting
only the three setup descriptors; keep its existing callers' inheritance policy unchanged.
Keep POSIX_SPAWN_CLOEXEC_DEFAULT, duplicate sources before choosing child fd numbers,
and prove no collisions with stdio/cwd actions. Do not use unsafe post-fork Rust hooks
in a multithreaded host. The helper is single-threaded and loads no third-party plugins.

Start the helper with an empty ambient environment; it reads target env only from FD 4.
Host builds that env from scratch: fixed PATH, private HOME/TMPDIR/XDG paths, locale,
run label and declared toolchain settings. No inherited provider keys, SSH_AUTH_SOCK,
DYLD_*, shell startup variables, Git overrides, loader/plugin search paths or arbitrary
operator variables. Clear Git config inheritance explicitly. No dotenv loading.
BOX-1A does not mint phantom tokens: authenticated provider operation waits for BOX-1B
or an independently approved host service. Never pass real credentials for convenience.

### 3.3 Helper order, one-way transition and failures

1. Validate ABI/FD identities, close ambient descriptors and bound all reads/allocations.
2. Hash/parse both records; cross-check executable, cwd, run identity and profile digest.
3. Revalidate held cwd/root identities; reject unexpected executable type or indirection.
4. Prepare argv/env and all required memory before apply; close FDs 3/4 and other inputs.
5. Call sandbox_init exactly once. Free its error buffer with sandbox_free_error.
6. On failure, send a fixed setup category and `_exit`; never execute the target.
7. On success, write a bounded APPLIED record containing profile digest to FD 5.
8. `execve` the absolute target with the explicit environment in the same process.
   On exec failure send EXEC_FAILED/errno category and exit; no retry shell or helper.

There is no unsandbox, detach, reset or relaxation operation. Children inherit the applied
boundary across fork/exec. Reapplying/nesting is not a portable mechanism for revocation.
No background task or callback is permitted between apply and exec.
The host owns timeout/wait state using `OwnedChild`; unknown child status is quarantined.
Profile application success and status-pipe EOF are not proof that application startup
succeeded: target exit/signal, helper setup records and an optional application handshake
are separate outcomes. A crash after APPLIED can close the pipe before exec succeeds.

| Exit/status | Meaning |
|---|---|
| 64 + INVOCATION | Invalid ABI, flag, descriptor or record shape |
| 65 + INTEGRITY | Digest, identity or admitted-policy mismatch |
| 69 + UNSUPPORTED | Unsupported OS, missing sandbox symbol or unsupported profile dialect |
| 70 + APPLY_FAILED | Kernel/profile apply failed; target never ran |
| 71 + SETUP_FAILED | Setup I/O, bounds or status channel failure |
| 126 + EXEC_FAILED | Sandbox applied; executable could not be executed |
| 127 + EXEC_NOT_FOUND | Sandbox applied; target unavailable |
| Target code/signal | After successful exec, preserve exact wait result, even if code overlaps above |

Interpret codes together with setup records; target exit 70 is not automatically apply failure.
Parent-side helper verification refusal creates no child. Logs contain categories/digests,
never argv, env values, raw profile parse errors, credentials or source file contents.

### 3.4 Verify SHA-256 and Developer ID before execution

Resolve only the packaged helper adjacent to the verified host installation, never PATH
or repository configuration. Open no-follow, require regular file/link count one, validate
ownership/mode and hold its identity. Hash exact bytes against a host-embedded release
manifest covered by the host's own verified signature, binding host/helper versions,
ABI, architecture and source revision. A self-reported hash
or adjacent writable checksum file is not trusted provenance.

For Darwin's pathname exec, materialize those opened bytes into an exclusive private
host-controlled launch image, close writer, set nonwritable executable mode, reopen/hash,
and validate its signature through Security.framework static-code validation.
Require the release's pinned Team ID, helper signing identifier and Developer ID anchor,
correct architecture, hardened runtime and no get-task-allow/dangerous entitlements.
Do not accept any valid signer, ad-hoc signing or merely a codesign text string.
Signature validation must cover the copied executable's actual bytes and nested integrity
where applicable. Hold/recheck directory and image identities immediately before spawn.

**ASSUMPTION A5:** packaging supplies a reviewed Team ID/identifier, trusted manifest,
and tested signature/notarization policy; this checkout supplies no verified gate for them.
File-copy/signature preservation and launch-image acceptance require release-runner tests.
Other unsandboxed processes with the same UID can attack private files; mode 0700 is not
an isolation boundary against them. The design trusts the host account and installer.
Production must not advertise race resistance against an independently hostile same-UID
process; stronger guarantees require protected installation/staging or another OS identity.

Unsigned development qualification is a separately built, visibly development-only host
and helper; require the exact fixture SHA while intentionally omitting Developer ID checks.
No release CLI flag or environment variable may downgrade verification. A dry run renders
and inspects artifacts without launching an agent or accessing signing credentials.
Unsigned kernel integration tests are a distinct development test lane, not a dry run.

## 4. Threat model and limits

Trust the OS/kernel, host supervisor, authority verifier/coordinator, compiler, helper,
runtime manifest, installer/release identity and admitted source snapshot preparation.
Treat the agent, generated code, shell tools, dependency scripts and file names as hostile.
The intended property is path-scoped syscall mutation in a private clone, plus bounded
reads; it is not a VM, content correctness proof or multi-tenant security boundary.

| Threat/limit | Required handling and residual exposure |
|---|---|
| Lease TOCTOU, expiry, revocation | Profile is immutable after apply; it does not query CRDB on each syscall. Recheck before launch, bind digests and enforce a host deadline. Stop new broker work on expiry/revocation; restart for changed scope. Direct descendant writes may continue until every owned descendant exits. |
| Strict lease handoff | v0.1.2 must not reassign a scope based merely on agent leader exit or expired DB observation. Retain/quarantine the workspace until quiescence is established. POSIX groups alone cannot catch daemonized descendants that escape the group; strict live revocation is not claimed. |
| Symlink escape and ancestor swaps | Reject grant symlink ancestors; never resolve an outside target into an allow. Test kernel checks of newly created links and concurrent swaps. Deny namespace-root replacement. Canonicalization alone does not close races. |
| Hard links | Existing allowed name can alias an outside inode, so SBPL path rules alone are insufficient. Refuse multiply-linked writable files, use independent CoW inodes, deny new hard-link creation (`file-link`, subject to OS qualification), and forbid external grafts/mounts. A concurrent trusted-host/same-UID mutation remains outside this threat model. |
| Rename across boundary | Both source unlink and destination create must be constrained. Test rename, exchange, directory moves and replacement of protected destinations; narrow file-write* if any operation can escape. Atomic saves to unleased sibling names may fail legitimately. |
| Protected file replacement | Protect control paths and their ancestors against unlink/rename, not only file contents. Fresh nested `.git`/`.chinwag`, mixed case and future files must remain denied under broad leases. |
| Mach, IPC and network | A file lease conveys no IPC/network authority. Default deny plus an explicit runtime service manifest is required; broker permission is a separate capability. Broad Mach or localhost grants could create a confused-deputy escape. |
| Secrets and exfiltration | No home/credential/env inheritance; deny conventional secret paths. Secrets embedded in ordinary readable source/history, runtime files, stdin or broker responses remain exposed. stdout/stderr and any permitted broker/egress route can export readable data. BOX-1B/1C are separate. |
| Child processes and leaf mode | All direct children inherit the agent profile; they are not automatically a stricter leaf sandbox. A shell run directly by the agent retains its broker capability. Guaranteed leaf mode requires host-brokered launch under a distinct profile and no inherited broker FD. |
| Host deputy and malicious Git | Broker rejects arbitrary host commands/paths, validates output scope and disables hooks/helpers. An unrestricted MCP or shell service outside containment would defeat the boundary. |
| Existing descriptors | Sandbox rules do not justify inheriting preopened file/socket capabilities. Close all except intentional streams/status before target exec; test writable FDs, mmap and SCM_RIGHTS paths separately. |
| Resource exhaustion | No CPU, disk, process-count or memory quota is provided; process-fork and leased destructive writes remain possible. Private TMPDIR is not a quota. |
| Platform SPI | sandbox-exec is deprecated; sandbox_init custom SBPL is unsupported SPI and SBPL can change without notice. Unknown OS/dialect fails closed, not silently skips containment. |
| Outside BOX-1A | Kernel exploits, root/host-account compromise, malicious trusted supervisor, arbitrary secret discovery, remote MCP containment, packet mediation, phantom vault, temporal taint, HPKE denial attestation and tamper-proof syscall audit are not delivered here. |

**ASSUMPTION A6:** OS-specific unlink/rename/link/graft filters can enforce the intended
namespace behavior on each supported release. This is a release blocker to prove, not a
claim made by the example profile. The example names hard-link and namespace operations
explicitly because `(deny default)` alone is not a sufficient claim about SPI preamble
behavior. Its generator must select a qualified operation set; unsupported names cannot
be emitted blindly on older systems. v0.1.2 may narrow OS support instead of weakening policy.

## 5. Verification plan

No tests below were run during this design-only spike. Use disposable fixtures exclusively;
never production `.chinwag`, real credentials, operator home or pristine-runs data.
Build outside the inspected source checkout when implementing this plan.

### 5.1 Pure compiler and authority tests

Golden `.sb` files cover exact files, tree roots, empty/duplicate scopes, overlap normalization,
multiple grants, protected subtraction, .env names, literal punctuation and escaped prefixes.
Each includes normalized admission input, emitted bytes, digest and expected path decisions.
Negative cases: absolute/parent/dot/empty components, controls/NUL/newline, non-ASCII,
case collisions, SBPL injection, huge input, unsupported glob syntax and oversized output.
Assert existing `files=["src/*.rs"]` never becomes a wildcard grant under v1 authority.
Use an independent reference matcher and compare admitted path sets to rendered selectors.
Test signature/repository/session/revision/expiry mismatches, rollback clocks, stale replica,
invalid evidence, unsigned authority, unresolved historical reply and copied DB observations.

### 5.2 macOS kernel integration matrix

Use a small syscall fixture reporting operation, errno and resulting hashes, not shell text
such as “permission denied.” The uncontained fixture must first succeed on the same
ordinary mode-0600 files, proving the later failure comes from containment rather than DAC.

| Case | Acceptance |
|---|---|
| Inside exact lease | Existing-file write/truncate succeeds; bytes match; sibling write denied. Create/unlink tested separately, never broadened if unsupported. |
| Tree/new files | Descendant create, mkdir, atomic replace, remove allowed; sibling prefix such as crate-extra denied. Leased root rename/remove denied. |
| Outside lease | open-write, truncate, unlink, mkdir, chmod, xattr and writable mmap fail with kernel denial; assert EPERM for the core write syscall. EACCES variants require explicit OS expectation, never silent success. |
| Read boundary | Allowed source/runtime reads succeed; fake outside secret, .env/.env.local and fake .chinwag/state.crdb reads fail, including mixed-case aliases. |
| Symlink | Existing final/ancestor links rejected at admission; runtime link to outside cannot write/read target; inside-target links tested under declared policy. Race loop swaps ancestors without changing outside canaries. |
| Hardlink | Preexisting cross-boundary alias refused; new hardlink creation denied; APFS clone edits leave source inode/content unchanged. Test both link directions. |
| Rename | Inside→outside, outside→inside, overwrite protected file, directory move, renameat/exchange and root replacement denied; within-lease safe rename succeeds where supported. |
| Scratch | Only private T writable; host TMPDIR sibling denied; HOME/cache/build output remain in T; T root cannot be renamed away. |
| Git layouts | Standalone Git reads work within declared surface; index/hooks/config writes denied. Linked gitdir/commondir and alternates are rejected until the separate admission mode exists. |
| Children | sh/python/generated executable inherit denies; double-fork descendants retain profile; broker-launched leaf cannot connect to broker or network. Direct agent children explicitly retain agent rights. |
| IPC/network | Arbitrary Unix socket, loopback TCP, internet socket, Mach lookup/task ports denied; only declared agent broker endpoint succeeds. No broker grant in leaf profile. |
| FD leakage | Unlisted file/socket FDs absent in target; attempt inherited writable FD and mmap attacks; status FD closed on exec; no setup payload survives in env. |
| Lifetime | Change/revoke/expire authority after apply; demonstrate unchanged kernel profile, stopped broker actions, quarantined result and no premature reassignment. |

Core fixtures must test file-link and OS-specific graft/mount escape operations as available.
The worked SBPL is promoted to a shipping golden only after these proofs; compilation alone
does not establish enforcement. Test actual file outcomes, not just helper return codes.

### 5.3 Launcher, signatures and CI

Negative launch tests: malformed/duplicate flags, wrong profile/launch digests, nonregular
or writable input descriptor, short/oversized input, fd collisions, missing cwd, changed inode,
missing sandbox symbol, invalid operation/regex and forced apply error all prevent target run.
Use a marker fixture to prove target never ran; no tests invoke the production Chinwag binary.
Exercise helper crash before/after apply, broken status pipe, failed exec, target code 70,
target signal, unknown wait result and supervisor cancellation without losing child ownership.
All timeouts and signals in future tests target only fixture processes owned by that test.

Production verifier tests reject tampered bytes, wrong manifest, Team ID or identifier,
ad-hoc/unsigned helper, wrong architecture, debug entitlements and helper path substitution.
Copy the signed helper to its launch image and verify code-signing validity survives.
Environment tests inject synthetic bait variables only; assert target receives none and no
secret-like values/argv enter setup receipts. Do not inspect real process argument vectors.

CI uses macOS runners for kernel proofs; Linux compiler tests cannot stand in for Seatbelt.
PROPOSED initial matrix: macOS 15 and 26, Apple Silicon; Intel remains unclaimed until tested.
**ASSUMPTION A7:** runner images/toolchains for both OS releases are available and approved.
Unsupported runner/toolchain is a failed or explicitly unqualified release gate, not a green skip.
Run pure parsing/goldens/fuzz smoke without signing credentials on PRs; run ad-hoc development
kernel tests separately; release-owner signed qualification verifies the real production path.
`dry_run=true` checks bundle/manifest structure without Apple certificates and cannot prove
Developer ID validity, notarization or signed launch behavior. No secrets for fork PR jobs.

### 5.4 Fuzzing

Fuzz the versioned glob parser, path validator, SBPL serializers and launch-record decoder
with bounded input/output and depth; no panic, injection, unbounded regex expansion or hang.
Generate valid patterns plus candidate paths; independently match AST semantics and emitted
regex. Include slash boundaries, zero-directory `**/`, punctuation and case-folded protections.
Run a bounded macOS differential corpus against actual sandboxed path operations; minimize
counterexamples into goldens. Never feed arbitrary raw SBPL to privileged production helpers.

## 6. Phased build plan for RUST

Size is relative engineering scope: S = localized work, M = several interacting modules,
L = cross-crate/platform authority or lifecycle work; these are not calendar commitments.

| Phase | Size | Deliverable and acceptance criteria |
|---|---|---|
| 1. Reconcile authority and CLI-13 | M | Identify deployed spawn source/commit or confirm missing baseline; document authoritative lease lifecycle and release baseline. Prove no DB observation/report can construct `AdmittedLease`. No containment launch enabled. |
| 2. Admission and deterministic compiler | L | New `chinwag-containment` library: typed admitted scope, path identity model, protected floors, exact-only SBPL compiler and independent matcher/goldens. Tree only behind authenticated v2 authority. Rejected input cannot widen scope; all pure tests pass. |
| 3. Minimal trampoline and owned spawn | M | New `chinwag-contain-trampoline` binary, bounded FD ABI, isolated macOS FFI, apply→exec and status protocol; `spawn_contained_at` in host-process. Invalid profile prevents marker execution; descriptor and exit tests pass. |
| 4. CoW preparation and Git admission | L | New host-process `contained_workspace` module prepares independent APFS clone, private T/C and standalone sanitized Git view. Verify source unchanged, no inode aliases, protected roots pinned and cleanup restricted to original owned run. No linked-worktree shortcuts. |
| 5. Product lease source and spawn wiring | L | Versioned authenticated authority adapter and CLI `SpawnRequest`/dispatch; bind source snapshot/run/lease/profile receipts, expiry and result quarantine. End-to-end contained spawn works without fabricating signed scope from CRDB rows. Gate on a defined exclusivity/handoff contract. |
| 6. Kernel qualification and release identity | L | macOS attack matrix, signed helper verification, trusted artifact manifest and negative failure proofs. No kernel escape in supported operations; signed launch passes; unsigned development mode cannot enter release builds. This gates v0.1.2 product claims. |
| 7. Full globs and two-tier broker | L | v2 matcher shared with atomic coordinator overlap logic; fuzz/differential regex proof, linked-worktree admission if needed, host-owned broker leaf launch with no socket/network route. Integrate BOX-1B/1C separately for v0.2.0. |

Suggested crate/module ownership (new names are PROPOSED):
`chinwag-containment::{scope, paths, protected, glob, sbpl, launch_wire}` contains pure
validation/rendering; `macos` contains the minimal unsafe sandbox/signature boundary.
The helper depends only on launch decoding, hashing, libc and that minimal apply boundary;
it does not link CRDB, networking, key loading, provider SDKs or general MCP services.
`chinwag-host-process::{contained_spawn, contained_workspace, helper_verifier, lease_admission}`
owns orchestration/lifecycle; `chinwag-cli::spawn_run` owns user dispatch and safe receipts.
Authority event interpretation belongs with claim/snapshot owners, not inside SBPL rendering.
Preserve opaque/non-Clone ownership and checked-finish conventions of existing crates.

**v0.1.2:** ship a fail-closed macOS opt-in exact-file/offline contained spawn once phases
1–6 pass; bounded runtime reads, private scratch, standalone CoW copy, signed helper and
explicit lifetime/quiescence limits. Tree is conditional on real authenticated v2 scope.
If product authority/CoW prerequisites are absent, ship compiler/helper as development
qualification only; do not call it completed CHWG-BOX-1A or a lease-enforced agent product.
Interactive provider harnesses may wait for BOX-1B instead of inheriting real credentials.

**v0.2.0:** authenticated general globs with coordinator overlap semantics, tested linked
Git worktrees if required, broker-mediated agent/leaf distinction, broader harness/runtime
qualification and integration with separately delivered phantom egress/temporal policy.
Strict instantaneous kernel revocation still requires a separately proven lifecycle design;
the version number alone does not solve detached descendants or immutable profiles.

## 7. Open questions for Gemini-PM

1. **Which source is CLI-13's deployed spawn implementation?** Recommended default:
   treat it as absent in this checkout until a concrete commit/path is supplied; schedule
   CoW preparation and CLI dispatch as prerequisites, not a small Seatbelt-only patch.
2. **What makes a CRDB lease authoritative and exclusive?** Recommended default:
   verify signed authority events and current owner/session/revision against a defined
   atomic authority service; replicated observations and historical receipts never grant.
3. **Exact paths or new signed glob semantics?** Recommended default: preserve v1 exact
   strings, introduce a new signed domain for Tree/Glob, ship exact-only first. Never
   reinterpret a string containing `*` under an old signature as broader authority.
4. **Must lease expiry instantly stop all direct writes?** Recommended default: disclose
   immutable per-run profiles and quarantine workspaces/results until proven quiescent;
   no scope handoff to another writer merely on TTL expiry. If instant revocation is
   mandatory, it blocks v0.1.2 until a stronger lifecycle/isolation mechanism is proven.
5. **Is repository history readable, and who may commit?** Recommended default:
   standalone sanitized Git metadata, approved history reads, host-only mutation/signing.
   Linked-worktree/common-gitdir support waits for its own admission and deny tests.
6. **How much build/editor convenience may exceed a lease?** Recommended default:
   scratch/cache/target in T, host-mediated exact-file atomic replacement, no parent
   directory grants for editors and no workspace-wide `target/` write exception.
7. **Which runtime/network modes are in the first product slice?** Recommended default:
   offline leaf/exact-file mode first; broker-only agent IPC once implemented. Provider
   egress waits for BOX-1B; direct children retain their parent's IPC rights. Guaranteed
   leaf isolation applies only to host-brokered tool launches.
8. **Which macOS/platform support can we promise?** Recommended default: Apple Silicon
   macOS 15/26 only after actual qualification; choose a narrower matrix if SPI operation
   differences cannot be represented safely. No Intel or future OS claim without testing.
9. **Does the CHWG-011-1 two-SHA signing add-on belong in v0.1.1 or later?** Recommended
   default: include it in v0.1.1 if unreleased, before any credential-bearing pre-merge
   signing job. Require release-owner-reviewed `SIGNING_TEST_WORKFLOW_SHA` and
   `SIGNING_TEST_SOURCE_SHA`, each exactly 40 lowercase hex characters; reject missing,
   branch/tag/short/uppercase/all-zero values and verify the fetched commits are the
   exact workflow and source executed. Gate before credential access, pin nested actions
   and scripts too, and preserve credential-free `dry_run=true`. These pins bind review
   to execution and protect the signing identity BOX-1A will trust; delaying them until
   sandbox delivery creates an avoidable release-chain gap. If v0.1.1 already shipped,
   do not rewrite its tag: use the next patch before enabling signed pre-merge runs.
   ASSUMPTION: the release numbering and current CHWG-011-1 workflow live elsewhere;
   this checkout contains no verified implementation of that gate.
10. **Who owns production helper provenance?** Recommended default: release owner pins
    Team ID, identifier, hardened entitlements, trusted SHA manifest and notarization
    policy; helper cannot be selected by agent config. Development unsigned binaries
    remain visibly separate and cannot downgrade the production path.
11. **What is the readable-source secret policy?** Recommended default: deny all .env*
    and credential/control paths, use empty private HOME/env, require explicit approval
    of readable history/runtime trees. Do not promise content-level secret detection,
    phantom credentials or complete read/egress audit as part of BOX-1A.
12. **Is same-UID hostile-host resistance a requirement?** Recommended default: trust
    the operator account and installer, document that private staging is not protection
    against arbitrary unsandboxed peers. Escalate to stronger identity/VM isolation if
    independent hostile processes on the same account must be resisted.

## 8. References and qualification receipts

- [Canonical CHWG-BOX-1 PRD](/Users/brianspector/WORKSPACE/paperclip-wiki/wiki/projects/Chinwag/prd/chwg-box-1-kernel-seatbelt-leases-and-phantom-credentials-prd.md): desired BOX-1A/B/C split and two-SHA signing requirement; not evidence that described code already exists.
- [Installed Apple sandbox header](/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sandbox.h): deprecated sandbox_init/free_error, named-profile documented contract and return/error-buffer handling.
- [Installed sandbox-exec manual](/usr/share/man/man1/sandbox-exec.1): explicitly deprecated, profile-file CLI interface.
- [Apple DTS on custom sandbox support](https://developer.apple.com/forums/thread/661939): SBPL is undocumented for third-party use and sandbox-exec is deprecated; App Sandbox is a distinct supported facility.
- [Strands Box macOS enforcement](https://github.com/strands-agents/box/blob/main/docs/design/macos-enforcement.md): design ideas only—separate apply-before-exec launcher, fixed per-run profiles and distinct broker/tool containment. No source code copied.
- [Strands Box containment design](https://github.com/strands-agents/box/blob/main/crates/containment/README.md): design ideas only—canonical identities, pinned writable roots, setup failure channel and copying an opened helper into a private macOS executable image. Chinwag adds an independently required signature/SHA provenance gate. No code copied.
- [Strands Box macOS operation inventory](https://github.com/strands-agents/box/blob/main/crates/containment/src/backend/macos/seatbelt-agent.sb): reviewed for SPI operation names and OS-specific namespace restrictions; this document's example was composed for the synthetic Chinwag lease, not copied from that template.
- [Strands Box limitations](https://github.com/strands-agents/box/blob/main/docs/design/limitations.md): comparison ideas only—allowed actions can still harm, direct file reads bypass policy history, and process containment is not host or resource isolation.
- The PRD-linked Box `docs/dev/macos-release.md` could not be fetched during this spike;
  its exact two-SHA mechanism is unverified here. The recommendation in question 9
  derives from the supplied Chinwag PRD and this design's release trust requirements.

Qualification receipt: repository/spec/source/header/manual reads and public web reading
only; no build, Chinwag execution, database open, signing operation, publication, service
post or process control. The sole requested output is this DESIGN.md. Kernel enforcement,
runtime compatibility, helper signature execution and authority lifecycle remain untested.
