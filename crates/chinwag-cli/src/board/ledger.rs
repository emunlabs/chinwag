// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! `INV-BOARD-LEDGER-TRACKING-01` and `INV-UNIQUE-TICKET-ID-01`: no card is admitted to the
//! board without its scoping fields, none sits in the shipped column without its settlement
//! fields, and no two cards share a ticket ID. `chinwag board verify-ledger` audits local task
//! files and, with `--live`, every item on the GitHub project.

use super::*;

/// Upper bound on `gh project item-list`. A larger board fails the audit instead of being
/// silently truncated.
const LIVE_ITEM_LIMIT: usize = 300;

/// Upper bound on `gh issue list` per linked repository, with the same fail-closed rule.
const LIVE_ISSUE_STATE_LIMIT: usize = 5_000;

const CYCLE_TIME_UNSETTLED_PREFIXES: [&str; 2] = ["Queued", "In flight"];

fn violation(invariant: &str, issue_id: &str, reason: String) -> HBoardViolation {
    HBoardViolation {
        exit_code: EXIT_H_BOARD_REJECT,
        invariant: invariant.to_string(),
        issue_id: issue_id.to_string(),
        reason,
    }
}

fn policy_violation(reason: String) -> HBoardViolation {
    violation(
        INV_BOARD_LEDGER_TRACKING,
        BOARD_POLICY_RELATIVE_PATH,
        reason,
    )
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let inline = format!("{flag}=");
    args.iter().enumerate().find_map(|(idx, arg)| {
        if arg == flag {
            args.get(idx + 1).map(String::as_str)
        } else {
            arg.strip_prefix(&inline)
        }
    })
}

/// The workspace a tasks directory belongs to: `--workspace-root` when given, otherwise the
/// directory that holds `.chinwag/tasks`. A tasks directory outside any `.chinwag/` has none.
pub(super) fn resolve_board_workspace_root(args: &[String], tasks_dir: &Path) -> Option<PathBuf> {
    if let Some(root) = arg_value(args, "--workspace-root") {
        return Some(PathBuf::from(root));
    }
    let chinwag_dir = tasks_dir.parent()?;
    (chinwag_dir.file_name()? == ".chinwag")
        .then(|| chinwag_dir.parent().map(Path::to_path_buf))
        .flatten()
}

/// Loads the policy that governs `tasks_dir`. `Ok(None)` means the tasks directory is detached
/// from any workspace; such a directory can never reach a live board (see
/// [`require_board_policy_for_live`]). A workspace whose policy is missing or invalid is an error.
pub(super) fn resolve_board_policy(
    args: &[String],
    tasks_dir: &Path,
) -> Result<Option<BoardPolicyTomlV1>, HBoardViolation> {
    let Some(root) = resolve_board_workspace_root(args, tasks_dir) else {
        return Ok(None);
    };
    BoardPolicyTomlV1::load(&root)
        .map(Some)
        .map_err(|e| policy_violation(e.to_string()))
}

/// A live board mutation is only ever allowed under a loaded policy.
pub(super) fn require_board_policy_for_live(
    policy: Option<&BoardPolicyTomlV1>,
) -> Result<&BoardPolicyTomlV1, HBoardViolation> {
    policy.ok_or_else(|| {
        policy_violation(format!(
            "a live board mutation requires `{BOARD_POLICY_RELATIVE_PATH}`; run from a workspace or pass `--workspace-root`"
        ))
    })
}

/// Every way `issue` breaks the ledger policy, in a stable order.
#[must_use]
pub fn collect_board_ledger_violations(
    issue: &AtomicTaskIssue,
    policy: &BoardPolicyTomlV1,
) -> Vec<HBoardViolation> {
    let mut found = Vec::new();
    let mut reject = |invariant: &str, reason: String| {
        found.push(violation(invariant, &issue.id, reason));
    };
    let prefix = &policy.board.ticket_prefix;

    if TicketId::parse(&issue.id, prefix).is_none() {
        reject(
            INV_BOARD_LEDGER_TRACKING,
            format!(
                "ticket id `{}` must match ^{prefix}-[0-9]{{4}}(?:\\.[0-9]{{2}}(?:-[0-9]{{2}})?)?$",
                issue.id
            ),
        );
    }
    if !policy.allows_deliverable_kind(&issue.deliverable_kind) {
        reject(
            INV_BOARD_LEDGER_TRACKING,
            format!(
                "deliverable_kind `{}` is not allowed (allowed: {})",
                issue.deliverable_kind,
                policy.ledger().allow_deliverable_kinds.join(", ")
            ),
        );
    }
    if policy.requires_scoping(ScopingField::FunctionTeam) {
        match issue.primary_function.as_deref() {
            None => reject(
                INV_BOARD_LEDGER_TRACKING,
                format!(
                    "primary_function is missing; set one of: {}",
                    FUNCTIONS.join(", ")
                ),
            ),
            Some(function) if !FUNCTIONS.contains(&function) => reject(
                INV_BOARD_LEDGER_TRACKING,
                format!(
                    "primary_function `{function}` is not one of: {}",
                    FUNCTIONS.join(", ")
                ),
            ),
            Some(_) => {}
        }
    }
    let seats: Vec<String> = issue
        .assigned_seats
        .iter()
        .map(|seat| normalize_seat_token(seat))
        .filter(|seat| !seat.is_empty())
        .collect();
    if policy.requires_scoping(ScopingField::ActiveSeats)
        && issue.status != BoardStatus::OpenBounty
        && seats.is_empty()
    {
        reject(
            INV_BOARD_LEDGER_TRACKING,
            format!(
                "assigned_seats is empty; only {} cards may be unassigned",
                BoardStatus::OpenBounty.as_code()
            ),
        );
    }

    if issue.visibility.eq_ignore_ascii_case("public")
        && let Some(seat) = seats.iter().find(|seat| policy.locks_seat_private(seat))
    {
        reject(
            "INV-DEFAULT-PRIVATE-TASK-01",
            format!(
                "seat `{seat}` is locked to private by {BOARD_POLICY_RELATIVE_PATH} and cannot be published on a public board"
            ),
        );
    }
    if !issue_requires_private_repo(issue) {
        let public_copy = issue.to_markdown();
        if let Some(needle) = policy
            .privacy()
            .forbidden_public_substrings
            .iter()
            .find(|needle| public_copy.contains(needle.as_str()))
        {
            reject(
                "INV-PUBLIC-BOARD-REDACTION-01",
                format!(
                    "substring `{needle}` is forbidden on public cards by {BOARD_POLICY_RELATIVE_PATH}"
                ),
            );
        }
    }

    if issue.status == BoardStatus::ShippedVerified {
        if policy.requires_settlement(SettlementField::TClaimMs) && issue.t_claim_ms == 0 {
            reject(
                INV_BOARD_LEDGER_TRACKING,
                "shipped card has no claim time (t_claim_ms is 0)".to_string(),
            );
        }
        if policy.requires_settlement(SettlementField::TShipMs)
            && (issue.t_ship_ms == 0 || issue.t_ship_ms < issue.t_claim_ms)
        {
            reject(
                INV_BOARD_LEDGER_TRACKING,
                format!(
                    "shipped card needs t_ship_ms >= t_claim_ms (t_ship_ms {}, t_claim_ms {})",
                    issue.t_ship_ms, issue.t_claim_ms
                ),
            );
        }
        if policy.requires_settlement(SettlementField::LocChanged) && issue.loc_changed.is_none() {
            reject(
                INV_BOARD_LEDGER_TRACKING,
                "shipped card has no loc_changed (record 0 for an artifact with no line count)"
                    .to_string(),
            );
        }
        let (ceiling, inflated) = enforce_tier_lock_for_deliverable(
            issue.dora_tier,
            issue.loc_changed,
            &issue.deliverable_kind,
        );
        if policy.ledger().require_settlement_on_ship && inflated {
            reject(
                "INV-TIER-LOCK-01",
                format!(
                    "claimed tier {} exceeds tier {} allowed for {} LOC",
                    issue.dora_tier.as_str(),
                    ceiling.as_str(),
                    issue.loc_changed.unwrap_or_default()
                ),
            );
        }
        if policy.requires_settlement(SettlementField::CryptographicReceipt)
            && issue
                .receipt_trailers
                .iter()
                .all(|trailer| trailer.trim().is_empty())
        {
            reject(
                INV_BOARD_LEDGER_TRACKING,
                "shipped card has no receipt trailers (cryptographic_receipt)".to_string(),
            );
        }
    }

    found
}

/// Validates one card for admission to the board and, in the shipped column, for settlement.
pub fn validate_board_ledger_issue(
    issue: &AtomicTaskIssue,
    policy: &BoardPolicyTomlV1,
) -> Result<(), HBoardViolation> {
    match collect_board_ledger_violations(issue, policy)
        .into_iter()
        .next()
    {
        Some(first) => Err(first),
        None => Ok(()),
    }
}

/// One card's claim on a ticket ID. `source` says where the card lives, such as a task file
/// path or `owner/repo#42`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketCardRef {
    pub ticket_id: String,
    pub source: String,
}

/// `INV-UNIQUE-TICKET-ID-01`: no two cards may claim the same `<PREFIX>-<NNNN>` or
/// `<PREFIX>-<NNNN>.<sub_id>`. A ticket and its own sub-tickets are distinct IDs. Cards whose
/// ID is not canonical are left to the admission check.
pub fn validate_unique_ticket_ids(
    cards: &[TicketCardRef],
    ticket_prefix: &str,
) -> Result<(), Vec<HBoardViolation>> {
    let mut claims: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for card in cards {
        if let Some(ticket) = TicketId::parse(&card.ticket_id, ticket_prefix) {
            claims
                .entry(ticket.as_str())
                .or_default()
                .push(card.source.as_str());
        }
    }
    let violations: Vec<HBoardViolation> = claims
        .into_iter()
        .filter(|(_, sources)| sources.len() > 1)
        .map(|(ticket, sources)| {
            violation(
                INV_UNIQUE_TICKET_ID,
                ticket,
                format!(
                    "ticket id `{ticket}` is claimed by {} cards: {}",
                    sources.len(),
                    sources.join(", ")
                ),
            )
        })
        .collect();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// One item on the live GitHub project, as reported by `gh project item-list`.
#[derive(Debug, Clone, PartialEq)]
pub struct LiveBoardItem {
    pub item_id: String,
    pub title: String,
    /// `Issue`, `PullRequest`, `DraftIssue`, or `Redacted`.
    pub content_type: String,
    /// `owner/name` of the repository that holds the item's issue.
    pub repository: Option<String>,
    pub number: Option<u64>,
    /// `OPEN` or `CLOSED`, from the issue's own repository.
    pub issue_state: Option<String>,
    /// Project field values keyed the way `gh` prints them.
    pub fields: BTreeMap<String, Value>,
}

impl LiveBoardItem {
    /// Looks a project field up by its real name. `gh` lowercases the first byte of every
    /// field name, which turns `DORA Baseline` into `dORA Baseline` and the two-byte `Δ` into
    /// two U+FFFD replacement characters, so neither form can be matched literally.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Value> {
        if let Some(value) = self.fields.get(name) {
            return Some(value);
        }
        let mut chars = name.chars();
        let first = chars.next()?;
        let tail = chars.as_str();
        self.fields
            .iter()
            .find(|(key, _)| {
                key.strip_suffix(tail).is_some_and(|head| {
                    let mut head_chars = head.chars();
                    let lowered_first = matches!(
                        (head_chars.next(), head_chars.next()),
                        (Some(c), None) if c.to_lowercase().eq(first.to_lowercase())
                    );
                    lowered_first || (!head.is_empty() && head.chars().all(|c| c == '\u{fffd}'))
                })
            })
            .map(|(_, value)| value)
    }

    fn text(&self, name: &str) -> Option<&str> {
        self.field(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
    }

    fn number_value(&self, name: &str) -> Option<f64> {
        self.field(name).and_then(Value::as_f64)
    }

    fn has_value(&self, name: &str) -> bool {
        match self.field(name) {
            None | Some(Value::Null) => false,
            Some(Value::String(text)) => !text.trim().is_empty(),
            Some(Value::Array(values)) => !values.is_empty(),
            Some(_) => true,
        }
    }

    fn status(&self) -> Option<&str> {
        self.text("Status")
    }

    fn issue_ref(&self) -> String {
        match (&self.repository, self.number) {
            (Some(repo), Some(number)) => format!("{repo}#{number}"),
            _ => self.item_id.clone(),
        }
    }
}

/// Everything `verify-ledger --live` reads from GitHub.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LiveBoardSnapshot {
    pub items: Vec<LiveBoardItem>,
}

fn repo_slug_from(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("https://github.com/")
        .trim_end_matches('/')
        .to_string()
}

/// Parses `gh project item-list <n> --owner <org> --format json`. Fails when GitHub reports
/// more items than were returned, because an audit of a partial board proves nothing.
pub fn parse_live_project_items(list: &Value) -> Result<Vec<LiveBoardItem>, String> {
    let items = list
        .get("items")
        .and_then(Value::as_array)
        .ok_or("project item list has no `items` array")?;
    if let Some(total) = list.get("totalCount").and_then(Value::as_u64)
        && total as usize > items.len()
    {
        return Err(format!(
            "project has {total} items but only {} were returned; raise the item limit",
            items.len()
        ));
    }
    items
        .iter()
        .map(|raw| {
            let object = raw.as_object().ok_or("project item is not a JSON object")?;
            let content = object.get("content");
            let content_str = |key: &str| {
                content
                    .and_then(|c| c.get(key))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            };
            let item_id = object
                .get("id")
                .and_then(Value::as_str)
                .ok_or("project item has no `id`")?
                .to_string();
            let title = content_str("title")
                .or_else(|| {
                    object
                        .get("title")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_default();
            let repository = content_str("repository")
                .map(|repo| repo_slug_from(&repo))
                .filter(|repo| !repo.is_empty());
            let fields = object
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "id" | "content"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            Ok(LiveBoardItem {
                item_id,
                title,
                content_type: content_str("type").unwrap_or_else(|| "Unknown".to_string()),
                repository,
                number: content
                    .and_then(|c| c.get("number"))
                    .and_then(Value::as_u64),
                issue_state: None,
                fields,
            })
        })
        .collect()
}

fn board_status_from_column(raw: &str) -> Option<BoardStatus> {
    [
        BoardStatus::OpenBounty,
        BoardStatus::ScopedBenchmarked,
        BoardStatus::InFlight,
        BoardStatus::TribunalGate,
        BoardStatus::ShippedVerified,
    ]
    .into_iter()
    .find(|status| status.column_header() == raw)
}

/// Credits priced into an execution-mode label such as `Triad · 150 Cr`.
fn credits_for_execution_mode(label: &str) -> Option<u64> {
    label
        .trim()
        .strip_suffix("Cr")?
        .trim_end()
        .rsplit(' ')
        .next()?
        .parse()
        .ok()
}

/// Audits every live board item against the policy. Read-only.
#[must_use]
pub fn collect_live_board_violations(
    snapshot: &LiveBoardSnapshot,
    policy: &BoardPolicyTomlV1,
) -> Vec<HBoardViolation> {
    let prefix = &policy.board.ticket_prefix;
    let shipped_header = BoardStatus::ShippedVerified.column_header();
    let mut found = Vec::new();
    let mut claims = Vec::new();

    for item in &snapshot.items {
        let ticket = TicketId::from_title(&item.title, prefix);
        let issue_ref = item.issue_ref();
        let label = ticket.map_or(issue_ref.as_str(), |t| t.as_str());
        let mut reject = |reason: String| {
            found.push(violation(INV_BOARD_LEDGER_TRACKING, label, reason));
        };

        if item.content_type != "Issue" {
            reject(format!(
                "{issue_ref} is a {} item; only repository issues are tracked",
                item.content_type
            ));
            continue;
        }
        match item.repository.as_deref() {
            Some(repo) if policy.links_repo(repo) => {}
            Some(repo) => reject(format!(
                "{issue_ref} lives in `{repo}`, which is not in board.linked_repos"
            )),
            None => reject(format!("{issue_ref} has no repository")),
        }
        match ticket {
            Some(ticket) => claims.push(TicketCardRef {
                ticket_id: ticket.as_str().to_string(),
                source: issue_ref.clone(),
            }),
            None if policy.board.disallow_raw_bypass => reject(format!(
                "{issue_ref} title `{}` does not start with a `{prefix}-NNNN` ticket id; the card was not created through the board gate",
                item.title
            )),
            None => {}
        }

        let status = match item.status() {
            None => {
                reject(format!("{issue_ref} is an orphan with no Status"));
                None
            }
            Some(raw) => {
                let status = board_status_from_column(raw);
                if status.is_none() {
                    reject(format!(
                        "{issue_ref} has Status `{raw}`, which is not a ledger column"
                    ));
                }
                status
            }
        };
        let is_shipped = status == Some(BoardStatus::ShippedVerified);

        match item.issue_state.as_deref() {
            None => reject(format!("{issue_ref} issue state could not be read")),
            Some(state) if state.eq_ignore_ascii_case("CLOSED") && !is_shipped => {
                reject(format!(
                    "{issue_ref} is closed but its card is not in `{shipped_header}`"
                ));
            }
            Some(state) if state.eq_ignore_ascii_case("OPEN") && is_shipped => {
                reject(format!(
                    "{issue_ref} is open but its card is in `{shipped_header}`"
                ));
            }
            Some(_) => {}
        }

        for field in ScopingField::ALL {
            if !policy.requires_scoping(field)
                || (field == ScopingField::ActiveSeats && status == Some(BoardStatus::OpenBounty))
            {
                continue;
            }
            if !item.has_value(field.board_field_name()) {
                reject(format!(
                    "{issue_ref} is missing scoping field `{}`",
                    field.board_field_name()
                ));
            }
        }

        if !is_shipped {
            continue;
        }
        for field in SettlementField::ALL {
            let Some(name) = field.board_field_name() else {
                continue;
            };
            if !policy.requires_settlement(field) {
                continue;
            }
            if !item.has_value(name) {
                reject(format!(
                    "{issue_ref} is shipped but settlement field `{name}` is empty"
                ));
                continue;
            }
            match field {
                SettlementField::CreditsUsed => {
                    let mode_name = ScopingField::ExecutionMode.board_field_name();
                    if let Some(mode) = item.text(mode_name) {
                        let expected = credits_for_execution_mode(mode);
                        let actual = item.number_value(name);
                        if expected.map(|credits| credits as f64) != actual {
                            reject(format!(
                                "{issue_ref} `{name}` is {} but `{mode_name}` is `{mode}`",
                                actual
                                    .map_or_else(|| "not a number".to_string(), |n| n.to_string())
                            ));
                        }
                    }
                }
                SettlementField::NetHoursSaved => {
                    if item.number_value(name).is_none() {
                        reject(format!("{issue_ref} `{name}` is not a number"));
                    }
                }
                SettlementField::ChinwagCycleTime => {
                    if let Some(text) = item.text(name)
                        && CYCLE_TIME_UNSETTLED_PREFIXES
                            .iter()
                            .any(|unsettled| text.starts_with(unsettled))
                    {
                        reject(format!(
                            "{issue_ref} is shipped but `{name}` still reads `{text}`"
                        ));
                    }
                }
                SettlementField::SpeedupVsDora => {
                    if let Some(text) = item.text(name)
                        && (text == SPEEDUP_OPTIONS[3] || text == SPEEDUP_OPTIONS[4])
                    {
                        reject(format!(
                            "{issue_ref} is shipped but `{name}` still reads `{text}`"
                        ));
                    }
                }
                SettlementField::VerificationReceipt
                | SettlementField::CryptographicReceipt
                | SettlementField::TClaimMs
                | SettlementField::TShipMs
                | SettlementField::LocChanged => {}
            }
        }
    }

    if let Err(duplicates) = validate_unique_ticket_ids(&claims, prefix) {
        found.extend(duplicates);
    }
    found
}

fn run_gh_json(args: &[&str]) -> Result<Value, String> {
    let output = std::process::Command::new("gh")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run `gh {}`: {e}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "`gh {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("`gh {}` returned invalid JSON: {e}", args.join(" ")))
}

fn fetch_live_board_snapshot(policy: &BoardPolicyTomlV1) -> Result<LiveBoardSnapshot, String> {
    let project_number = policy.board.project_number.to_string();
    let item_limit = LIVE_ITEM_LIMIT.to_string();
    let list = run_gh_json(&[
        "project",
        "item-list",
        &project_number,
        "--owner",
        &policy.board.org,
        "--limit",
        &item_limit,
        "--format",
        "json",
    ])?;
    let mut items = parse_live_project_items(&list)?;

    let issue_limit = LIVE_ISSUE_STATE_LIMIT.to_string();
    for repo in &policy.board.linked_repos {
        if !items.iter().any(|item| {
            item.repository
                .as_deref()
                .is_some_and(|r| r.eq_ignore_ascii_case(repo))
        }) {
            continue;
        }
        let issues = run_gh_json(&[
            "issue",
            "list",
            "--repo",
            repo,
            "--state",
            "all",
            "--limit",
            &issue_limit,
            "--json",
            "number,state",
        ])?;
        let issues = issues
            .as_array()
            .ok_or_else(|| format!("issue list for `{repo}` is not a JSON array"))?;
        if issues.len() >= LIVE_ISSUE_STATE_LIMIT {
            return Err(format!(
                "`{repo}` has at least {LIVE_ISSUE_STATE_LIMIT} issues; issue states would be truncated"
            ));
        }
        let states: BTreeMap<u64, &str> = issues
            .iter()
            .filter_map(|issue| {
                Some((
                    issue.get("number")?.as_u64()?,
                    issue.get("state")?.as_str()?,
                ))
            })
            .collect();
        for item in &mut items {
            if item.content_type == "Issue"
                && item
                    .repository
                    .as_deref()
                    .is_some_and(|r| r.eq_ignore_ascii_case(repo))
                && let Some(number) = item.number
            {
                item.issue_state = states.get(&number).map(|state| (*state).to_string());
            }
        }
    }
    Ok(LiveBoardSnapshot { items })
}

fn collect_local_violations(
    issues_dir: &Path,
    policy: &BoardPolicyTomlV1,
) -> (usize, Vec<HBoardViolation>) {
    let mut paths: Vec<PathBuf> = fs::read_dir(issues_dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("md"))
                .collect()
        })
        .unwrap_or_default();
    paths.sort();

    let mut found = Vec::new();
    let mut claims = Vec::new();
    for path in &paths {
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        let issue = fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|raw| AtomicTaskIssue::from_markdown(&raw));
        match issue {
            Ok(issue) => {
                found.extend(collect_board_ledger_violations(&issue, policy));
                claims.push(TicketCardRef {
                    ticket_id: issue.id,
                    source: format!("issues/{file_name}"),
                });
            }
            Err(e) => found.push(violation(
                INV_BOARD_LEDGER_TRACKING,
                &file_name,
                format!("task file cannot be read as a card: {e}"),
            )),
        }
    }
    if let Err(duplicates) = validate_unique_ticket_ids(&claims, &policy.board.ticket_prefix) {
        found.extend(duplicates);
    }
    (paths.len(), found)
}

/// `chinwag board verify-ledger [--live] [--json] [--workspace-root <path>]`.
pub fn run_board_verify_ledger(
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    run_board_verify_ledger_with(args, stdout, stderr, &fetch_live_board_snapshot)
}

pub(super) fn run_board_verify_ledger_with(
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    fetch_live: &dyn Fn(&BoardPolicyTomlV1) -> Result<LiveBoardSnapshot, String>,
) -> u8 {
    let live = args.iter().any(|arg| arg == "--live");
    let json_only = args.iter().any(|arg| arg == "--json");
    let explicit_root = arg_value(args, "--workspace-root").map(PathBuf::from);
    let tasks_dir = match (&explicit_root, arg_value(args, "--tasks-dir")) {
        (Some(root), None) => root.join(".chinwag").join("tasks"),
        _ => resolve_tasks_dir(args),
    };

    let mut violations = Vec::new();
    let mut checked_local = 0;
    let mut checked_live = 0;

    let policy = match resolve_board_workspace_root(args, &tasks_dir) {
        Some(root) => BoardPolicyTomlV1::load(&root).map_err(|e| e.to_string()),
        None => Err(format!(
            "`{}` is not inside a workspace `.chinwag/` directory; pass `--workspace-root`",
            tasks_dir.display()
        )),
    };
    match &policy {
        Err(reason) => violations.push(policy_violation(reason.clone())),
        Ok(policy) => {
            violations.extend(
                policy.ledger_tracking_gaps().into_iter().map(|gap| {
                    policy_violation(format!("policy does not enforce the ledger: {gap}"))
                }),
            );
            let (count, local) = collect_local_violations(&tasks_dir.join("issues"), policy);
            checked_local = count;
            violations.extend(local);
            if live {
                match fetch_live(policy) {
                    Ok(snapshot) => {
                        checked_live = snapshot.items.len();
                        violations.extend(collect_live_board_violations(&snapshot, policy));
                    }
                    Err(e) => violations.push(violation(
                        INV_BOARD_LEDGER_TRACKING,
                        "live-board",
                        format!("live board could not be audited: {e}"),
                    )),
                }
            }
        }
    }

    let ok = violations.is_empty();
    let report = json!({
        "ok": ok,
        "invariant": INV_BOARD_LEDGER_TRACKING,
        "invariants": [INV_BOARD_LEDGER_TRACKING, INV_UNIQUE_TICKET_ID],
        "command": "chinwag board verify-ledger",
        "live": live,
        "checked_items": checked_local + checked_live,
        "checked_local_issues": checked_local,
        "checked_live_items": checked_live,
        "violations": violations,
    });
    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
    if !json_only {
        for v in &violations {
            let _ = writeln!(stderr, "[{}] {}: {}", v.invariant, v.issue_id, v.reason);
        }
        let _ = writeln!(
            stderr,
            "verify-ledger: {} items checked, {} violations",
            checked_local + checked_live,
            violations.len()
        );
    }
    if ok { 0 } else { EXIT_H_BOARD_REJECT }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_WORKSPACE: AtomicU64 = AtomicU64::new(0);

    fn policy_with_prefix(prefix: &str) -> BoardPolicyTomlV1 {
        BoardPolicyTomlV1::starter(
            "acme-co",
            7,
            None,
            "acme-co/product",
            Some("acme-co/tasks"),
            prefix,
        )
    }

    fn policy() -> BoardPolicyTomlV1 {
        policy_with_prefix("ACME")
    }

    fn scoped(id: &str) -> AtomicTaskIssue {
        let mut issue = AtomicTaskIssue::new_unscoped(id, "Scoped card", DoraTier::M);
        issue.primary_function = Some("Engineering".to_string());
        issue.assigned_seats = vec!["DEV".to_string(), "QA".to_string()];
        issue
    }

    fn shipped(id: &str) -> AtomicTaskIssue {
        let mut issue = scoped(id);
        issue.status = BoardStatus::ShippedVerified;
        issue.t_claim_ms = 1_000_000;
        issue.t_ship_ms = 1_600_000;
        issue.loc_changed = Some(180);
        issue.receipt_trailers = vec!["CleanroomCIReceiptV1: status=PASS".to_string()];
        issue
    }

    fn reasons(issue: &AtomicTaskIssue, policy: &BoardPolicyTomlV1) -> Vec<(String, String)> {
        collect_board_ledger_violations(issue, policy)
            .into_iter()
            .map(|v| {
                assert_eq!(v.exit_code, 78);
                assert_eq!(v.issue_id, issue.id);
                (v.invariant, v.reason)
            })
            .collect()
    }

    fn tracking(reason: &str) -> (String, String) {
        (
            "INV-BOARD-LEDGER-TRACKING-01".to_string(),
            reason.to_string(),
        )
    }

    #[test]
    fn scoped_cards_are_admitted_in_every_column() {
        for status in [
            BoardStatus::OpenBounty,
            BoardStatus::ScopedBenchmarked,
            BoardStatus::InFlight,
            BoardStatus::TribunalGate,
        ] {
            let mut issue = scoped("ACME-0001");
            issue.status = status;
            assert_eq!(validate_board_ledger_issue(&issue, &policy()), Ok(()));
        }
        assert_eq!(
            validate_board_ledger_issue(&shipped("ACME-0001.02-03"), &policy()),
            Ok(())
        );
    }

    #[test]
    fn admission_rejects_a_card_with_no_explicit_function() {
        let unscoped = AtomicTaskIssue::new_default("ACME-0002", "Defaulted", DoraTier::S);
        assert_eq!(unscoped.primary_function, None);
        assert_eq!(
            reasons(&unscoped, &policy()),
            [tracking(
                "primary_function is missing; set one of: Engineering, Design, Product, Security, QA & Release, Analytics, Docs"
            )]
        );

        let mut invented = scoped("ACME-0002");
        invented.primary_function = Some("Synergy".to_string());
        assert_eq!(
            reasons(&invented, &policy()),
            [tracking(
                "primary_function `Synergy` is not one of: Engineering, Design, Product, Security, QA & Release, Analytics, Docs"
            )]
        );
    }

    #[test]
    fn admission_requires_seats_everywhere_except_open_bounty() {
        let mut issue = scoped("ACME-0003");
        issue.assigned_seats = vec!["  ".to_string(), "@■ ".to_string()];
        assert_eq!(
            reasons(&issue, &policy()),
            [tracking(
                "assigned_seats is empty; only 01_OPEN_BOUNTY cards may be unassigned"
            )]
        );
        issue.status = BoardStatus::OpenBounty;
        assert_eq!(reasons(&issue, &policy()), []);
    }

    #[test]
    fn admission_rejects_foreign_or_malformed_ticket_ids_and_unknown_kinds() {
        for id in ["CHWG-0004", "ACME-4", "ACME-0004-CI-FAIL", "ACME-0004.1"] {
            assert_eq!(
                reasons(&scoped(id), &policy()),
                [tracking(&format!(
                    "ticket id `{id}` must match ^ACME-[0-9]{{4}}(?:\\.[0-9]{{2}}(?:-[0-9]{{2}})?)?$"
                ))]
            );
        }
        let mut issue = scoped("ACME-0004");
        issue.deliverable_kind = "vibes".to_string();
        assert_eq!(
            reasons(&issue, &policy()),
            [tracking(
                "deliverable_kind `vibes` is not allowed (allowed: code, artifact)"
            )]
        );

        let mut code_only = policy();
        code_only.board.ledger.allow_deliverable_kinds = vec!["code".to_string()];
        issue.deliverable_kind = "artifact".to_string();
        assert_eq!(
            reasons(&issue, &code_only),
            [tracking(
                "deliverable_kind `artifact` is not allowed (allowed: code)"
            )]
        );
    }

    #[test]
    fn task_files_without_deliverable_kind_parse_as_code_and_round_trip() {
        let mut artifact = scoped("ACME-0005");
        artifact.deliverable_kind = "artifact".to_string();
        let markdown = artifact.to_markdown();
        assert!(markdown.contains("\ndeliverable_kind: artifact\n"));
        assert_eq!(
            AtomicTaskIssue::from_markdown(&markdown)
                .unwrap()
                .deliverable_kind,
            "artifact"
        );

        let legacy = markdown.replace("deliverable_kind: artifact\n", "");
        assert!(!legacy.contains("deliverable_kind"));
        assert_eq!(
            AtomicTaskIssue::from_markdown(&legacy)
                .unwrap()
                .deliverable_kind,
            "code"
        );

        let mut as_json = serde_json::to_value(&artifact).unwrap();
        as_json.as_object_mut().unwrap().remove("deliverable_kind");
        let from_json: AtomicTaskIssue = serde_json::from_value(as_json).unwrap();
        assert_eq!(from_json.deliverable_kind, "code");
    }

    #[test]
    fn settlement_rejects_each_missing_ledger_input() {
        let mut unclaimed = shipped("ACME-0006");
        unclaimed.t_claim_ms = 0;
        unclaimed.t_ship_ms = 0;
        assert_eq!(
            reasons(&unclaimed, &policy()),
            [
                tracking("shipped card has no claim time (t_claim_ms is 0)"),
                tracking("shipped card needs t_ship_ms >= t_claim_ms (t_ship_ms 0, t_claim_ms 0)"),
            ]
        );

        let mut backwards = shipped("ACME-0006");
        backwards.t_ship_ms = 999_999;
        assert_eq!(
            reasons(&backwards, &policy()),
            [tracking(
                "shipped card needs t_ship_ms >= t_claim_ms (t_ship_ms 999999, t_claim_ms 1000000)"
            )]
        );

        let mut instant = shipped("ACME-0006");
        instant.t_ship_ms = instant.t_claim_ms;
        assert_eq!(reasons(&instant, &policy()), []);

        let mut unmeasured = shipped("ACME-0006");
        unmeasured.loc_changed = None;
        assert_eq!(
            reasons(&unmeasured, &policy()),
            [tracking(
                "shipped card has no loc_changed (record 0 for an artifact with no line count)"
            )]
        );

        let mut unreceipted = shipped("ACME-0006");
        unreceipted.receipt_trailers = vec![" ".to_string()];
        assert_eq!(
            reasons(&unreceipted, &policy()),
            [tracking(
                "shipped card has no receipt trailers (cryptographic_receipt)"
            )]
        );

        // The same gaps are fine on a card that has not shipped yet.
        unclaimed.status = BoardStatus::TribunalGate;
        unclaimed.loc_changed = None;
        unclaimed.receipt_trailers.clear();
        assert_eq!(reasons(&unclaimed, &policy()), []);
    }

    #[test]
    fn tier_lock_binds_code_but_never_rebands_an_artifact() {
        let mut inflated = shipped("ACME-0007");
        inflated.dora_tier = DoraTier::XL;
        inflated.loc_changed = Some(45);
        assert_eq!(
            reasons(&inflated, &policy()),
            [(
                "INV-TIER-LOCK-01".to_string(),
                "claimed tier XL exceeds tier S allowed for 45 LOC".to_string()
            )]
        );
        let code_proof = compute_velocity_proof_for_deliverable(
            DoraTier::XL,
            Some(45),
            "code",
            1_000_000,
            1_600_000,
        );
        assert_eq!(code_proof.effective_tier, DoraTier::S);
        assert!(code_proof.tier_downgraded);
        assert_eq!(code_proof.cycle_time_label, "10m 00s · 45 LOC");
        assert_eq!(
            code_proof,
            compute_velocity_proof(DoraTier::XL, Some(45), 1_000_000, 1_600_000)
        );

        inflated.deliverable_kind = "artifact".to_string();
        inflated.loc_changed = Some(0);
        assert_eq!(reasons(&inflated, &policy()), []);
        let artifact_proof = compute_velocity_proof_for_deliverable(
            DoraTier::XL,
            Some(0),
            "artifact",
            1_000_000,
            1_600_000,
        );
        assert_eq!(artifact_proof.effective_tier, DoraTier::XL);
        assert!(!artifact_proof.tier_downgraded);
        assert_eq!(artifact_proof.metric_b_active_baseline_hours, 112.0);
        assert_eq!(artifact_proof.cycle_time_label, "10m 00s · artifact");
    }

    #[test]
    fn switched_off_requirements_are_not_enforced() {
        let mut lax = policy();
        lax.board.ledger.require_scoping_on_add = false;
        lax.board.ledger.require_settlement_on_ship = false;
        let mut bare = AtomicTaskIssue::new_unscoped("ACME-0008", "Bare", DoraTier::XL);
        bare.status = BoardStatus::ShippedVerified;
        bare.loc_changed = Some(10);
        assert_eq!(reasons(&bare, &lax), []);
        assert_eq!(reasons(&bare, &policy()).len(), 6);
    }

    #[test]
    fn policy_privacy_entries_extend_the_built_in_guards() {
        let mut policy = policy();
        policy.board.privacy.private_locked_seats = vec!["legal".to_string()];
        policy.board.privacy.forbidden_public_substrings = vec!["Project Nightjar".to_string()];

        let mut issue = scoped("ACME-0009");
        issue.assigned_seats = vec!["@■ LEGAL#abc123".to_string()];
        issue.body = "Kickoff notes for Project Nightjar.".to_string();
        assert_eq!(issue.visibility, "private");
        assert_eq!(reasons(&issue, &policy), []);

        issue.visibility = "public".to_string();
        assert_eq!(
            reasons(&issue, &policy),
            [
                (
                    "INV-DEFAULT-PRIVATE-TASK-01".to_string(),
                    "seat `LEGAL` is locked to private by .chinwag/board.toml and cannot be published on a public board".to_string()
                ),
                (
                    "INV-PUBLIC-BOARD-REDACTION-01".to_string(),
                    "substring `Project Nightjar` is forbidden on public cards by .chinwag/board.toml".to_string()
                ),
            ]
        );
    }

    fn claim(ticket_id: &str, source: &str) -> TicketCardRef {
        TicketCardRef {
            ticket_id: ticket_id.to_string(),
            source: source.to_string(),
        }
    }

    #[test]
    fn duplicate_ticket_ids_are_rejected_across_repositories() {
        let distinct = [
            claim("ACME-0276", "acme-co/product#91"),
            claim("ACME-0276.01", "acme-co/product#92"),
            claim("ACME-0276.02", "acme-co/tasks#12"),
            claim("ACME-0276.02-01", "acme-co/tasks#13"),
            claim("not-a-ticket", "acme-co/tasks#14"),
            claim("not-a-ticket", "acme-co/tasks#15"),
        ];
        assert_eq!(validate_unique_ticket_ids(&distinct, "ACME"), Ok(()));

        let colliding = [
            claim("ACME-0276", "acme-co/product#91"),
            claim("ACME-0277.01", "acme-co/site#3"),
            claim("ACME-0276", "acme-co/tasks#40"),
            claim("ACME-0277.01", "acme-co/tasks#41"),
            claim("ACME-0278", "acme-co/tasks#42"),
        ];
        let violations = validate_unique_ticket_ids(&colliding, "ACME").unwrap_err();
        let summary: Vec<(&str, &str, &str, u8)> = violations
            .iter()
            .map(|v| {
                (
                    v.invariant.as_str(),
                    v.issue_id.as_str(),
                    v.reason.as_str(),
                    v.exit_code,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "INV-UNIQUE-TICKET-ID-01",
                    "ACME-0276",
                    "ticket id `ACME-0276` is claimed by 2 cards: acme-co/product#91, acme-co/tasks#40",
                    78
                ),
                (
                    "INV-UNIQUE-TICKET-ID-01",
                    "ACME-0277.01",
                    "ticket id `ACME-0277.01` is claimed by 2 cards: acme-co/site#3, acme-co/tasks#41",
                    78
                ),
            ]
        );
    }

    /// One item shaped exactly like `gh project item-list --format json` output, including
    /// the first-byte lowercasing that mangles `Δ` into two replacement characters.
    fn live_item(number: u64, repo: &str, title: &str, status: &str) -> Value {
        let shipped = status.starts_with("05");
        let mut item = json!({
            "id": format!("PVTI_{number}"),
            "title": title,
            "status": status,
            "assignees": ["someone"],
            "repository": format!("https://github.com/{repo}"),
            "content": {
                "type": "Issue",
                "number": number,
                "repository": repo,
                "title": title,
                "url": format!("https://github.com/{repo}/issues/{number}"),
                "body": "body",
            },
            "dORA Baseline": "Tier M · 27h Eng / 3.4d Cal (100–400 LOC)",
            "baseline Hours": 27,
            "execution Mode": "Triad · 150 Cr",
            "function / Team": "Engineering",
            "active Seats": "■ DEV · ■ QA · ■ DOCS",
        });
        if shipped {
            let fields = item.as_object_mut().unwrap();
            fields.insert("credits Used".to_string(), json!(150));
            fields.insert("net Hours Saved".to_string(), json!(26.68));
            fields.insert("chinwag Cycle Time".to_string(), json!("19m 00s · 180 LOC"));
            fields.insert(
                "\u{fffd}\u{fffd} Speedup vs. DORA".to_string(),
                json!("🔥 10x–49x Faster vs. DORA"),
            );
            fields.insert(
                "verification Receipt".to_string(),
                json!("Recorded checks green"),
            );
            fields.insert(
                "cryptographic Receipt".to_string(),
                json!("✓ed25519 · H1+H2"),
            );
        }
        item
    }

    const SCOPED: &str = "02 · 📐 SCOPED & BENCHMARKED";
    const IN_FLIGHT: &str = "03 · ⚡ IN FLIGHT — CLOCK LIVE";
    const SHIPPED: &str = "05 · ✓ SHIPPED — Δ VERIFIED";

    fn snapshot(items: Vec<Value>) -> LiveBoardSnapshot {
        let total = items.len();
        let mut items =
            parse_live_project_items(&json!({ "items": items, "totalCount": total })).unwrap();
        for item in &mut items {
            let shipped = item.status() == Some(SHIPPED);
            item.issue_state = Some(if shipped { "CLOSED" } else { "OPEN" }.to_string());
        }
        LiveBoardSnapshot { items }
    }

    fn live_reasons(snapshot: &LiveBoardSnapshot) -> Vec<(String, String, String)> {
        collect_live_board_violations(snapshot, &policy())
            .into_iter()
            .map(|v| (v.invariant, v.issue_id, v.reason))
            .collect()
    }

    fn live_tracking(id: &str, reason: &str) -> (String, String, String) {
        (
            "INV-BOARD-LEDGER-TRACKING-01".to_string(),
            id.to_string(),
            reason.to_string(),
        )
    }

    #[test]
    fn fully_tracked_live_board_has_no_violations() {
        let board = snapshot(vec![
            live_item(1, "acme-co/product", "[ACME-0001] Shipped work", SHIPPED),
            live_item(2, "acme-co/tasks", "ACME-0002: Queued work", SCOPED),
            live_item(3, "acme-co/product", "[ACME-0002.01] Sub-task", IN_FLIGHT),
        ]);
        assert_eq!(
            board.items[0].field("Δ Speedup vs. DORA"),
            Some(&json!("🔥 10x–49x Faster vs. DORA"))
        );
        assert!(board.items[0].field("DORA Baseline").is_some());
        assert_eq!(board.items[1].field("Credits Used"), None);
        assert_eq!(live_reasons(&board), []);
    }

    #[test]
    fn open_bounty_cards_need_no_active_seats() {
        let mut bounty = live_item(
            4,
            "acme-co/product",
            "[ACME-0004] Up for grabs",
            "01 · 🌱 OPEN BOUNTY (+500 CR)",
        );
        bounty.as_object_mut().unwrap().remove("active Seats");
        bounty["execution Mode"] = json!("Open bounty");
        assert_eq!(live_reasons(&snapshot(vec![bounty])), []);
    }

    #[test]
    fn orphan_and_unknown_status_items_are_violations() {
        let mut orphan = live_item(5, "acme-co/product", "[ACME-0005] Orphan", SCOPED);
        orphan.as_object_mut().unwrap().remove("status");
        let stray = live_item(6, "acme-co/product", "[ACME-0006] Stray", "Todo");
        assert_eq!(
            live_reasons(&snapshot(vec![orphan, stray])),
            [
                live_tracking("ACME-0005", "acme-co/product#5 is an orphan with no Status"),
                live_tracking(
                    "ACME-0006",
                    "acme-co/product#6 has Status `Todo`, which is not a ledger column"
                ),
            ]
        );
    }

    #[test]
    fn issue_state_must_agree_with_the_shipped_column() {
        let mut board = snapshot(vec![
            live_item(7, "acme-co/product", "[ACME-0007] Closed early", IN_FLIGHT),
            live_item(
                8,
                "acme-co/product",
                "[ACME-0008] Shipped but open",
                SHIPPED,
            ),
            live_item(9, "acme-co/tasks", "[ACME-0009] Unknown state", SCOPED),
        ]);
        board.items[0].issue_state = Some("CLOSED".to_string());
        board.items[1].issue_state = Some("OPEN".to_string());
        board.items[2].issue_state = None;
        assert_eq!(
            live_reasons(&board),
            [
                live_tracking(
                    "ACME-0007",
                    "acme-co/product#7 is closed but its card is not in `05 · ✓ SHIPPED — Δ VERIFIED`"
                ),
                live_tracking(
                    "ACME-0008",
                    "acme-co/product#8 is open but its card is in `05 · ✓ SHIPPED — Δ VERIFIED`"
                ),
                live_tracking("ACME-0009", "acme-co/tasks#9 issue state could not be read"),
            ]
        );
    }

    #[test]
    fn every_missing_scoping_field_is_reported() {
        let mut bare = live_item(10, "acme-co/product", "[ACME-0010] Raw card", SCOPED);
        let fields = bare.as_object_mut().unwrap();
        for key in [
            "dORA Baseline",
            "baseline Hours",
            "execution Mode",
            "function / Team",
        ] {
            fields.remove(key);
        }
        fields.insert("active Seats".to_string(), json!("  "));
        assert_eq!(
            live_reasons(&snapshot(vec![bare])),
            [
                live_tracking(
                    "ACME-0010",
                    "acme-co/product#10 is missing scoping field `DORA Baseline`"
                ),
                live_tracking(
                    "ACME-0010",
                    "acme-co/product#10 is missing scoping field `Baseline Hours`"
                ),
                live_tracking(
                    "ACME-0010",
                    "acme-co/product#10 is missing scoping field `Execution Mode`"
                ),
                live_tracking(
                    "ACME-0010",
                    "acme-co/product#10 is missing scoping field `Function / Team`"
                ),
                live_tracking(
                    "ACME-0010",
                    "acme-co/product#10 is missing scoping field `Active Seats`"
                ),
            ]
        );
    }

    #[test]
    fn shipped_cards_must_be_fully_settled() {
        let mut blank = live_item(11, "acme-co/product", "[ACME-0011] Blank ledger", SHIPPED);
        let fields = blank.as_object_mut().unwrap();
        for key in [
            "credits Used",
            "net Hours Saved",
            "chinwag Cycle Time",
            "\u{fffd}\u{fffd} Speedup vs. DORA",
            "verification Receipt",
            "cryptographic Receipt",
        ] {
            fields.remove(key);
        }
        let mut stale = live_item(12, "acme-co/product", "[ACME-0012] Stale ledger", SHIPPED);
        stale["credits Used"] = json!(100);
        stale["chinwag Cycle Time"] = json!("In flight · Clock running");
        stale["\u{fffd}\u{fffd} Speedup vs. DORA"] = json!("⏱️ Clock Running — In Flight");
        let mut queued = live_item(13, "acme-co/product", "[ACME-0013] Queued ledger", SHIPPED);
        queued["execution Mode"] = json!("Open bounty");
        queued["credits Used"] = json!(0);
        queued["chinwag Cycle Time"] = json!("Queued · Ready");
        queued["\u{fffd}\u{fffd} Speedup vs. DORA"] = json!("📐 Baseline Locked — Queued");

        let settled = |n: u64, field: &str| {
            live_tracking(
                &format!("ACME-00{n}"),
                &format!("acme-co/product#{n} is shipped but settlement field `{field}` is empty"),
            )
        };
        assert_eq!(
            live_reasons(&snapshot(vec![blank, stale, queued])),
            [
                settled(11, "Credits Used"),
                settled(11, "Net Hours Saved"),
                settled(11, "Chinwag Cycle Time"),
                settled(11, "Δ Speedup vs. DORA"),
                settled(11, "Verification Receipt"),
                settled(11, "Cryptographic Receipt"),
                live_tracking(
                    "ACME-0012",
                    "acme-co/product#12 `Credits Used` is 100 but `Execution Mode` is `Triad · 150 Cr`"
                ),
                live_tracking(
                    "ACME-0012",
                    "acme-co/product#12 is shipped but `Chinwag Cycle Time` still reads `In flight · Clock running`"
                ),
                live_tracking(
                    "ACME-0012",
                    "acme-co/product#12 is shipped but `Δ Speedup vs. DORA` still reads `⏱️ Clock Running — In Flight`"
                ),
                live_tracking(
                    "ACME-0013",
                    "acme-co/product#13 `Credits Used` is 0 but `Execution Mode` is `Open bounty`"
                ),
                live_tracking(
                    "ACME-0013",
                    "acme-co/product#13 is shipped but `Chinwag Cycle Time` still reads `Queued · Ready`"
                ),
                live_tracking(
                    "ACME-0013",
                    "acme-co/product#13 is shipped but `Δ Speedup vs. DORA` still reads `📐 Baseline Locked — Queued`"
                ),
            ]
        );
    }

    #[test]
    fn raw_bypass_cards_foreign_repos_and_drafts_are_violations() {
        let raw = live_item(14, "acme-co/product", "Fix the flaky build", SCOPED);
        let foreign = live_item(15, "elsewhere/repo", "[ACME-0015] Wrong repo", SCOPED);
        let mut draft = live_item(16, "acme-co/product", "[ACME-0016] Draft", SCOPED);
        draft["content"] = json!({ "type": "DraftIssue", "title": "[ACME-0016] Draft" });
        assert_eq!(
            live_reasons(&snapshot(vec![raw.clone(), foreign, draft])),
            [
                live_tracking(
                    "acme-co/product#14",
                    "acme-co/product#14 title `Fix the flaky build` does not start with a `ACME-NNNN` ticket id; the card was not created through the board gate"
                ),
                live_tracking(
                    "ACME-0015",
                    "elsewhere/repo#15 lives in `elsewhere/repo`, which is not in board.linked_repos"
                ),
                live_tracking(
                    "ACME-0016",
                    "PVTI_16 is a DraftIssue item; only repository issues are tracked"
                ),
            ]
        );

        let mut tolerant = policy();
        tolerant.board.disallow_raw_bypass = false;
        assert_eq!(
            collect_live_board_violations(&snapshot(vec![raw]), &tolerant),
            []
        );
    }

    #[test]
    fn duplicate_live_ticket_ids_across_repos_break_uniqueness() {
        let board = snapshot(vec![
            live_item(91, "acme-co/product", "[ACME-0276] First claim", SCOPED),
            live_item(40, "acme-co/tasks", "ACME-0276: Second claim", SCOPED),
            live_item(92, "acme-co/product", "[ACME-0276.01] Sub-task", SCOPED),
        ]);
        assert_eq!(
            live_reasons(&board),
            [(
                "INV-UNIQUE-TICKET-ID-01".to_string(),
                "ACME-0276".to_string(),
                "ticket id `ACME-0276` is claimed by 2 cards: acme-co/product#91, acme-co/tasks#40"
                    .to_string()
            )]
        );
    }

    #[test]
    fn truncated_item_list_is_refused() {
        let list = json!({
            "items": [live_item(1, "acme-co/product", "[ACME-0001] One", SCOPED)],
            "totalCount": 301
        });
        assert_eq!(
            parse_live_project_items(&list),
            Err("project has 301 items but only 1 were returned; raise the item limit".to_string())
        );
        assert_eq!(
            parse_live_project_items(&json!({ "totalCount": 0 })),
            Err("project item list has no `items` array".to_string())
        );
    }

    #[test]
    fn execution_mode_labels_price_their_credits() {
        assert_eq!(credits_for_execution_mode("Triad · 150 Cr"), Some(150));
        assert_eq!(credits_for_execution_mode("CI Fix · 50 Cr"), Some(50));
        assert_eq!(credits_for_execution_mode("Open bounty"), None);
        assert_eq!(credits_for_execution_mode("Lots · many Cr"), None);
    }

    /// A workspace laid out as `<root>/.chinwag/tasks/issues`, with an optional policy.
    fn workspace(label: &str, policy: Option<&BoardPolicyTomlV1>) -> PathBuf {
        let id = NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "chinwag-board-ledger-{label}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join(".chinwag/tasks/issues")).unwrap();
        if let Some(policy) = policy {
            fs::write(root.join(".chinwag/board.toml"), policy.to_toml_string()).unwrap();
        }
        root
    }

    fn write_issue(root: &Path, file_stem: &str, issue: &AtomicTaskIssue) {
        fs::write(
            root.join(format!(".chinwag/tasks/issues/{file_stem}.md")),
            issue.to_markdown(),
        )
        .unwrap();
    }

    fn read_issue(root: &Path, id: &str) -> AtomicTaskIssue {
        let raw = fs::read_to_string(root.join(format!(".chinwag/tasks/issues/{id}.md"))).unwrap();
        AtomicTaskIssue::from_markdown(&raw).unwrap()
    }

    fn verify(
        root: &Path,
        extra: &[&str],
        live: &dyn Fn(&BoardPolicyTomlV1) -> Result<LiveBoardSnapshot, String>,
    ) -> (u8, Value) {
        let mut args = vec![
            "verify-ledger".to_string(),
            "--json".to_string(),
            "--workspace-root".to_string(),
            root.to_string_lossy().to_string(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_string()));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_board_verify_ledger_with(&args, &mut out, &mut err, live);
        assert_eq!(err, b"", "--json keeps stderr quiet");
        (code, serde_json::from_slice(&out).expect("report is JSON"))
    }

    fn no_live(_: &BoardPolicyTomlV1) -> Result<LiveBoardSnapshot, String> {
        panic!("offline verify-ledger must not query the live board")
    }

    #[test]
    fn verify_ledger_fails_closed_without_a_valid_policy() {
        let root = workspace("verify-missing", None);
        let (code, report) = verify(&root, &[], &no_live);
        assert_eq!(code, 78);
        assert_eq!(report["ok"], false);
        assert_eq!(report["invariant"], "INV-BOARD-LEDGER-TRACKING-01");
        assert_eq!(report["checked_items"], 0);
        assert_eq!(report["violations"].as_array().unwrap().len(), 1);
        assert_eq!(report["violations"][0]["issue_id"], ".chinwag/board.toml");
        assert_eq!(report["violations"][0]["exit_code"], 78);
        assert!(
            report["violations"][0]["reason"]
                .as_str()
                .unwrap()
                .ends_with("is missing; create it with `chinwag board init`")
        );

        fs::write(root.join(".chinwag/board.toml"), "schema = 1").unwrap();
        let (code, report) = verify(&root, &["--live"], &no_live);
        assert_eq!(code, 78);
        assert!(
            report["violations"][0]["reason"]
                .as_str()
                .unwrap()
                .starts_with("board policy is not valid TOML")
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_ledger_refuses_to_certify_a_weakened_policy() {
        let mut weak = policy();
        weak.board.ledger.require_scoping_on_add = false;
        let root = workspace("verify-weak", Some(&weak));
        let (code, report) = verify(&root, &[], &no_live);
        assert_eq!(code, 78);
        assert_eq!(
            report["violations"][0]["reason"],
            "policy does not enforce the ledger: board.ledger.require_scoping_on_add is false"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_ledger_audits_local_task_files() {
        let root = workspace("verify-local", Some(&policy()));
        let (code, report) = verify(&root, &[], &no_live);
        assert_eq!(
            (code, &report["ok"], &report["checked_items"]),
            (0, &json!(true), &json!(0))
        );

        write_issue(&root, "ACME-0001", &shipped("ACME-0001"));
        write_issue(&root, "ACME-0002", &scoped("ACME-0002"));
        let (code, report) = verify(&root, &[], &no_live);
        assert_eq!(code, 0);
        assert_eq!(report["ok"], true);
        assert_eq!(report["checked_items"], 2);
        assert_eq!(report["violations"], json!([]));

        let mut unsettled = shipped("ACME-0003");
        unsettled.loc_changed = None;
        write_issue(&root, "ACME-0003", &unsettled);
        write_issue(&root, "ACME-0002-copy", &scoped("ACME-0002"));
        fs::write(
            root.join(".chinwag/tasks/issues/broken.md"),
            "no frontmatter",
        )
        .unwrap();
        let (code, report) = verify(&root, &[], &no_live);
        assert_eq!(code, 78);
        assert_eq!(report["ok"], false);
        assert_eq!(report["checked_items"], 5);
        let found: Vec<(&str, &str)> = report["violations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    v["invariant"].as_str().unwrap(),
                    v["issue_id"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            found,
            [
                ("INV-BOARD-LEDGER-TRACKING-01", "ACME-0003"),
                ("INV-BOARD-LEDGER-TRACKING-01", "broken.md"),
                ("INV-UNIQUE-TICKET-ID-01", "ACME-0002"),
            ]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_ledger_live_audits_the_board_and_fails_closed_on_query_errors() {
        let root = workspace("verify-live", Some(&policy()));
        write_issue(&root, "ACME-0001", &scoped("ACME-0001"));

        let clean = |p: &BoardPolicyTomlV1| {
            assert_eq!(
                (p.board.org.as_str(), p.board.project_number),
                ("acme-co", 7)
            );
            Ok(snapshot(vec![
                live_item(1, "acme-co/product", "[ACME-0001] Tracked", SCOPED),
                live_item(2, "acme-co/tasks", "[ACME-0002] Shipped", SHIPPED),
            ]))
        };
        let (code, report) = verify(&root, &["--live"], &clean);
        assert_eq!(code, 0);
        assert_eq!(report["ok"], true);
        assert_eq!(report["live"], true);
        assert_eq!(report["checked_items"], 3);
        assert_eq!(report["checked_live_items"], 2);

        let dirty = |_: &BoardPolicyTomlV1| {
            Ok(snapshot(vec![live_item(
                3,
                "acme-co/product",
                "Created with gh issue create",
                SCOPED,
            )]))
        };
        let (code, report) = verify(&root, &["--live"], &dirty);
        assert_eq!(code, 78);
        assert_eq!(report["checked_items"], 2);
        assert_eq!(report["violations"][0]["issue_id"], "acme-co/product#3");

        let down = |_: &BoardPolicyTomlV1| Err("gh: not logged in".to_string());
        let (code, report) = verify(&root, &["--live"], &down);
        assert_eq!(code, 78);
        assert_eq!(report["checked_items"], 1);
        assert_eq!(
            report["violations"][0]["reason"],
            "live board could not be audited: gh: not logged in"
        );
        let _ = fs::remove_dir_all(&root);
    }

    fn board(root: &Path, args: &[&str]) -> (u8, String, String) {
        let mut argv: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
        argv.extend(["--repo".to_string(), root.to_string_lossy().to_string()]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_board_cli(&argv, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).to_string(),
            String::from_utf8_lossy(&err).to_string(),
        )
    }

    fn rejection(stdout: &str) -> (String, String) {
        let payload: Value = serde_json::from_str(stdout.trim()).expect("rejection is JSON");
        assert_eq!(payload["ok"], false);
        assert_eq!(payload["exit_code"], 78);
        (
            payload["invariant"].as_str().unwrap().to_string(),
            payload["reason"].as_str().unwrap().to_string(),
        )
    }

    #[test]
    fn board_commands_in_a_workspace_require_the_policy_file() {
        let root = workspace("cli-missing-policy", None);
        for args in [
            &[
                "add",
                "CHWG-0300",
                "02",
                "--function",
                "Engineering",
                "--seats",
                "DEV",
            ][..],
            &["move", "CHWG-0300", "03"],
            &["push", "--dry-run"],
            &["sync", "--dry-run"],
            &["verify-ledger"],
        ] {
            let (code, _, stderr) = board(&root, args);
            assert_eq!(code, 78, "{args:?}: {stderr}");
            assert!(stderr.contains("INV-BOARD-LEDGER-TRACKING-01"), "{args:?}");
            assert!(stderr.contains("board.toml"), "{args:?}: {stderr}");
        }
        assert!(!root.join(".chinwag/tasks/issues/CHWG-0300.md").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn board_init_creates_a_starter_policy_once() {
        let root = workspace("cli-init", None);
        let (code, stdout, stderr) = board(
            &root,
            &[
                "init",
                "--org",
                "acme-co",
                "--public-repo",
                "acme-co/product",
                "--private-repo",
                "acme-co/tasks",
                "--ticket-prefix",
                "ACME",
            ],
        );
        assert_eq!(code, 0, "{stderr}");
        let payload: Value = serde_json::from_str(&stdout).unwrap();
        let policy_path = root.join(".chinwag/board.toml");
        assert_eq!(
            payload["board_policy_created"],
            json!(policy_path.to_string_lossy())
        );
        let created = BoardPolicyTomlV1::load(&root).unwrap();
        assert_eq!(created.board.org, "acme-co");
        assert_eq!(created.board.ticket_prefix, "ACME");
        assert_eq!(created.board.project_id, None);
        assert_eq!(
            created.board.linked_repos,
            ["acme-co/product", "acme-co/tasks"]
        );
        assert_eq!(created.ledger_tracking_gaps(), Vec::<String>::new());

        let (code, stdout, _) = board(&root, &["init", "--org", "other-org"]);
        assert_eq!(code, 0);
        let payload: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(payload["board_policy_created"], Value::Null);
        assert_eq!(BoardPolicyTomlV1::load(&root), Ok(created));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn board_add_and_move_enforce_scoping_then_settlement() {
        let root = workspace("cli-add-move", Some(&policy_with_prefix("CHWG")));
        let issue_path = root.join(".chinwag/tasks/issues/CHWG-0300.md");

        let (code, stdout, _) = board(&root, &["add", "CHWG-0300", "02", "--seats", "DEV,QA"]);
        assert_eq!(code, 78);
        assert_eq!(
            rejection(&stdout),
            (
                "INV-BOARD-LEDGER-TRACKING-01".to_string(),
                "primary_function is missing; set one of: Engineering, Design, Product, Security, QA & Release, Analytics, Docs".to_string()
            )
        );
        let (code, stdout, _) = board(&root, &["add", "CHWG-0300", "02", "--function", "Docs"]);
        assert_eq!(code, 78);
        assert_eq!(
            rejection(&stdout).1,
            "assigned_seats is empty; only 01_OPEN_BOUNTY cards may be unassigned"
        );
        let (code, stdout, _) = board(&root, &["add", "ACME-0300", "02"]);
        assert_eq!(code, 78);
        assert_eq!(
            rejection(&stdout).1,
            "ticket id `ACME-0300` must match ^CHWG-[0-9]{4}(?:\\.[0-9]{2}(?:-[0-9]{2})?)?$"
        );
        assert!(!issue_path.exists(), "a rejected add writes nothing");

        let (code, _, stderr) = board(
            &root,
            &[
                "add",
                "CHWG-0300",
                "02",
                "--function",
                "Docs",
                "--seats",
                "DEV, QA",
                "--deliverable-kind",
                "artifact",
                "--tier",
                "L",
                "--title",
                "Write the operator guide",
            ],
        );
        assert_eq!(code, 0, "{stderr}");
        let added = read_issue(&root, "CHWG-0300");
        assert_eq!(added.status, BoardStatus::ScopedBenchmarked);
        assert_eq!(added.primary_function.as_deref(), Some("Docs"));
        assert_eq!(added.assigned_seats, ["DEV", "QA"]);
        assert_eq!(added.deliverable_kind, "artifact");
        assert_eq!(added.dora_tier, DoraTier::L);
        assert_eq!((added.t_claim_ms, added.t_ship_ms), (0, 0));
        assert_eq!(added.receipt_trailers, Vec::<String>::new());

        let (code, stdout, _) = board(&root, &["move", "CHWG-0300", "05", "--loc-changed", "0"]);
        assert_eq!(code, 78);
        assert_eq!(
            rejection(&stdout).1,
            "shipped card has no claim time (t_claim_ms is 0)"
        );
        assert_eq!(
            read_issue(&root, "CHWG-0300"),
            added,
            "a rejected move writes nothing"
        );

        let (code, _, stderr) = board(&root, &["move", "CHWG-0300", "03"]);
        assert_eq!(code, 0, "{stderr}");
        let claimed = read_issue(&root, "CHWG-0300");
        assert_eq!(claimed.status, BoardStatus::InFlight);
        assert!(
            claimed.t_claim_ms > 1_700_000_000_000,
            "claim clock started"
        );
        assert_eq!(claimed.t_ship_ms, 0);

        let (code, stdout, _) = board(&root, &["move", "CHWG-0300", "05"]);
        assert_eq!(code, 78);
        assert_eq!(
            rejection(&stdout).1,
            "shipped card has no loc_changed (record 0 for an artifact with no line count)"
        );
        let (code, stdout, _) = board(&root, &["move", "CHWG-0300", "05", "--loc-changed", "0"]);
        assert_eq!(code, 78);
        assert_eq!(
            rejection(&stdout).1,
            "shipped card has no receipt trailers (cryptographic_receipt)"
        );
        assert_eq!(read_issue(&root, "CHWG-0300"), claimed);

        let mut receipted = claimed.clone();
        receipted
            .receipt_trailers
            .push("CleanroomCIReceiptV1: status=PASS gate=H2".to_string());
        write_issue(&root, "CHWG-0300", &receipted);
        let (code, _, stderr) = board(&root, &["move", "CHWG-0300", "05", "--loc-changed", "0"]);
        assert_eq!(code, 0, "{stderr}");
        let settled = read_issue(&root, "CHWG-0300");
        assert_eq!(settled.status, BoardStatus::ShippedVerified);
        assert_eq!(settled.t_claim_ms, claimed.t_claim_ms);
        assert!(settled.t_ship_ms >= settled.t_claim_ms);
        assert_eq!(settled.loc_changed, Some(0));
        assert_eq!(settled.dora_tier, DoraTier::L, "an artifact keeps its tier");
        assert_eq!(
            validate_board_ledger_issue(&settled, &policy_with_prefix("CHWG")),
            Ok(())
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn board_move_refuses_a_ticket_id_already_claimed_by_another_file() {
        let root = workspace("cli-move-duplicate", Some(&policy_with_prefix("CHWG")));
        write_issue(&root, "CHWG-0310", &scoped("CHWG-0310"));
        write_issue(&root, "CHWG-0311", &scoped("CHWG-0310"));
        let (code, stdout, _) = board(&root, &["move", "CHWG-0310", "02"]);
        assert_eq!(code, 78);
        let (invariant, reason) = rejection(&stdout);
        assert_eq!(invariant, "INV-UNIQUE-TICKET-ID-01");
        assert_eq!(
            reason,
            "ticket id `CHWG-0310` is claimed by 2 cards: issues/CHWG-0311.md, issues/CHWG-0310.md"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn board_push_enforces_the_ledger_and_the_policy_org() {
        let root = workspace("cli-push", Some(&policy_with_prefix("CHWG")));
        write_issue(&root, "CHWG-0320", &scoped("CHWG-0320"));
        write_issue(&root, "CHWG-0321", &shipped("CHWG-0321"));
        let (code, stdout, stderr) = board(&root, &["push", "--dry-run"]);
        assert_eq!(code, 0, "{stderr}");
        let payload: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(payload["issue_count"], 2);

        let (code, stdout, _) = board(&root, &["push", "--dry-run", "--org", "someone-else"]);
        assert_eq!(code, 78);
        assert_eq!(
            rejection(&stdout).1,
            "`--org someone-else` is not the organization governed by the board policy (`acme-co`)"
        );

        let unscoped = AtomicTaskIssue::new_default("CHWG-0322", "Raw card", DoraTier::S);
        write_issue(&root, "CHWG-0322", &unscoped);
        let (code, stdout, _) = board(&root, &["sync", "--dry-run"]);
        assert_eq!(code, 78);
        assert!(
            rejection(&stdout)
                .1
                .starts_with("primary_function is missing")
        );

        write_issue(&root, "CHWG-0322", &scoped("CHWG-0320"));
        let (code, stdout, _) = board(&root, &["push", "--dry-run"]);
        assert_eq!(code, 78);
        assert_eq!(rejection(&stdout).0, "INV-UNIQUE-TICKET-ID-01");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn live_push_from_a_detached_tasks_dir_is_refused_before_any_network_call() {
        let detached = std::env::temp_dir().join(format!(
            "chinwag-board-ledger-detached-{}-{}",
            std::process::id(),
            NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(detached.join("issues")).unwrap();
        let tasks_dir = detached.to_string_lossy().to_string();
        assert_eq!(resolve_board_policy(&[], &detached), Ok(None));

        for sub in ["push", "sync", "sync-loop"] {
            let args: Vec<String> = [sub, "--tasks-dir", &tasks_dir, "--live"]
                .iter()
                .map(|arg| (*arg).to_string())
                .collect();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            assert_eq!(run_board_cli(&args, &mut out, &mut err), 78, "{sub}");
            assert_eq!(
                rejection(&String::from_utf8_lossy(&out)).1,
                "a live board mutation requires `.chinwag/board.toml`; run from a workspace or pass `--workspace-root`",
                "{sub}"
            );
        }
        assert_eq!(
            push_github_project_v2_live(&detached, &[], "acme-co"),
            Err("INV-BOARD-LEDGER-TRACKING-01 on .chinwag/board.toml: a live board mutation requires `.chinwag/board.toml`; run from a workspace or pass `--workspace-root`".to_string())
        );
        let _ = fs::remove_dir_all(&detached);
    }
}
