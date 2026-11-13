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

//! Declarative board policy loaded from `<workspace_root>/.chinwag/board.toml`
//! (`chinwag.board.policy.v1`). Every org, repository, seat, and ticket prefix that the
//! ledger gate enforces comes from this file; nothing customer-specific is compiled in.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub const BOARD_POLICY_SCHEMA_V1: &str = "chinwag.board.policy.v1";

/// Policy location relative to the workspace root.
pub const BOARD_POLICY_RELATIVE_PATH: &str = ".chinwag/board.toml";

pub const INV_BOARD_LEDGER_TRACKING: &str = "INV-BOARD-LEDGER-TRACKING-01";
pub const INV_UNIQUE_TICKET_ID: &str = "INV-UNIQUE-TICKET-ID-01";

/// Source-code deliverable: `loc_changed` is a diff size and locks the DORA tier.
pub const DELIVERABLE_KIND_CODE: &str = "code";
/// Non-code deliverable: `loc_changed` is an artifact size and never rebands the DORA tier.
pub const DELIVERABLE_KIND_ARTIFACT: &str = "artifact";

/// Kinds whose settlement semantics the engine defines. A policy may allow any subset.
pub const KNOWN_DELIVERABLE_KINDS: [&str; 2] = [DELIVERABLE_KIND_CODE, DELIVERABLE_KIND_ARTIFACT];

const MAX_TICKET_PREFIX_LEN: usize = 16;

#[must_use]
pub fn default_deliverable_kind() -> String {
    DELIVERABLE_KIND_CODE.to_string()
}

/// Scoping field a card must carry from the moment it is admitted to the board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopingField {
    DoraTier,
    BaselineHours,
    ExecutionMode,
    FunctionTeam,
    ActiveSeats,
}

impl ScopingField {
    pub const ALL: [Self; 5] = [
        Self::DoraTier,
        Self::BaselineHours,
        Self::ExecutionMode,
        Self::FunctionTeam,
        Self::ActiveSeats,
    ];

    /// Key used in `[board.ledger] required_add_fields`.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::DoraTier => "dora_tier",
            Self::BaselineHours => "baseline_hours",
            Self::ExecutionMode => "execution_mode",
            Self::FunctionTeam => "function_team",
            Self::ActiveSeats => "active_seats",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.key() == raw)
    }

    /// Project field that carries this value on the live board.
    #[must_use]
    pub fn board_field_name(self) -> &'static str {
        match self {
            Self::DoraTier => "DORA Baseline",
            Self::BaselineHours => "Baseline Hours",
            Self::ExecutionMode => "Execution Mode",
            Self::FunctionTeam => "Function / Team",
            Self::ActiveSeats => "Active Seats",
        }
    }
}

/// Settlement field a card must carry before it may sit in the shipped column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettlementField {
    TClaimMs,
    TShipMs,
    LocChanged,
    CreditsUsed,
    NetHoursSaved,
    ChinwagCycleTime,
    SpeedupVsDora,
    VerificationReceipt,
    CryptographicReceipt,
}

impl SettlementField {
    pub const ALL: [Self; 9] = [
        Self::TClaimMs,
        Self::TShipMs,
        Self::LocChanged,
        Self::CreditsUsed,
        Self::NetHoursSaved,
        Self::ChinwagCycleTime,
        Self::SpeedupVsDora,
        Self::VerificationReceipt,
        Self::CryptographicReceipt,
    ];

    /// Key used in `[board.ledger] required_ship_fields`.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::TClaimMs => "t_claim_ms",
            Self::TShipMs => "t_ship_ms",
            Self::LocChanged => "loc_changed",
            Self::CreditsUsed => "credits_used",
            Self::NetHoursSaved => "net_hours_saved",
            Self::ChinwagCycleTime => "chinwag_cycle_time",
            Self::SpeedupVsDora => "speedup_vs_dora",
            Self::VerificationReceipt => "verification_receipt",
            Self::CryptographicReceipt => "cryptographic_receipt",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.key() == raw)
    }

    /// Project field that carries this value on the live board. The claim clock, ship clock,
    /// and diff size live only in the task file, so they have no board field.
    #[must_use]
    pub fn board_field_name(self) -> Option<&'static str> {
        match self {
            Self::TClaimMs | Self::TShipMs | Self::LocChanged => None,
            Self::CreditsUsed => Some("Credits Used"),
            Self::NetHoursSaved => Some("Net Hours Saved"),
            Self::ChinwagCycleTime => Some("Chinwag Cycle Time"),
            Self::SpeedupVsDora => Some("Δ Speedup vs. DORA"),
            Self::VerificationReceipt => Some("Verification Receipt"),
            Self::CryptographicReceipt => Some("Cryptographic Receipt"),
        }
    }
}

/// Root of `.chinwag/board.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardPolicyTomlV1 {
    pub schema: String,
    pub board: BoardPolicyBoardV1,
}

/// `[board]`: which project and repositories the policy governs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardPolicyBoardV1 {
    pub org: String,
    pub project_number: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub public_repo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_repo: Option<String>,
    pub linked_repos: Vec<String>,
    pub ticket_prefix: String,
    pub disallow_raw_bypass: bool,
    pub ledger: BoardLedgerPolicyV1,
    #[serde(default)]
    pub privacy: BoardPrivacyPolicyV1,
}

/// `[board.ledger]`: what a card must carry when it is added and when it ships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardLedgerPolicyV1 {
    pub require_scoping_on_add: bool,
    pub require_settlement_on_ship: bool,
    pub allow_deliverable_kinds: Vec<String>,
    pub required_add_fields: Vec<String>,
    pub required_ship_fields: Vec<String>,
}

/// `[board.privacy]`: customer additions to the built-in public-board safety guards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardPrivacyPolicyV1 {
    #[serde(default)]
    pub private_locked_seats: Vec<String>,
    #[serde(default)]
    pub forbidden_public_substrings: Vec<String>,
}

/// Why a policy could not be loaded. Every variant fails the gate closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardPolicyError {
    Missing { path: PathBuf },
    Unreadable { path: PathBuf, detail: String },
    Malformed { detail: String },
    Invalid { problems: Vec<String> },
}

impl fmt::Display for BoardPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { path } => write!(
                f,
                "board policy `{}` is missing; create it with `chinwag board init`",
                path.display()
            ),
            Self::Unreadable { path, detail } => {
                write!(
                    f,
                    "board policy `{}` is unreadable: {detail}",
                    path.display()
                )
            }
            Self::Malformed { detail } => write!(f, "board policy is not valid TOML: {detail}"),
            Self::Invalid { problems } => {
                write!(f, "board policy is invalid: {}", problems.join("; "))
            }
        }
    }
}

impl std::error::Error for BoardPolicyError {}

impl BoardPolicyTomlV1 {
    #[must_use]
    pub fn policy_path(workspace_root: &Path) -> PathBuf {
        workspace_root.join(BOARD_POLICY_RELATIVE_PATH)
    }

    /// Loads and validates `<workspace_root>/.chinwag/board.toml`.
    pub fn load(workspace_root: &Path) -> Result<Self, BoardPolicyError> {
        let path = Self::policy_path(workspace_root);
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BoardPolicyError::Missing { path });
            }
            Err(e) => {
                return Err(BoardPolicyError::Unreadable {
                    path,
                    detail: e.to_string(),
                });
            }
        };
        Self::from_toml_str(&raw)
    }

    /// Parses and validates policy TOML. Unknown keys are rejected so a misspelled
    /// requirement cannot silently switch enforcement off.
    pub fn from_toml_str(raw: &str) -> Result<Self, BoardPolicyError> {
        let policy: Self = toml::from_str(raw).map_err(|e| BoardPolicyError::Malformed {
            detail: e.to_string(),
        })?;
        policy
            .validate()
            .map_err(|problems| BoardPolicyError::Invalid { problems })?;
        Ok(policy)
    }

    #[must_use]
    pub fn ledger(&self) -> &BoardLedgerPolicyV1 {
        &self.board.ledger
    }

    #[must_use]
    pub fn privacy(&self) -> &BoardPrivacyPolicyV1 {
        &self.board.privacy
    }

    /// Structural validation. Returns every problem, not just the first.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();
        let board = &self.board;

        if self.schema != BOARD_POLICY_SCHEMA_V1 {
            problems.push(format!(
                "schema must be `{BOARD_POLICY_SCHEMA_V1}` (found `{}`)",
                self.schema
            ));
        }
        if !is_owner_name(&board.org) {
            problems.push(format!(
                "board.org `{}` is not a valid organization login",
                board.org
            ));
        }
        if board.project_number == 0 {
            problems.push("board.project_number must be greater than 0".to_string());
        }
        if board
            .project_id
            .as_deref()
            .is_some_and(|id| id.trim().is_empty())
        {
            problems.push("board.project_id must not be blank when set".to_string());
        }
        if !is_repo_slug(&board.public_repo) {
            problems.push(format!(
                "board.public_repo `{}` must be `owner/name`",
                board.public_repo
            ));
        }
        if let Some(private_repo) = &board.private_repo {
            if !is_repo_slug(private_repo) {
                problems.push(format!(
                    "board.private_repo `{private_repo}` must be `owner/name`"
                ));
            }
            if private_repo.eq_ignore_ascii_case(&board.public_repo) {
                problems.push(
                    "board.private_repo must be a different repository from board.public_repo"
                        .to_string(),
                );
            }
        }
        if board.linked_repos.is_empty() {
            problems.push("board.linked_repos must list at least one repository".to_string());
        }
        for repo in &board.linked_repos {
            if !is_repo_slug(repo) {
                problems.push(format!(
                    "board.linked_repos entry `{repo}` must be `owner/name`"
                ));
            }
        }
        push_duplicates(
            &mut problems,
            "board.linked_repos",
            &board.linked_repos,
            true,
        );
        for (label, repo) in std::iter::once(("public_repo", &board.public_repo))
            .chain(board.private_repo.iter().map(|r| ("private_repo", r)))
        {
            if !self.links_repo(repo) {
                problems.push(format!(
                    "board.linked_repos must include board.{label} `{repo}`"
                ));
            }
        }
        if !is_ticket_prefix(&board.ticket_prefix) {
            problems.push(format!(
                "board.ticket_prefix `{}` must be 2-{MAX_TICKET_PREFIX_LEN} characters of A-Z or 0-9 starting with a letter",
                board.ticket_prefix
            ));
        }

        let ledger = &board.ledger;
        if ledger.allow_deliverable_kinds.is_empty() {
            problems.push(
                "board.ledger.allow_deliverable_kinds must allow at least one kind".to_string(),
            );
        }
        for kind in &ledger.allow_deliverable_kinds {
            if !KNOWN_DELIVERABLE_KINDS.contains(&kind.as_str()) {
                problems.push(format!(
                    "board.ledger.allow_deliverable_kinds entry `{kind}` is not a supported kind ({})",
                    KNOWN_DELIVERABLE_KINDS.join(", ")
                ));
            }
        }
        push_duplicates(
            &mut problems,
            "board.ledger.allow_deliverable_kinds",
            &ledger.allow_deliverable_kinds,
            false,
        );
        for field in &ledger.required_add_fields {
            if ScopingField::parse(field).is_none() {
                problems.push(format!(
                    "board.ledger.required_add_fields entry `{field}` is not a known scoping field"
                ));
            }
        }
        push_duplicates(
            &mut problems,
            "board.ledger.required_add_fields",
            &ledger.required_add_fields,
            false,
        );
        for field in &ledger.required_ship_fields {
            if SettlementField::parse(field).is_none() {
                problems.push(format!(
                    "board.ledger.required_ship_fields entry `{field}` is not a known settlement field"
                ));
            }
        }
        push_duplicates(
            &mut problems,
            "board.ledger.required_ship_fields",
            &ledger.required_ship_fields,
            false,
        );

        let privacy = &board.privacy;
        if privacy
            .private_locked_seats
            .iter()
            .any(|seat| seat.trim().is_empty())
        {
            problems.push(
                "board.privacy.private_locked_seats must not contain blank seats".to_string(),
            );
        }
        // A blank substring matches every card and would reject the whole board.
        if privacy
            .forbidden_public_substrings
            .iter()
            .any(|needle| needle.trim().is_empty())
        {
            problems.push(
                "board.privacy.forbidden_public_substrings must not contain blank entries"
                    .to_string(),
            );
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    /// Reasons this policy is too weak to certify `INV-BOARD-LEDGER-TRACKING-01`.
    /// Empty when both requirement switches are on and every ledger field is required.
    #[must_use]
    pub fn ledger_tracking_gaps(&self) -> Vec<String> {
        let ledger = self.ledger();
        let mut gaps = Vec::new();
        if !ledger.require_scoping_on_add {
            gaps.push("board.ledger.require_scoping_on_add is false".to_string());
        }
        if !ledger.require_settlement_on_ship {
            gaps.push("board.ledger.require_settlement_on_ship is false".to_string());
        }
        for field in ScopingField::ALL {
            if !ledger.required_add_fields.iter().any(|f| f == field.key()) {
                gaps.push(format!(
                    "board.ledger.required_add_fields omits `{}`",
                    field.key()
                ));
            }
        }
        for field in SettlementField::ALL {
            if !ledger.required_ship_fields.iter().any(|f| f == field.key()) {
                gaps.push(format!(
                    "board.ledger.required_ship_fields omits `{}`",
                    field.key()
                ));
            }
        }
        gaps
    }

    #[must_use]
    pub fn requires_scoping(&self, field: ScopingField) -> bool {
        let ledger = self.ledger();
        ledger.require_scoping_on_add && ledger.required_add_fields.iter().any(|f| f == field.key())
    }

    #[must_use]
    pub fn requires_settlement(&self, field: SettlementField) -> bool {
        let ledger = self.ledger();
        ledger.require_settlement_on_ship
            && ledger.required_ship_fields.iter().any(|f| f == field.key())
    }

    #[must_use]
    pub fn allows_deliverable_kind(&self, kind: &str) -> bool {
        self.ledger()
            .allow_deliverable_kinds
            .iter()
            .any(|allowed| allowed == kind)
    }

    #[must_use]
    pub fn links_repo(&self, repo: &str) -> bool {
        self.board
            .linked_repos
            .iter()
            .any(|linked| linked.eq_ignore_ascii_case(repo))
    }

    /// `seat` must already be reduced to its bare seat token (no sigil or instance suffix).
    #[must_use]
    pub fn locks_seat_private(&self, seat: &str) -> bool {
        self.privacy()
            .private_locked_seats
            .iter()
            .any(|locked| locked.trim().eq_ignore_ascii_case(seat))
    }

    /// Renders the policy as commented TOML for `chinwag board init`.
    #[must_use]
    pub fn to_toml_string(&self) -> String {
        let board = &self.board;
        let ledger = &board.ledger;
        let privacy = &board.privacy;
        let mut out = String::new();
        out.push_str("# Chinwag board policy. `chinwag board add|move|push|sync|verify-ledger` fail closed\n");
        out.push_str("# (exit 78) when this file is missing, invalid, or violated.\n");
        out.push_str(&format!("schema = {}\n\n", toml_string(&self.schema)));
        out.push_str("[board]\n");
        out.push_str(&format!("org = {}\n", toml_string(&board.org)));
        out.push_str(&format!("project_number = {}\n", board.project_number));
        if let Some(project_id) = &board.project_id {
            out.push_str(&format!("project_id = {}\n", toml_string(project_id)));
        }
        out.push_str(&format!(
            "public_repo = {}\n",
            toml_string(&board.public_repo)
        ));
        if let Some(private_repo) = &board.private_repo {
            out.push_str(&format!("private_repo = {}\n", toml_string(private_repo)));
        }
        out.push_str(&format!(
            "linked_repos = {}\n",
            toml_string_array(&board.linked_repos)
        ));
        out.push_str(&format!(
            "ticket_prefix = {}\n",
            toml_string(&board.ticket_prefix)
        ));
        out.push_str(&format!(
            "disallow_raw_bypass = {}\n\n",
            board.disallow_raw_bypass
        ));
        out.push_str("[board.ledger]\n");
        out.push_str(&format!(
            "require_scoping_on_add = {}\n",
            ledger.require_scoping_on_add
        ));
        out.push_str(&format!(
            "require_settlement_on_ship = {}\n",
            ledger.require_settlement_on_ship
        ));
        out.push_str(&format!(
            "allow_deliverable_kinds = {}\n",
            toml_string_array(&ledger.allow_deliverable_kinds)
        ));
        out.push_str(&format!(
            "required_add_fields = {}\n",
            toml_string_array(&ledger.required_add_fields)
        ));
        out.push_str(&format!(
            "required_ship_fields = {}\n\n",
            toml_string_array(&ledger.required_ship_fields)
        ));
        out.push_str("[board.privacy]\n");
        out.push_str(&format!(
            "private_locked_seats = {}\n",
            toml_string_array(&privacy.private_locked_seats)
        ));
        out.push_str(&format!(
            "forbidden_public_substrings = {}\n",
            toml_string_array(&privacy.forbidden_public_substrings)
        ));
        out
    }

    /// Fully enforcing starter policy for a workspace that has none yet.
    #[must_use]
    pub fn starter(
        org: &str,
        project_number: u64,
        project_id: Option<&str>,
        public_repo: &str,
        private_repo: Option<&str>,
        ticket_prefix: &str,
    ) -> Self {
        let mut linked_repos = vec![public_repo.to_string()];
        if let Some(private_repo) = private_repo
            && !private_repo.eq_ignore_ascii_case(public_repo)
        {
            linked_repos.push(private_repo.to_string());
        }
        Self {
            schema: BOARD_POLICY_SCHEMA_V1.to_string(),
            board: BoardPolicyBoardV1 {
                org: org.to_string(),
                project_number,
                project_id: project_id.map(str::to_string),
                public_repo: public_repo.to_string(),
                private_repo: private_repo.map(str::to_string),
                linked_repos,
                ticket_prefix: ticket_prefix.to_string(),
                disallow_raw_bypass: true,
                ledger: BoardLedgerPolicyV1 {
                    require_scoping_on_add: true,
                    require_settlement_on_ship: true,
                    allow_deliverable_kinds: KNOWN_DELIVERABLE_KINDS
                        .iter()
                        .map(|kind| (*kind).to_string())
                        .collect(),
                    required_add_fields: ScopingField::ALL
                        .iter()
                        .map(|field| field.key().to_string())
                        .collect(),
                    required_ship_fields: SettlementField::ALL
                        .iter()
                        .map(|field| field.key().to_string())
                        .collect(),
                },
                privacy: BoardPrivacyPolicyV1::default(),
            },
        }
    }
}

/// A ticket ID that matches `^<PREFIX>-[0-9]{4}(?:\.[0-9]{2}(?:-[0-9]{2})?)?$`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TicketId<'a> {
    raw: &'a str,
    primary_len: usize,
}

impl<'a> TicketId<'a> {
    /// Returns `None` unless `raw` is exactly a canonical ticket ID under `prefix`.
    #[must_use]
    pub fn parse(raw: &'a str, prefix: &str) -> Option<Self> {
        if !is_ticket_prefix(prefix) {
            return None;
        }
        let digits = raw.strip_prefix(prefix)?.strip_prefix('-')?.as_bytes();
        let all_digits = |range: &[u8]| range.iter().all(u8::is_ascii_digit);
        let well_formed = match digits.len() {
            4 => all_digits(digits),
            7 => all_digits(&digits[..4]) && digits[4] == b'.' && all_digits(&digits[5..]),
            10 => {
                all_digits(&digits[..4])
                    && digits[4] == b'.'
                    && all_digits(&digits[5..7])
                    && digits[7] == b'-'
                    && all_digits(&digits[8..])
            }
            _ => false,
        };
        well_formed.then_some(Self {
            raw,
            primary_len: prefix.len() + 1 + 4,
        })
    }

    /// Reads the ticket ID that leads a card title, as `[ID] Title` or `ID: Title`.
    #[must_use]
    pub fn from_title(title: &'a str, prefix: &str) -> Option<Self> {
        let title = title.trim_start();
        let token = match title.strip_prefix('[') {
            Some(rest) => rest.split_once(']')?.0.trim(),
            None => {
                let end = title
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
                    .unwrap_or(title.len());
                title[..end].trim_end_matches('.')
            }
        };
        Self::parse(token, prefix)
    }

    #[must_use]
    pub fn as_str(&self) -> &'a str {
        self.raw
    }

    /// The `<PREFIX>-<NNNN>` part, shared by a ticket and all of its sub-tickets.
    #[must_use]
    pub fn primary(&self) -> &'a str {
        &self.raw[..self.primary_len]
    }

    #[must_use]
    pub fn is_sub_ticket(&self) -> bool {
        self.raw.len() > self.primary_len
    }
}

fn is_ticket_prefix(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    (2..=MAX_TICKET_PREFIX_LEN).contains(&bytes.len())
        && bytes[0].is_ascii_uppercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn is_owner_name(raw: &str) -> bool {
    !raw.is_empty()
        && !raw.starts_with('-')
        && raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn is_repo_slug(raw: &str) -> bool {
    let Some((owner, name)) = raw.split_once('/') else {
        return false;
    };
    is_owner_name(owner)
        && !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn push_duplicates(problems: &mut Vec<String>, label: &str, values: &[String], ignore_case: bool) {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        let key = if ignore_case {
            value.to_ascii_lowercase()
        } else {
            value.clone()
        };
        if !seen.insert(key) {
            problems.push(format!("{label} lists `{value}` more than once"));
        }
    }
}

/// TOML basic string. JSON string escaping is a subset of TOML's except for DEL,
/// which JSON leaves raw and TOML forbids.
fn toml_string(raw: &str) -> String {
    serde_json::Value::String(raw.to_string())
        .to_string()
        .replace('\u{7f}', "\\u007F")
}

fn toml_string_array(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| toml_string(value)).collect();
    format!("[{}]", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn starter() -> BoardPolicyTomlV1 {
        BoardPolicyTomlV1::starter(
            "acme-co",
            7,
            Some("PVT_example"),
            "acme-co/product",
            Some("acme-co/tasks"),
            "ACME",
        )
    }

    #[test]
    fn committed_workspace_policy_loads_and_fully_enforces_the_ledger() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let policy = BoardPolicyTomlV1::load(&workspace_root).expect("committed board.toml loads");
        assert_eq!(policy.schema, "chinwag.board.policy.v1");
        assert_eq!(policy.board.org, "emunlabs");
        assert_eq!(policy.board.project_number, 1);
        assert_eq!(
            policy.board.project_id.as_deref(),
            Some("PVT_kwDOFJPsXM4BrFUV")
        );
        assert_eq!(policy.board.public_repo, "emunlabs/chinwag");
        assert_eq!(
            policy.board.private_repo.as_deref(),
            Some("emunlabs/chinwag-tasks")
        );
        assert_eq!(
            policy.board.linked_repos,
            [
                "emunlabs/chinwag",
                "emunlabs/chinwag-tasks",
                "emunlabs/chinwag-website",
                "emunlabs/chinwag-edge-proxy"
            ]
        );
        assert_eq!(policy.board.ticket_prefix, "CHWG");
        assert!(policy.board.disallow_raw_bypass);
        assert_eq!(
            policy.ledger().allow_deliverable_kinds,
            ["code", "artifact"]
        );
        assert_eq!(policy.ledger_tracking_gaps(), Vec::<String>::new());
        assert!(policy.locks_seat_private("PATENT"));
    }

    #[test]
    fn starter_policy_survives_a_toml_round_trip_with_hostile_strings() {
        let mut policy = starter();
        policy.board.privacy.private_locked_seats = vec!["LEGAL".to_string()];
        policy.board.privacy.forbidden_public_substrings = vec![
            "say \"hi\"".to_string(),
            "back\\slash".to_string(),
            "tab\there".to_string(),
            "Δ café".to_string(),
            "del\u{7f}ete".to_string(),
        ];
        let rendered = policy.to_toml_string();
        assert_eq!(BoardPolicyTomlV1::from_toml_str(&rendered), Ok(policy));
    }

    #[test]
    fn misspelled_requirement_is_rejected_instead_of_defaulting_off() {
        let rendered = starter()
            .to_toml_string()
            .replace("require_scoping_on_add", "require_scoping_on_ad");
        let err = BoardPolicyTomlV1::from_toml_str(&rendered).unwrap_err();
        assert!(
            matches!(&err, BoardPolicyError::Malformed { detail } if detail.contains("require_scoping_on_ad")),
            "{err}"
        );
    }

    #[test]
    fn missing_ledger_section_is_rejected() {
        let rendered = starter().to_toml_string();
        let without_ledger = rendered.split("[board.ledger]").next().unwrap();
        assert!(matches!(
            BoardPolicyTomlV1::from_toml_str(without_ledger),
            Err(BoardPolicyError::Malformed { .. })
        ));
    }

    #[test]
    fn missing_policy_file_reports_the_expected_path() {
        let root = std::env::temp_dir().join(format!(
            "chinwag-board-policy-missing-{}",
            std::process::id()
        ));
        assert_eq!(
            BoardPolicyTomlV1::load(&root),
            Err(BoardPolicyError::Missing {
                path: root.join(".chinwag/board.toml")
            })
        );
    }

    #[test]
    fn validate_reports_every_structural_problem() {
        let mut policy = starter();
        policy.schema = "chinwag.board.policy.v0".to_string();
        policy.board.org = "acme co".to_string();
        policy.board.project_number = 0;
        policy.board.public_repo = "product".to_string();
        policy.board.private_repo = Some("acme-co/../tasks".to_string());
        policy.board.linked_repos = vec!["acme-co/site".to_string(), "ACME-CO/site".to_string()];
        policy.board.ticket_prefix = "acme".to_string();
        policy.board.ledger.allow_deliverable_kinds = vec!["design".to_string()];
        policy.board.ledger.required_add_fields = vec!["function".to_string()];
        policy.board.ledger.required_ship_fields =
            vec!["credits_used".to_string(), "credits_used".to_string()];
        policy.board.privacy.forbidden_public_substrings = vec![" ".to_string()];

        let problems = policy.validate().unwrap_err();
        for expected in [
            "schema must be `chinwag.board.policy.v1` (found `chinwag.board.policy.v0`)",
            "board.org `acme co` is not a valid organization login",
            "board.project_number must be greater than 0",
            "board.public_repo `product` must be `owner/name`",
            "board.private_repo `acme-co/../tasks` must be `owner/name`",
            "board.linked_repos lists `ACME-CO/site` more than once",
            "board.linked_repos must include board.public_repo `product`",
            "board.ticket_prefix `acme` must be 2-16 characters of A-Z or 0-9 starting with a letter",
            "board.ledger.allow_deliverable_kinds entry `design` is not a supported kind (code, artifact)",
            "board.ledger.required_add_fields entry `function` is not a known scoping field",
            "board.ledger.required_ship_fields lists `credits_used` more than once",
            "board.privacy.forbidden_public_substrings must not contain blank entries",
        ] {
            assert!(
                problems.iter().any(|p| p == expected),
                "missing `{expected}` in {problems:#?}"
            );
        }
    }

    #[test]
    fn weakened_policy_reports_each_ledger_tracking_gap() {
        let mut policy = starter();
        policy.board.ledger.require_settlement_on_ship = false;
        policy
            .board
            .ledger
            .required_add_fields
            .retain(|f| f != "active_seats");
        policy
            .board
            .ledger
            .required_ship_fields
            .retain(|f| f != "verification_receipt");
        assert_eq!(policy.validate(), Ok(()));
        assert_eq!(
            policy.ledger_tracking_gaps(),
            [
                "board.ledger.require_settlement_on_ship is false",
                "board.ledger.required_add_fields omits `active_seats`",
                "board.ledger.required_ship_fields omits `verification_receipt`",
            ]
        );
        assert!(!policy.requires_scoping(ScopingField::ActiveSeats));
        assert!(policy.requires_scoping(ScopingField::FunctionTeam));
        assert!(!policy.requires_settlement(SettlementField::CreditsUsed));
    }

    #[test]
    fn ticket_id_accepts_only_the_canonical_shapes() {
        for (raw, primary, is_sub) in [
            ("CHWG-0282", "CHWG-0282", false),
            ("CHWG-0282.01", "CHWG-0282", true),
            ("CHWG-0282.01-02", "CHWG-0282", true),
        ] {
            let ticket = TicketId::parse(raw, "CHWG").unwrap_or_else(|| panic!("{raw} is valid"));
            assert_eq!(ticket.as_str(), raw);
            assert_eq!(ticket.primary(), primary);
            assert_eq!(ticket.is_sub_ticket(), is_sub);
        }
        for raw in [
            "",
            "CHWG",
            "CHWG-",
            "CHWG-282",
            "CHWG-02820",
            "chwg-0282",
            "CHWG_0282",
            "CHWG-0282.1",
            "CHWG-0282.001",
            "CHWG-0282.01-2",
            "CHWG-0282.01-023",
            "CHWG-0282.01-02-03",
            "CHWG-0282-01",
            "CHWG-0282-CI-FAIL",
            "CHWG-0282 ",
            " CHWG-0282",
            "CHWG-0282\n",
            "CHWG-٠٢٨٢",
            "CHWG-0282,CHWG-0283",
            "../CHWG-0282",
            "ACME-0282",
        ] {
            assert_eq!(
                TicketId::parse(raw, "CHWG"),
                None,
                "`{raw}` must be rejected"
            );
        }
        assert!(TicketId::parse("ACME-0007.03", "ACME").is_some());
        assert_eq!(TicketId::parse("CHWG-0282", "ACME"), None);
        assert_eq!(TicketId::parse("-0282", ""), None);
    }

    #[test]
    fn ticket_id_is_read_from_both_title_forms() {
        let id = |title| TicketId::from_title(title, "CHWG").map(|t| t.as_str());
        assert_eq!(id("[CHWG-0271] P0 crypto fix"), Some("CHWG-0271"));
        assert_eq!(id("[CHWG-0276.01-02] Sub-task"), Some("CHWG-0276.01-02"));
        assert_eq!(id("CHWG-0189: Match agents to work"), Some("CHWG-0189"));
        assert_eq!(id("CHWG-0189.02 Docs"), Some("CHWG-0189.02"));
        assert_eq!(id("CHWG-0189. Trailing dot"), Some("CHWG-0189"));
        assert_eq!(id("Fix the build (CHWG-0189)"), None);
        assert_eq!(id("[P0] CHWG-0189 regression"), None);
        assert_eq!(id("CHWG-0189-followup: thing"), None);
        assert_eq!(id("[CHWG-0189"), None);
    }
}
