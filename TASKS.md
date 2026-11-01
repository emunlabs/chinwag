# TASKS.md — Chinwag fleet task board

> Drafted 2026-11-01 (America/Chicago) by infra for Brian's walk-through. **PR only, not merged.**
> Replaces the 2026-10-29 engineering board (blob `9086cc09`, on `main` at `0dbd8d6`). Still-relevant legacy items are carried in [Appendix A](#appendix-a--carried-from-the-2026-10-29-board).
> Status values: `open`, `open · in review`, `open · waiting on Brian`, `done`. Everything is `open` unless noted.

## 1. Rules

1. **One writer.** Only infra edits `TASKS.md`. Everyone else sends changes to infra over the bus.
2. **Every task has an owner, dependencies and a reviewer.** A task missing any of the three is not ready to be handed out.
3. **The bus hands idle agents the next ready task.** Ready means all dependencies are done and the task has an owner and reviewer.
4. **Agents may only mark `done, pending review`.** The reviewer marks `done`. An owner never marks its own task `done`.
5. **Standup flags** agents idle for more than 30 minutes and tasks blocked for more than 12 hours.

Ordering notes: reviewers listed as "A, then B" review in that order. "infra QA" means infra's QA pass; for PRs it includes the squash-merge.

## 2. Ready now

Open, with no unfinished dependency. Each row has an owner and reviewer in the tables below.

| ID | Task | Owner |
| :--- | :--- | :--- |
| ENG-1 | PR #11 allowed_signers (FLINT review blocked on gh auth) | ENG |
| ENG-3 | Secrets plug-in PRD | ENG |
| ENG-6 | One-way Vault credits with proving test | ENG |
| ENG-9 | Spotify demo behind a flag (GROWTH's demo) | ENG |
| ENG-10 | Dioxus cleanup (GPUI only) | ENG |
| ENG-11 | Mission Control 422s on /api/initiatives and /api/export | ENG |
| ENG-12 | Per-worker build dirs | ENG |
| ENG-13 | PRs #4, #5, #8, #10 | ENG |
| ENG-14 | Key scrub on eng/decompose-preview | ENG |
| PRD-1 | v0.1.2 PRD build | product |
| PRD-6 | ALISTAIR co-sign of dealer safety floor (PLY-14, 17, 18, 19, 22) | ALISTAIR |
| SM-0 | chinwag.sh website revamp copy | DECLARATION |
| SM-0b | emunlabs.com website revamp copy | TBD |
| SM-2 | Default card copy | DECLARATION |
| SM-3 | Enterprise comparables | SALES |
| SM-6a | Spotify one-pager (ready) | GROWTH |
| SM-7 | Founder bio without clearance mention | DECLARATION |
| SM-8b | Concierge playbook | SALES |
| SM-9 | Dioxus → GPUI in S&M materials | DECLARATION |
| BIZ-1 | MO price table | MO |
| BIZ-3 | EAGLE-EYE customer terms + privacy wording | EAGLE-EYE |
| BIZ-3a | One-page disclaimer-protection note | EAGLE-EYE |
| BIZ-5 | Spotify terms | EAGLE-EYE |
| BIZ-6 | Security pack | EAGLE-EYE |
| BIZ-10 | Nic's IP assignment to Emun Labs, Inc. (covers Captionize code) | EAGLE-EYE |
| BIZ-11 | Consulting agreement with Nic, with IP assignment clause; contracting party left blank until she picks her LLC or herself personally | EAGLE-EYE |
| PA-1 | D&B email send (before ~8 AM CT Nov 2) | Brian |
| PA-3 | Sign IRS 8822-B | Brian |
| PA-4 | 9 AM CT standup list | Brian |
| INF-1 | Seat model audit | infra |
| INF-2 | Daily seat-model drift check | infra |
| INF-4 | §11 delivery approval checklist | infra |
| INF-5 | Roughtime write-up | infra |
| INF-7 | Long worktree renames | infra |
| INF-8 | black-october phase 2 | infra |
| INF-9 | Producer restart on ethernet | infra |
| INF-10 | PR #3 | infra |
| INF-11 | Exhibit A for IP assignment | infra |

Due-time item: **SM-1** (row 66 retention list) must land before the 9 AM CT standup. Its privacy part waits on BIZ-3.

## 3. Waiting on Brian

| # | Item | Blocks |
| :--- | :--- | :--- |
| 1 | INIT-07 slide 14 | SM-10 |
| 2 | EAGLE-EYE 18+ clause and disclaimer-note review (BIZ-3, BIZ-3a) | ENG-8, SM-12, privacy part of SM-1 |
| 3 | Apple $99 fee OK (PA-2) | ENG-15 (CHWG-011-1 signing work) |
| 4 | CHWG-011-1 signing work OK | ENG-15 |
| 5 | D&B email send before ~8 AM CT Nov 2 (PA-1) | none |
| 6 | IRS 8822-B signature (PA-3) | none |
| 7 | itsaplan R2 bucket + token | INF-3 |
| 9 | Price-table approval (BIZ-1), after VENTURE + SALES check | BIZ-2, BIZ-4, SM-13 |
| 10 | Title and consideration blanks for the IP assignment | BIZ-7 |
| 11 | Reviews you own: SM-1, SM-5 (rules), SM-6, SM-7, BIZ-3..BIZ-8, BIZ-9 (rules) | their parent tasks |
| 12 | Pick message-house upgrade route Option A or B | SM-0 final copy |
| 13 | emunlabs.com message house owner: GEMINI-PM or DECLARATION | SM-0b |

Resolved since the draft began: orphaned pi process — killed by eng with Brian's approval. FLINT reviews of #11/#12 have not run yet (gh auth over SSH).

## 4. Dependency chain

Read top to bottom. `A -> B` means B waits on A.

```
v0.1.2 PRD build (fold comments + rulings)
   ->  STE-80 lint rerun
   ->  split for DEX / DECLARATION
   ->  DEX + DECLARATION review of split docs   (s-and-m relays; Brian rules)
   ->  MacBook Codex consistency pass on every doc
   (ALISTAIR and QA also get the full doc)

ENG-3 Secrets PRD            ->  ENG-4 SecretStore + Cloudflare plug-in
ENG-1 PR #11 (FLINT, ALISTAIR+QA ok, infra QA)  ->  ENG-2 PR #12 (FLINT + ALISTAIR, then infra QA)  ->  ENG-7 DCO CI check
INF-5 Roughtime write-up     ->  ENG-5 Roughtime
BIZ-3 EAGLE-EYE 18+ terms    ->  ENG-8 18+ signup + minor-report handling
                             ->  SM-12 18+ signup and marketing copy
                             ->  privacy part of SM-1 (row 66 retention list)
BIZ-1 MO price table (Brian approves)  ->  BIZ-2 revenue model
                                       ->  BIZ-4 founding contract template
                                       ->  SM-13 Founding Enterprise sales materials
INF seat config              ->  SM-11 fleet-skills PR #5 + seat setup
PA-2 Apple $99 fee OK        ->  ENG-15 CHWG-011-1 signing work
PRD-6 ALISTAIR co-sign       ->  DEX/DECLARATION review of Breakroom sections and the 0.2 dealer gates
ENG-9 Spotify demo flag      ->  SM-6b Spotify demo
INF-11 Exhibit A + Brian's blanks  ->  BIZ-7 IP assignment
counsel claims review        ->  BIZ-8 patent pledge CHWG-PAT-05
Brian picks A/B  ->  SM-0 chinwag.sh copy
emunlabs.com message house (owner TBD)  ->  SM-0b emunlabs.com copy
```

## 5. Tasks by team

### 5.1 ENG

| ID | Task | Owner | Depends on | Reviewer | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| ENG-1 | [PR #11](https://github.com/emunlabs/chinwag/pull/11) allowed_signers | ENG | FLINT review (not yet run: gh auth fails for FLINT over SSH on the MacBook; options with Brian) | FLINT, then infra QA (squash-merge). ALISTAIR + QA approved | open · in progress |
| ENG-2 | [PR #12](https://github.com/emunlabs/chinwag/pull/12) CLA → DCO | ENG | ENG-1 (#12 follows #11) | FLINT + ALISTAIR, then infra QA | open |
| ENG-3 | Secrets plug-in PRD | ENG | — | ALISTAIR, infra, QA | open |
| ENG-4 | SecretStore interface + Cloudflare plug-in | RUST | ENG-3 | FLINT, ALISTAIR, infra QA | open |
| ENG-5 | Roughtime | ENG | INF-5 (infra write-up) | ALISTAIR, infra QA | open |
| ENG-6 | One-way Vault credits with proving test | ENG | — | ALISTAIR, infra QA | open |
| ENG-7 | DCO CI check | ENG | ENG-2 | infra QA | open |
| ENG-8 | 18+ signup checkbox (no ID checks) + minor-report handling — spec in 5.1.1 | ENG | BIZ-3 (EAGLE-EYE 18+ terms) | ALISTAIR, infra QA | open |
| ENG-9 | Spotify demo behind a flag (GROWTH's demo) | ENG | — (ready) | EAGLE-EYE reviews terms (BIZ-5) | open |
| ENG-10 | Dioxus cleanup (GPUI only) | ENG | — | FLINT, infra QA | open |
| ENG-11 | Mission Control 422s on /api/initiatives and /api/export | ENG | — | FLINT, infra QA | open |
| ENG-12 | Per-worker build dirs | ENG | — | FLINT, infra QA | open |
| ENG-13 | PRs [#4](https://github.com/emunlabs/chinwag/pull/4), [#5](https://github.com/emunlabs/chinwag/pull/5), [#8](https://github.com/emunlabs/chinwag/pull/8), [#10](https://github.com/emunlabs/chinwag/pull/10) | ENG | — | FLINT, infra QA | open |
| ENG-14 | Key scrub on eng/decompose-preview | ENG | — | FLINT, infra QA | open |
| ENG-15 | CHWG-011-1 signing work | ENG | PA-2 (Apple $99 fee OK), Brian's OK on the work | FLINT, infra QA | open · waiting on Brian |

#### 5.1.1 ENG-8 spec: minor-report handling

- A report **never** freezes, closes or deletes an account automatically. The account stays fully usable pending review.
- The enterprise admin is notified first.
- The account owner gets a notice and a window to respond.
- **Only Brian, from his signed-in account, can approve a closure.** Every approval is audit-logged.
- After approval: close the account and delete its data. Log the deletion without personal details.
- Rate-limit reports.
- Bursts of reports, or spikes from one source or org, are treated as an attack: hold everything, alert Brian and infra.
- No profiling of self-declared under-18s. 18+ signup is a checkbox only, with no ID checks.

### 5.2 PRODUCT

| ID | Task | Owner | Depends on | Reviewer | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| PRD-1 | v0.1.2 PRD build: fold comments + rulings; remove the unknown-age profiling section; include the minor flow in 5.1.1. Folds in v0.1.1 comments from GROWTH (G1-G15), SALES (S1-S13), GEMINI-PM (PM1-PM14); do not re-send them for review. | product | — | MacBook Codex | open |
| PRD-2 | STE-80 lint rerun | product | PRD-1 | QA | open |
| PRD-3 | DEX / DECLARATION doc split | product | PRD-1, PRD-2 | s-and-m | open |
| PRD-4 | Consistency pass on every doc | MacBook Codex | PRD-3, SM-5 | product | open |
| PRD-5 | PLY-18.5 — closed by Brian (no ID checks, 18+) | Brian | — | Brian | done |
| PRD-6 | ALISTAIR co-sign on dealer safety floor PLY-14, 17, 18, 19, 22. Blocks DEX/DECLARATION review of the Breakroom sections and the 0.2 dealer gates | ALISTAIR | — | product | open |
| PRD-7 | Sync the wiki copy of GEMINI-PM's message house to the Antigravity source (back up first) | product | — (ready) | GEMINI-PM | done, pending review (GEMINI-PM) (wiki copy of GEMINI-PM's message house was synced) |

### 5.3 S&M

| ID | Task | Owner | Depends on | Reviewer | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| SM-0 | chinwag.sh website revamp copy from GEMINI-PM message house (`chinwag-sh-revamp-message-house-and-two-routes.md`, product syncs wiki copy from GEMINI-PM's Antigravity source). Use 'encrypted'/'tamper-proof sealed'. Drop "zero-knowledge" from caption card copy only; BBS+ ZKP wording stays; no clearance in bios; 18+ statement on site; tiers Free/Team/Enterprise with no prices | DECLARATION | Brian picks Option A or B before copy is final | Brian | open |
| SM-0b | emunlabs.com website revamp copy | TBD (Brian: GEMINI-PM writes a message house, or DECLARATION drafts from the Chinwag one) | emunlabs.com message house (none exists yet) | Brian | open · waiting on Brian |
| SM-1 | Row 66 retention list. Copy: EAGLE-EYE. Due before the 9 AM CT standup | DEX | BIZ-3 (privacy part only) | Brian | open |
| SM-2 | Default card copy. "encrypted" and "tamper-proof sealed" are OK; no "zero-knowledge" on caption card copy only; BBS+ ZKP wording stays | DECLARATION | — | ALISTAIR | open |
| SM-3 | Enterprise comparables | SALES | — | MO | open |
| SM-4 | PRD v0.1.1 review: GROWTH (15 comments), SALES (13), GEMINI-PM (14) | GROWTH, SALES, GEMINI-PM | — | Brian | done |
| SM-5 | PRD v0.1.2 review, this round: DEX and DECLARATION review their split docs. ALISTAIR and QA also get the full doc. Breakroom sections and 0.2 dealer gates also wait on PRD-6 | DEX, DECLARATION (s-and-m relays) | PRD-3, PRD-6 (for those sections) | Brian rules | open |
| SM-6a | Spotify one-pager | GROWTH | — (ready) | Brian | open |
| SM-6b | Spotify demo. Nothing goes out without Brian's OK | GROWTH | ENG-9, BIZ-5 (EAGLE-EYE terms) | Brian | open |
| SM-7 | Founder bio without clearance mention | DECLARATION | — | Brian | open |
| SM-8a | Top-20 connectors | SALES | PRD-1 | product | open |
| SM-8b | Concierge playbook | SALES | — (ready) | product | open |
| SM-9 | Dioxus → GPUI in S&M materials | DECLARATION | — (ready) | s-and-m | open |
| SM-10 | INIT-07 slide 14 | s-and-m | Brian | s-and-m | open · waiting on Brian |
| SM-11 | fleet-skills PR #5 + seat setup | s-and-m | infra seat config | eng | open |
| SM-12 | 18+ signup and marketing copy | DECLARATION | BIZ-3 (EAGLE-EYE clause) | ALISTAIR | open |
| SM-13 | Founding Enterprise sales materials | SALES | BIZ-1 (MO final price table) | MO (pricing), EAGLE-EYE (contract terms); Brian final OK before anything goes to a prospect | open |

### 5.4 BIZFIN

| ID | Task | Owner | Depends on | Reviewer | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| BIZ-1 | MO price table. Unblocks SM-13, BIZ-2, BIZ-4 | MO | — (ready) | VENTURE + SALES check; Brian approves | open |
| BIZ-2 | MO revenue model | MO | BIZ-1 | VENTURE | open |
| BIZ-3 | EAGLE-EYE customer terms + privacy wording: 18+ clause ("verified within a reasonable time"), IP/tag language, customer-owned cards. Unblocks ENG-8, SM-12, privacy part of SM-1 | EAGLE-EYE | — (ready) | Brian | open · waiting on Brian (review) |
| BIZ-3a | One-page note on disclaimer protection under COPPA, GDPR Art 8, UK Children's Code, APPI | EAGLE-EYE | — (ready; Brian reviews with BIZ-3) | Brian | open · waiting on Brian (review) |
| BIZ-4 | Founding contract template: SOC 2 by month 12, with credit if missed | EAGLE-EYE | BIZ-1 | Brian | open |
| BIZ-5 | Spotify terms | EAGLE-EYE | — (ready) | Brian | open |
| BIZ-6 | Security pack | EAGLE-EYE | — (ready) | ALISTAIR | open |
| BIZ-7 | RMM → Emun IP assignment | EAGLE-EYE | Brian's title + consideration blanks; INF-11 (Exhibit A) | Counsel + Brian | open |
| BIZ-8 | Patent pledge CHWG-PAT-05 | EAGLE-EYE | Counsel claims review | Brian | open |
| BIZ-9 | BIZFIN commercial/legal review of full v0.1.2 (no separate split doc unless Brian wants one) | BIZFIN | PRD-1 (full v0.1.2) | Brian rules | open |
| BIZ-10 | Nic's IP assignment to Emun Labs, Inc. (covers Captionize code) | EAGLE-EYE | — | Brian | open |
| BIZ-11 | Consulting agreement with Nic, with IP assignment clause; contracting party left blank until she picks her LLC or herself personally | EAGLE-EYE | — | Brian | open |

### 5.5 PERSONAL-ASSISTANT (Brian owns)

| ID | Task | Owner | Depends on | Reviewer | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| PA-1 | D&B email send — before ~8 AM CT Nov 2 | Brian | — | Brian | open · waiting on Brian |
| PA-2 | Apple $99 fee OK. Blocks ENG-15 | Brian | — | Brian | open · waiting on Brian |
| PA-3 | Unsigned IRS 8822-B signature | Brian | — | Brian | open · waiting on Brian |
| PA-4 | 9 AM CT standup list | Brian | — | Brian | open |

### 5.6 INFRA

| ID | Task | Owner | Depends on | Reviewer | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| INF-1 | Seat model audit | infra | — | TBD | open |
| INF-2 | Daily seat-model drift check | infra | — | TBD | open |
| INF-3 | itsaplan R2 upload | infra | Brian: R2 bucket + token | TBD | open · waiting on Brian |
| INF-4 | §11 delivery approval checklist | infra | — | TBD | open |
| INF-5 | Roughtime write-up | infra | — | TBD | open |
| INF-6 | QA + merge PRs [#11](https://github.com/emunlabs/chinwag/pull/11) and [#12](https://github.com/emunlabs/chinwag/pull/12) (squash) | infra | ENG-1 (then ENG-2): FLINT, and ALISTAIR for #12, first | TBD | open |
| INF-7 | Long worktree renames | infra | — | TBD | open |
| INF-8 | black-october phase 2 | infra | — | TBD | open |
| INF-9 | Producer restart on ethernet | infra | — | TBD | open |
| INF-10 | [PR #3](https://github.com/emunlabs/chinwag/pull/3) | infra | — | TBD | open |
| INF-11 | Exhibit A for IP assignment | infra | — | TBD | open |

## Appendix A — carried from the 2026-10-29 board

The old board's seat table is stale (all heartbeats 2026-10-29) and is dropped. Done items TASK-01..25, 27..30, 32 and 34 stay in git history only (`TASKS.md` blob `9086cc09` at `0dbd8d6`). Items below were not done on that board and are carried unverified. **Infra: confirm whether each is still live before the next standup.**

| Legacy ID | Name | Owner (then) | Status (then) |
| :--- | :--- | :--- | :--- |
| TASK-26 | CHWG-TRIPLE-B-CLI-01: `chinwag bond status \| verify \| inspect` | RUST | in progress |
| TASK-31 | CHWG-UI-LIVE-SERVER-01: `chinwag ui` API + `POST /api/bus/send` verification | RUST | ready |
| TASK-33 | CHWG-UI-CAPTIONIZM-PLUGIN-01: Captionizm / chinwag.tv asset + audio verification | TYPE | in progress |
| TASK-35 | CHWG-CONT-ALISTAIR-35: rolling-wave verification | ALISTAIR | in progress |
| TASK-36 | CHWG-CONT-ARCHITECT-36: rolling-wave UI + protocol verification | ARCHITECT | in progress |
| TASK-37 | CHWG-CONT-FLINT-37: verify FLINT #213 F1/F2 remediations | FLINT | in progress |
| TASK-38 | CHWG-CONT-QA-38: full-suite + live workbench verification | QA | in progress |

Parser note: the old file was read every 45 s by the bus daemon (`CHWG-DYNAMIC-TASKS-PARSER-01`), which looked for `[IN_PROGRESS]` / `[READY]` task headings. This file uses tables, so that parser will find none until it is updated to read them. Infra owns checking this before merge.
