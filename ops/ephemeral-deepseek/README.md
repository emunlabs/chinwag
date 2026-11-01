# Ephemeral DEV/QA DeepSeek V4.1 Flash: empty-content fix (2026-11-01)

## Problem
`@cf/deepseek-ai/deepseek-v4.1-flash-1017` reasons at `high` effort by default and returns that
reasoning in a separate `message.reasoning` field. When reasoning uses the whole output budget the
reply is `content: ""` with `finish_reason: "length"`. Waves 1 and 6 hit this (wave 6: 5 of 10 seats
truncated at 32768 tokens, 1 timed out, 4 `unverified_finish`; every `output.txt` was 0 bytes). The old
Worker also defaulted to `max_tokens: 2048` and fell back to `JSON.stringify(res)` when content was
empty, which hid the cause.

## What is here
| Path | What | Deployed where |
|---|---|---|
| `worker/` | Worker source of record (first commit = deployed code as recovered, second = fix) | Cloudflare `chinwag-deepseek-v41` (**not deployed by this PR**) |
| `bin/deepseek-agent` | Python helper used by the dispatcher/`run_job_v2.py` | `~/.local/bin/deepseek-agent` (**not installed by this PR**) |
| `job-runner/` | `run_job_v2.py` + evidence parser + tests (no-replay runner) | operation directories |
| `crates/chinwag-cli/src/deepseek_pool.rs` | Rust direct-API path: effort default, finish_reason in errors, real cost in ledger | built into `chinwag` |
| `crates/chinwag-cli/src/agent_dispatch_run.rs` | warning when an engine yields no usable stdout | built into `chinwag` |

## Behaviour
* `reasoning_effort`: Worker default `low`, per-request override incl. `none`. Helper: env
  `EPHEMERAL_DEEPSEEK_REASONING`, else `none` for QA seats (env `EPHEMERAL_SEAT`), else `low`.
* `max_completion_tokens` replaces `max_tokens` (Worker accepts the old name from old clients;
  the helper sends both until the Worker is deployed, then drop `max_tokens`).
* Worker returns `finish_reason`, `usage`, `reasoning_chars`, `empty_content` next to `response`.
* Helper exits 1 with a one-line stderr reason on empty content or `finish_reason=length`, retries once
  at a lower effort on `length` (`EPHEMERAL_DEEPSEEK_RETRY=0` disables; `run_job_v2.py` disables it).
* `run_job_v2.py` publishes `outcome: failed` + `failure_reason` + `finish_reason` + `completion_tokens`
  for anything that is not a verified non-empty completion.
* System instruction: answer in the requested format/JSON only, keep reasoning brief.

## Rollout order (manual, not part of this PR)
1. `wrangler deploy` the Worker (`worker/`), set `AUTH_SECRET` as today. Old clients keep working.
2. Install `bin/deepseek-agent` to `~/.local/bin/` (a backup of the previous one is in
   `~/backups/deepseek-fix-2026-11-01/live/deepseek-agent`). `run_job_v2.py` pins its SHA-256; the
   copy in `job-runner/` pins the new helper. Copy `job-runner/*.py` into new operation dirs.
3. Roll out the `chinwag` binary containing the Rust changes.

## Rollback
Revert this PR; restore `~/.local/bin/deepseek-agent` from the backup; redeploy the previous Worker
(the first commit of this branch, `worker/src/worker.mjs`).

## Tests
`cd worker && node --test test/` · `python3 -m unittest test_deepseek_agent` (here) ·
`cd job-runner && python3 -m unittest discover -p 'test_*.py'` ·
`cargo test -p chinwag-cli --lib` (needs `CHINWAG_PRIVATE_CRSQL_INPUTS`).

## Follow-ups (not in this PR)
* Trim/chunk the ~92 KB prompts (wave 6 prompts were ~24-26K tokens each).
* Gateway `skipCache` is still `false` by default (per-request `skip_cache: true` now possible).
* Retry-at-lower-effort in `deepseek_pool.rs` (only the Python helper retries today).
* `ui_workbench_run.rs:967` on main has a broken raw string that stops `chinwag` bin from compiling.
