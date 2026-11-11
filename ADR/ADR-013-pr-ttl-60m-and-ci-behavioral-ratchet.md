# ADR-013: 60-Minute Maximum PR TTL (`INV-PR-MAX-TTL-60M-01`) & Compounding CI Behavioral Ratchet (`INV-CI-BEHAVIORAL-RATCHET-01`)

- **Status:** Accepted
- **Date:** 2026-11-11
- **Owner:** `■ ARCHITECT`

## Context & Problem Statement

Stale pull requests that sit open for more than 60 minutes accumulate branch drift, block binary deployment parity across fleet hosts, and bypass current CI gates. Furthermore, CI/CD must compound engineering intelligence on every pull request so that verified behaviors can never silently regress on subsequent merges.

## Decision

1. **`INV-PR-MAX-TTL-60M-01` (`--max-pr-age-secs 3600`):**
   - No pull request may remain open and unmerged for more than `3,600` seconds (`60` minutes) without a fresh rebase onto `origin/main` and a cryptographically signed `CiGreenReceiptV1`.
   - `chinwag-ci surface-gate` enforces `max_pr_age_secs = 3600` by default and fails closed with `ERR_PR_TTL_EXCEEDED_60M` when an unmerged PR exceeds the 60-minute window.
2. **`INV-CI-BEHAVIORAL-RATCHET-01` (Compounding Expected-Behavior Contract per PR):**
   - Every task manifest (`SurfaceImpactManifestV1` / `surface-impact.yaml`) declares explicit `expected_behaviors` and `min_cassettes_count`.
   - `chinwag-ci` verifies that offline Tombstone trajectory cassettes (`.chinwag/cassettes/*.cassette.json` / `.chinwag/regressions/*.json`) and `ui-gate` deterministic invariants (`176` rules) are monotonically non-decreasing and replay green in `<50 ms` at `$0` LLM spend.
