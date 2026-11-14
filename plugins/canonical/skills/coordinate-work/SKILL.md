---
name: coordinate-work
description: Coordinate blind organization delivery gates, run status, and handoff readiness with Chinwag.
---

# Coordinate Work with Chinwag

Use Chinwag's blind organization tools to inspect current engineering posture without exposing repository source files:

1. Call `chinwag_org_status` with the caller's `org_id` to inspect overall velocity and blind coordination health.
2. Call `chinwag_board_status` with `org_id` to inspect active delivery gates and step progress.
3. Call `chinwag_run_status` with `org_id` and `run_ref` to verify whether a pair review, QA check, or CI remediation run has settled.

Never request raw source snippets over remote blind tools. Emun Labs is pursuing SOC 2.
