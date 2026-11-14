---
name: inspect-delivery
description: Inspect verified blind CI remediation receipts, delivery board gates, and organization credit balances.
---

# Inspect Delivery Posture

When an operator asks about release readiness, credit posture, or verification gates:

1. Query `chinwag_run_status` for the specific `run_ref` to verify blind receipt status.
2. Query `chinwag_board_status` to check remaining open verification gates.
3. Query `chinwag_credit_ledger` for read-only credit pool balance and settled receipt counts.

All remote queries return zero source bytes and zero file paths. Emun Labs is pursuing SOC 2.
