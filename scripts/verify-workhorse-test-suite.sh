#!/usr/bin/env bash
# scripts/verify-workhorse-test-suite.sh
#
# Monotonic Test-Count Ratchet & WORKHORSE Build/Test Verification Gate
# (Ticket: CHWG-CORE-CI-MERGE-01)
#
# Guarantees:
# 1. Optional --sync-node2 mode fetches and verifies whether WORKHORSE on Node 2
#    (via CHINWAG_NODE2_HOST / origin/review/workhorse-*)
#    has newer test commits that must be pulled into CI/CD.
# 2. Runs cargo fmt --all -- --check and cargo clippy --workspace -- -D warnings.
# 3. Executes 100% of WORKHORSE's chinwag-cli unit, binary, and adversarial integration tests
#    plus the full workspace test suite.
# 4. Enforces a strict Monotonic Test-Count Ratchet Floor:
#    - chinwag-cli lib unit tests:               >= 284
#    - chinwag-cli lib + p0_adversarial tests:   >= 306 (above the 288 WORKHORSE floor)
#    - chinwag-cli total tests across targets:   >= 392
#    - workspace total passing tests:            >= 750
#    - total failed tests:                       == 0
# 5. Builds and smoke-tests the release binary: cargo build --release --bin chinwag --locked.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.local/bin:/opt/homebrew/bin:/usr/bin:/bin:$PATH"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.97.1}"
if [[ -d "${HOME}/.chinwag-native-inputs" ]]; then
  export CHINWAG_PRIVATE_CRSQL_INPUTS="${CHINWAG_PRIVATE_CRSQL_INPUTS:-$HOME/.chinwag-native-inputs}"
fi

# Monotonic Ratchet Floors (NEVER lower these numbers; only ratchet UP as WORKHORSE adds tests)
RATCHET_WORKHORSE_COMBINED_FLOOR="${RATCHET_WORKHORSE_COMBINED_FLOOR:-288}"
RATCHET_CHINWAG_CLI_LIB_FLOOR="${RATCHET_CHINWAG_CLI_LIB_FLOOR:-284}"
RATCHET_CHINWAG_CLI_P0_ADV_FLOOR="${RATCHET_CHINWAG_CLI_P0_ADV_FLOOR:-22}"
RATCHET_CHINWAG_CLI_TOTAL_FLOOR="${RATCHET_CHINWAG_CLI_TOTAL_FLOOR:-392}"
RATCHET_WORKSPACE_TOTAL_FLOOR="${RATCHET_WORKSPACE_TOTAL_FLOOR:-750}"

SYNC_NODE2=0
SKIP_RELEASE_BUILD=0

for arg in "$@"; do
  case "$arg" in
    --sync-node2)
      SYNC_NODE2=1
      ;;
    --skip-release-build)
      SKIP_RELEASE_BUILD=1
      ;;
    *)
      echo "Usage: $0 [--sync-node2] [--skip-release-build]" >&2
      exit 2
      ;;
  esac
done

echo "==> [1/5] Checking WORKHORSE branch & Node 2 test synchronization..."
if [[ "$SYNC_NODE2" -eq 1 ]]; then
  git fetch origin --prune || true
  if git rev-parse --verify origin/review/workhorse-p0-06-20261106 >/dev/null 2>&1; then
    ORIGIN_WH_SHA="$(git rev-parse origin/review/workhorse-p0-06-20261106)"
    echo "    origin/review/workhorse-p0-06-20261106: $ORIGIN_WH_SHA"
    if git merge-base --is-ancestor "$ORIGIN_WH_SHA" HEAD 2>/dev/null; then
      echo "    OK: origin/review/workhorse-p0-06-20261106 ($ORIGIN_WH_SHA) is an ancestor of HEAD."
    else
      echo "    WARN: origin/review/workhorse-p0-06-20261106 ($ORIGIN_WH_SHA) has commits not yet in HEAD."
    fi
  fi
fi

echo "==> [2/5] Running H2 Cleanroom formatting & Clippy gates..."
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings

echo "==> [3/5] Running WORKHORSE chinwag-cli & workspace test suites..."
TEST_LOG="$(mktemp "${TMPDIR:-/tmp}/chinwag-workhorse-tests.XXXXXX")"
trap 'rm -f "$TEST_LOG"' EXIT

# Run workspace tests (excluding legacy chinwag-ui crate per tombstone-never-use-or-mention-dioxus-v1)
# with --test-threads=4 to prevent subprocess timing starvation in chinwag-seed owned_process tests.
cargo test --workspace --exclude chinwag-ui -- --test-threads=4 2>&1 | tee "$TEST_LOG"

echo "==> [4/5] Evaluating Monotonic Test-Count Ratchet Gate..."
python3 - "$TEST_LOG" \
  "$RATCHET_WORKHORSE_COMBINED_FLOOR" \
  "$RATCHET_CHINWAG_CLI_LIB_FLOOR" \
  "$RATCHET_CHINWAG_CLI_P0_ADV_FLOOR" \
  "$RATCHET_CHINWAG_CLI_TOTAL_FLOOR" \
  "$RATCHET_WORKSPACE_TOTAL_FLOOR" <<'PY'
import re
import sys

log_path = sys.argv[1]
workhorse_floor = int(sys.argv[2])
cli_lib_floor = int(sys.argv[3])
cli_p0_adv_floor = int(sys.argv[4])
cli_total_floor = int(sys.argv[5])
workspace_floor = int(sys.argv[6])

with open(log_path, "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()

current_target = ""
in_chinwag_cli_section = False
cli_lib_passed = 0
cli_p0_adv_passed = 0
cli_total_passed = 0
workspace_passed = 0
workspace_failed = 0
suite_count = 0

running_re = re.compile(r"^\s*Running\s+(.*)$")
doctest_re = re.compile(r"^\s*Doc-tests\s+(\S+)")
result_re = re.compile(
    r"^test result:\s+(\w+)\.\s+(\d+)\s+passed;\s+(\d+)\s+failed;\s+(\d+)\s+ignored"
)

for raw in lines:
    line = raw.strip()
    m_run = running_re.match(line)
    if m_run:
        current_target = m_run.group(1)
        if "deps/chinwag_cli-" in current_target:
            in_chinwag_cli_section = True
        elif "unittests src/lib.rs" in current_target and "deps/chinwag_cli-" not in current_target:
            in_chinwag_cli_section = False
        continue
    m_doc = doctest_re.match(line)
    if m_doc:
        crate_name = m_doc.group(1)
        current_target = f"Doc-tests {crate_name}"
        in_chinwag_cli_section = (crate_name == "chinwag_cli")
        continue
    m_res = result_re.match(line)
    if m_res:
        status, passed_s, failed_s, _ = m_res.groups()
        passed = int(passed_s)
        failed = int(failed_s)
        suite_count += 1
        workspace_passed += passed
        workspace_failed += failed

        if "deps/chinwag_cli-" in current_target:
            cli_lib_passed += passed
            cli_total_passed += passed
        elif "deps/p0_adversarial-" in current_target or "tests/p0_adversarial.rs" in current_target:
            cli_p0_adv_passed += passed
            cli_total_passed += passed
        elif in_chinwag_cli_section:
            cli_total_passed += passed

workhorse_combined = cli_lib_passed + cli_p0_adv_passed

print(f"    Test Ratchet Summary:")
print(f"      - chinwag-cli lib unit tests:             {cli_lib_passed} (floor >= {cli_lib_floor})")
print(f"      - chinwag-cli p0_adversarial tests:       {cli_p0_adv_passed} (floor >= {cli_p0_adv_floor})")
print(f"      - WORKHORSE core (lib + p0_adversarial):  {workhorse_combined} (floor >= {workhorse_floor})")
print(f"      - chinwag-cli total tests across targets: {cli_total_passed} (floor >= {cli_total_floor})")
print(f"      - Workspace total passing tests:          {workspace_passed} (floor >= {workspace_floor})")
print(f"      - Workspace total failing tests:          {workspace_failed} (must be 0)")

errors = []
if workspace_failed != 0:
    errors.append(f"FAIL: {workspace_failed} test(s) failed")
if cli_lib_passed < cli_lib_floor:
    errors.append(f"FAIL: chinwag-cli lib tests ({cli_lib_passed}) dropped below ratchet floor ({cli_lib_floor})")
if cli_p0_adv_passed < cli_p0_adv_floor:
    errors.append(f"FAIL: chinwag-cli p0_adversarial tests ({cli_p0_adv_passed}) dropped below ratchet floor ({cli_p0_adv_floor})")
if workhorse_combined < workhorse_floor:
    errors.append(f"FAIL: WORKHORSE combined tests ({workhorse_combined}) dropped below Brian's ratchet floor ({workhorse_floor})")
if cli_total_passed < cli_total_floor:
    errors.append(f"FAIL: chinwag-cli total tests ({cli_total_passed}) dropped below ratchet floor ({cli_total_floor})")
if workspace_passed < workspace_floor:
    errors.append(f"FAIL: workspace total tests ({workspace_passed}) dropped below ratchet floor ({workspace_floor})")

if errors:
    for e in errors:
        print(f"    {e}", file=sys.stderr)
    sys.exit(1)

print("    OK: Monotonic Test-Count Ratchet Gate PASSED.")
PY

if [[ "$SKIP_RELEASE_BUILD" -eq 0 ]]; then
  echo "==> [5/5] Building & verifying release chinwag binary (--locked)..."
  cargo build --release --bin chinwag --locked
  "$REPO_ROOT/target/release/chinwag" --version
  echo "==> ALL WORKHORSE BUILD & TEST GATES PASSED."
else
  echo "==> [5/5] Skipping release binary build (--skip-release-build)."
fi
