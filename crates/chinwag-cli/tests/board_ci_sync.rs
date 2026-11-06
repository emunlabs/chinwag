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

#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_CASE: AtomicU64 = AtomicU64::new(0);

fn fixture_dir(tag: &str) -> PathBuf {
    let n = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "chinwag-board-cli-integ-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn cli_tasks_init_board_push_and_ci_report_lifecycle() {
    let dir = fixture_dir("lifecycle");
    let dir_str = dir.to_string_lossy().to_string();

    // 1. chinwag tasks init
    let init_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "tasks",
            "init",
            "--tasks-dir",
            &dir_str,
            "--id",
            "CHWG-0500",
            "--title",
            "Native Board & CI Sync Verification",
            "--tier",
            "L",
            "--author",
            "RUST#integ-thread-01",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(init_out.status.code(), Some(0));
    let init_json: Value = serde_json::from_slice(&init_out.stdout).unwrap();
    assert_eq!(init_json["ok"], true);
    assert_eq!(init_json["seed_issue_id"], "CHWG-0500");

    // 2. chinwag board push --dry-run
    let push_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(["board", "push", "--tasks-dir", &dir_str, "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(push_out.status.code(), Some(0));
    let push_json: Value = serde_json::from_slice(&push_out.stdout).unwrap();
    assert_eq!(push_json["ok"], true);
    assert_eq!(push_json["issue_count"], 1);

    // 3. chinwag ci-report --status pass --push-boards (with INV-TIER-LOCK-01 downgrade L -> S on 64 LOC)
    let pass_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "ci-report",
            "--issue",
            "CHWG-0500",
            "--status",
            "pass",
            "--gate",
            "H1+H2+H5",
            "--loc-changed",
            "64",
            "--push-boards",
            "--tasks-dir",
            &dir_str,
        ])
        .output()
        .unwrap();
    assert_eq!(pass_out.status.code(), Some(0));
    let pass_json: Value = serde_json::from_slice(&pass_out.stdout).unwrap();
    assert_eq!(pass_json["board_status"], "05_SHIPPED_VERIFIED");
    assert_eq!(pass_json["effective_tier"], "S");
    assert_eq!(pass_json["tier_downgraded"], true);
    assert_eq!(pass_json["chips_minted_delta"], 150);
    assert_eq!(pass_json["surv_status"], "PENDING_168H");

    // 4. chinwag ci-report --status fail (in-flight direct-to-author fast path vs main regression)
    let fail_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "ci-report",
            "--issue",
            "CHWG-0500",
            "--status",
            "fail",
            "--gate",
            "H2-Cleanroom-Regression",
            "--is-main-regression",
            "--delivery-licensed",
            "--push-boards",
            "--tasks-dir",
            &dir_str,
        ])
        .output()
        .unwrap();
    assert_eq!(fail_out.status.code(), Some(0));
    let fail_json: Value = serde_json::from_slice(&fail_out.stdout).unwrap();
    assert_eq!(fail_json["surv_status"], "FAILED_REGRESSION_CLAWBACK");
    assert_eq!(fail_json["chips_delta"], -150);
    assert_eq!(fail_json["p0_regression_issue_id"], "CHWG-0500-CI-FAIL");
    assert_eq!(
        fail_json["routing"]["primary_recipient"],
        "@RUST#integ-thread-01"
    );
    assert_eq!(fail_json["routing"]["cc_recipients"][0], "@DELIVERY");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_board_push_exits_78_on_zero_leak_violation() {
    let dir = fixture_dir("leak-exit-78");
    let dir_str = dir.to_string_lossy().to_string();

    let _ = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "tasks",
            "init",
            "--tasks-dir",
            &dir_str,
            "--id",
            "CHWG-0501",
            "--title",
            "Secret Token Leak ghp_1234567890abcdef",
        ])
        .output()
        .unwrap();

    let push_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(["board", "push", "--tasks-dir", &dir_str, "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(push_out.status.code(), Some(78));
    let _ = fs::remove_dir_all(&dir);
}
