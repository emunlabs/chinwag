// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Dev entry point. Production embeds `chinwag_ui::App` behind `chinwag ui`.
#![forbid(unsafe_code)]

fn main() {
    dioxus::launch(chinwag_ui::App);
}
