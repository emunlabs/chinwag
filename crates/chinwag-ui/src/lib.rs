// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Chinwag Mission Control in pure Rust Dioxus (CHWG-DIOXUS-1, Phase 1 scaffold).
//!
//! This crate replaces the Node/React `delivery-planner` (served on :5487) with a
//! single Rust codebase. The scaffold only proves the fullstack wiring: a themed
//! shell, a router, and one `#[get]` server function. The 13 workflow views, the
//! sqlite store, auth, and the Tokio agent listeners land in later milestones; see
//! `docs/chwg-dioxus-1/DESIGN.md`.
#![forbid(unsafe_code)]

mod app;
mod health;
mod theme;

pub use app::{App, Route};
pub use health::{Health, health};
pub use theme::Theme;

/// Port the legacy Node planner listens on; `chinwag ui` keeps the same port.
pub const MISSION_CONTROL_PORT: u16 = 5487;
