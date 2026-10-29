// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Bare-bones Mission Control. Contracts and data access are separate from presentation.
#![forbid(unsafe_code)]

pub mod api;
mod app;
pub mod components;
pub mod contracts;
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
pub mod guard;
mod health;
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
pub mod planner;
mod theme;
pub mod view_model;

pub use app::{App, Route};
pub use health::{Health, health};
pub use theme::Theme;

/// Port the legacy Node planner listens on; `chinwag ui` keeps the same port.
pub const MISSION_CONTROL_PORT: u16 = 5487;
