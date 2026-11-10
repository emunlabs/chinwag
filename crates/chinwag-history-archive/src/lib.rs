// Copyright (c) 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//! Derived coordinator context, never canonical task authority.
mod duckdb_ffi;
mod model;
pub use model::{Event, Manifest, digest};
mod store;
pub use store::{Archive, events, ingest, read_bounded};
mod cli;
pub use cli::run_cli;
mod pull_plan;
pub use pull_plan::{ObjectSpec, PullPlan};
mod pull;
pub use pull::pull;
mod bounded_child;
mod namespace;
