// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Explicit skill policy; roots belong to the manifest rather than an assumed home.
#![forbid(unsafe_code)]
use crate::{FleetManifest, FleetPolicyError, FleetResult, SeatDefinition};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillPolicyRef {
    #[serde(default)]
    pub allowed_skills: Vec<String>,
    #[serde(default)]
    pub forbidden_skills: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_invocation: Option<usize>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillConfig {
    #[serde(default)]
    pub roots: Vec<PathBuf>,
    #[serde(default)]
    pub paths: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub forbidden_skills: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_invocation: Option<usize>,
}
pub struct SkillResolver;
impl SkillResolver {
    pub fn resolve(
        manifest: &FleetManifest,
        seat: &SeatDefinition,
        requested: &[String],
        cwd: &std::path::Path,
    ) -> FleetResult<Vec<String>> {
        Ok(Self::resolve_files(manifest, seat, requested, cwd)?
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    pub fn resolve_files(
        manifest: &FleetManifest,
        seat: &SeatDefinition,
        requested: &[String],
        cwd: &std::path::Path,
    ) -> FleetResult<Vec<(String, PathBuf)>> {
        let mut resolved = BTreeMap::new();
        for name in requested {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                || name == "."
                || name == ".."
            {
                return Err(FleetPolicyError::ForbiddenSkill(name.clone()));
            }
            if manifest.skills.forbidden_skills.contains(name)
                || seat.skills.forbidden_skills.contains(name)
                || !seat.skills.allowed_skills.contains(name)
            {
                return Err(FleetPolicyError::ForbiddenSkill(name.clone()));
            }
            let candidates = if let Some(path) = manifest.skills.paths.get(name) {
                vec![manifest.resolve_path(path, cwd)]
            } else {
                manifest
                    .skills
                    .roots
                    .iter()
                    .map(|root| manifest.resolve_path(root, cwd).join(name).join("SKILL.md"))
                    .collect()
            };
            let mut found_path = None;
            for path in candidates {
                if !path.exists() {
                    continue;
                }
                let mut current = PathBuf::new();
                for component in path.components() {
                    current.push(component);
                    if std::fs::symlink_metadata(&current)?
                        .file_type()
                        .is_symlink()
                    {
                        return Err(FleetPolicyError::ForbiddenSkill(format!(
                            "symlink skill: {name}"
                        )));
                    }
                }
                if path.is_file() {
                    found_path = Some(path.canonicalize()?);
                    break;
                }
            }
            let Some(resolved_path) = found_path else {
                return Err(FleetPolicyError::MissingSkill(name.clone()));
            };
            resolved.insert(name.clone(), resolved_path);
        }
        if let Some(limit) = seat
            .skills
            .max_per_invocation
            .or(manifest.skills.max_per_invocation)
            && resolved.len() > limit
        {
            return Err(FleetPolicyError::ForbiddenSkill(format!(
                "requested {} skills exceeds max_per_invocation ({limit})",
                resolved.len()
            )));
        }
        Ok(resolved.into_iter().collect())
    }
}
