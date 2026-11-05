//! Field-specific normalization and canonical task specification/control digests.

use crate::task_dependency::{DependencyCommitment, canonicalize_dependencies};
use crate::task_ref::{
    MAX_ID_UTF8_BYTES, MAX_LIST_ITEMS, MAX_SCALAR_BYTES, Sha256Digest,
    TaskContractError, TaskKey, encode_bytes_field, encode_sorted_distinct_set,
    encode_str_field, encode_u64, validate_id,
};
use serde::Deserialize;
use std::collections::BTreeMap;

pub const TASK_SPEC_V1_DOMAIN: &[u8] = b"chinwag-task-spec-v1\0";
pub const TASK_CONTROL_V1_DOMAIN: &[u8] = b"chinwag-task-control-v1\0";

pub fn normalize_line_endings(input: &str) -> Result<String, TaskContractError> {
    let mut characters = input.chars();
    let mut normalized = String::with_capacity(input.len());
    while let Some(character) = characters.next() {
        if character == '\r' {
            if characters.next() != Some('\n') {
                return Err(TaskContractError::BareCarriageReturn);
            }
            normalized.push('\n');
        } else {
            normalized.push(character);
        }
    }
    Ok(normalized)
}

fn normalize_prose(
    input: &str,
    field: &'static str,
    maximum: usize,
) -> Result<String, TaskContractError> {
    // Bound the raw input before allocating. CRLF never expands on normalization.
    if input.len() > maximum {
        return Err(TaskContractError::LimitExceeded(field));
    }
    let normalized = normalize_line_endings(input)?;
    let trimmed = normalized.trim_matches([' ', '\t']);
    if trimmed.is_empty() || trimmed.contains(['\n', '\0']) {
        return Err(TaskContractError::InvalidField(field));
    }
    Ok(trimmed.to_owned())
}

fn normalize_scalar(input: &str, field: &'static str) -> Result<String, TaskContractError> {
    if input.len() > MAX_SCALAR_BYTES {
        return Err(TaskContractError::LimitExceeded(field));
    }
    normalize_line_endings(input)
}

fn normalize_scalars(
    items: &[String],
    field: &'static str,
) -> Result<Vec<String>, TaskContractError> {
    if items.len() > MAX_LIST_ITEMS {
        return Err(TaskContractError::LimitExceeded(field));
    }
    items.iter().map(|item| normalize_scalar(item, field)).collect()
}

/// A strict raw JSON-compatible schema: serde rejects missing/duplicate fields,
/// unknown fields, and scalar/list substitutions, including in dependencies.
/// Feed the original deserializer directly; a prebuilt JSON map may already have
/// discarded duplicate keys. The source reader must bound the whole input file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTaskSpecV1 {
    pub task_id: String,
    pub title: String,
    pub scope: String,
    pub promised_interfaces: Vec<String>,
    pub acceptance_checks: Vec<String>,
    pub dependencies: Vec<RawDependencyV1>,
    pub reviewer_role: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDependencyV1 {
    pub workspace_id: String,
    pub task_source_id: String,
    pub task_id: String,
    pub target_spec_digest: String,
    pub completion_policy_digest: String,
}

impl RawTaskSpecV1 {
    pub fn normalize(self, dependent_key: &TaskKey) -> Result<NormalizedTaskSpecV1, TaskContractError> {
        if self.dependencies.len() > MAX_LIST_ITEMS {
            return Err(TaskContractError::LimitExceeded("dependencies"));
        }
        let dependencies = self.dependencies.into_iter().map(|raw| {
            Ok(DependencyCommitment {
                target_key: TaskKey::new(raw.workspace_id, raw.task_source_id, raw.task_id)?,
                target_spec_digest: Sha256Digest::from_hex(&raw.target_spec_digest)?,
                completion_policy_digest: Sha256Digest::from_hex(&raw.completion_policy_digest)?,
            })
        }).collect::<Result<Vec<_>, TaskContractError>>()?;
        NormalizedTaskSpecV1::from_fields(dependent_key, vec![
            ("task_id".into(), RawSpecValue::Scalar(self.task_id)),
            ("title".into(), RawSpecValue::Scalar(self.title)),
            ("scope".into(), RawSpecValue::Scalar(self.scope)),
            ("promised_interfaces".into(), RawSpecValue::List(self.promised_interfaces)),
            ("acceptance_checks".into(), RawSpecValue::List(self.acceptance_checks)),
            ("dependencies".into(), RawSpecValue::Dependencies(dependencies)),
            ("reviewer_role".into(), RawSpecValue::Scalar(self.reviewer_role)),
        ])
    }
}

#[derive(Debug, Clone)]
pub enum RawSpecValue {
    Scalar(String),
    List(Vec<String>),
    Dependencies(Vec<DependencyCommitment>),
}

/// Private normalized fields ensure every infallible transcript is validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedTaskSpecV1 {
    task_id: String,
    title: String,
    scope: String,
    promised_interfaces: Vec<String>,
    acceptance_checks: Vec<String>,
    dependencies: Vec<DependencyCommitment>,
    reviewer_role: String,
}

impl NormalizedTaskSpecV1 {
    /// An ordered field stream preserves duplicates until they can be rejected.
    pub fn from_fields(
        dependent_key: &TaskKey,
        fields: Vec<(String, RawSpecValue)>,
    ) -> Result<Self, TaskContractError> {
        dependent_key.validate()?;
        let mut values = BTreeMap::new();
        for (name, value) in fields {
            let field = match name.as_str() {
                "task_id" => "task_id",
                "title" => "title",
                "scope" => "scope",
                "promised_interfaces" => "promised_interfaces",
                "acceptance_checks" => "acceptance_checks",
                "dependencies" => "dependencies",
                "reviewer_role" => "reviewer_role",
                _ => return Err(TaskContractError::UnknownField(name)),
            };
            if values.insert(field, value).is_some() {
                return Err(TaskContractError::DuplicateField(field));
            }
        }
        let mut take = |field: &'static str| {
            values.remove(field).ok_or(TaskContractError::MissingField(field))
        };
        let scalar = |field: &'static str, value: RawSpecValue| match value {
            RawSpecValue::Scalar(text) => Ok(text),
            _ => Err(TaskContractError::AmbiguousField(field)),
        };
        let list = |field: &'static str, value: RawSpecValue| match value {
            RawSpecValue::List(items) => Ok(items),
            _ => Err(TaskContractError::AmbiguousField(field)),
        };
        let task_id = scalar("task_id", take("task_id")?)?;
        validate_id(&task_id, "task_id")?;
        if task_id != dependent_key.task_id {
            return Err(TaskContractError::IdentityConflict);
        }
        let title = normalize_prose(&scalar("title", take("title")?)?, "title", MAX_SCALAR_BYTES)?;
        let scope = normalize_scalar(&scalar("scope", take("scope")?)?, "scope")?;
        let promised_interfaces = normalize_scalars(
            &list("promised_interfaces", take("promised_interfaces")?)?, "promised_interfaces",
        )?;
        let acceptance_checks = normalize_scalars(
            &list("acceptance_checks", take("acceptance_checks")?)?, "acceptance_checks",
        )?;
        let dependencies = match take("dependencies")? {
            RawSpecValue::Dependencies(items) => canonicalize_dependencies(dependent_key, items)?,
            _ => return Err(TaskContractError::AmbiguousField("dependencies")),
        };
        let reviewer_role = normalize_prose(
            &scalar("reviewer_role", take("reviewer_role")?)?, "reviewer_role", MAX_ID_UTF8_BYTES,
        )?;
        Ok(Self { task_id, title, scope, promised_interfaces, acceptance_checks, dependencies, reviewer_role })
    }

    pub fn task_id(&self) -> &str { &self.task_id }
    pub fn title(&self) -> &str { &self.title }
    pub fn scope(&self) -> &str { &self.scope }
    pub fn promised_interfaces(&self) -> &[String] { &self.promised_interfaces }
    pub fn acceptance_checks(&self) -> &[String] { &self.acceptance_checks }
    pub fn dependencies(&self) -> &[DependencyCommitment] { &self.dependencies }
    pub fn reviewer_role(&self) -> &str { &self.reviewer_role }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = TASK_SPEC_V1_DOMAIN.to_vec();
        encoded.extend(encode_str_field("task-spec-v1"));
        encoded.extend(encode_str_field(&self.task_id));
        encoded.extend(encode_str_field(&self.title));
        encoded.extend(encode_str_field(&self.scope));
        append_strings(&mut encoded, &self.promised_interfaces);
        append_strings(&mut encoded, &self.acceptance_checks);
        encoded.extend(encode_u64(self.dependencies.len() as u64));
        for dependency in &self.dependencies {
            encoded.extend(dependency.encode());
        }
        encoded.extend(encode_str_field(&self.reviewer_role));
        encoded
    }

    pub fn task_spec_digest(&self) -> Sha256Digest {
        Sha256Digest::of(&self.encode())
    }
}

fn append_strings(encoded: &mut Vec<u8>, strings: &[String]) {
    encoded.extend(encode_u64(strings.len() as u64));
    for string in strings {
        encoded.extend(encode_str_field(string));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ExecutionMode {
    #[serde(rename = "REVIEW_ONLY")]
    ReviewOnly,
    #[serde(rename = "IMPLEMENTATION")]
    Implementation,
}

impl ExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReviewOnly => "REVIEW_ONLY",
            Self::Implementation => "IMPLEMENTATION",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskControlV1 {
    pub task_key: TaskKey,
    pub owner_principal: String,
    pub reviewer_role: String,
    pub execution_mode: ExecutionMode,
    pub implementation_authorized: bool,
    pub deployment_authorized: bool,
    pub automatic_dispatch: bool,
    pub allowed_action_names: Vec<String>,
    pub review_policy_digest: Sha256Digest,
}

impl TaskControlV1 {
    pub fn validate(&self) -> Result<(), TaskContractError> {
        self.task_key.validate()?;
        validate_id(&self.owner_principal, "owner_principal")?;
        normalize_prose(&self.reviewer_role, "reviewer_role", MAX_ID_UTF8_BYTES)?;
        if self.execution_mode == ExecutionMode::ReviewOnly
            && (self.implementation_authorized || self.deployment_authorized || self.automatic_dispatch)
        {
            return Err(TaskContractError::ContradictoryControls);
        }
        if self.allowed_action_names.is_empty() {
            return Err(TaskContractError::MissingField("allowed_action_names"));
        }
        if self.allowed_action_names.len() > MAX_LIST_ITEMS {
            return Err(TaskContractError::LimitExceeded("allowed_action_names"));
        }
        for action in &self.allowed_action_names {
            validate_id(action, "allowed action name")?;
        }
        // The set encoder rejects duplicates as well as producing its order.
        encode_sorted_distinct_set(self.allowed_action_names.iter()
            .map(|action| encode_str_field(action)).collect())?;
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TaskContractError> {
        self.validate()?;
        let mut encoded = TASK_CONTROL_V1_DOMAIN.to_vec();
        encoded.extend(encode_bytes_field(&self.task_key.encode()));
        encoded.extend(encode_str_field(&self.owner_principal));
        encoded.extend(encode_str_field(&normalize_prose(
            &self.reviewer_role, "reviewer_role", MAX_ID_UTF8_BYTES,
        )?));
        encoded.extend(encode_str_field(self.execution_mode.as_str()));
        encoded.extend([
            u8::from(self.implementation_authorized),
            u8::from(self.deployment_authorized),
            u8::from(self.automatic_dispatch),
        ]);
        encoded.extend(encode_sorted_distinct_set(self.allowed_action_names.iter()
            .map(|action| encode_str_field(action)).collect())?);
        encoded.extend(self.review_policy_digest.encode_typed());
        Ok(encoded)
    }

    pub fn task_control_digest(&self) -> Result<Sha256Digest, TaskContractError> {
        Ok(Sha256Digest::of(&self.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(task_id: &str) -> TaskKey {
        TaskKey::new("p0-fixture-workspace", "00000000000000000000000000000001", task_id).unwrap()
    }

    fn fields() -> Vec<(String, RawSpecValue)> {
        vec![
            ("task_id".into(), RawSpecValue::Scalar("A".into())),
            ("title".into(), RawSpecValue::Scalar(" \tPlan\t ".into())),
            ("scope".into(), RawSpecValue::Scalar(" a\r\n".into())),
            ("promised_interfaces".into(), RawSpecValue::List(vec![" api\t".into()])),
            ("acceptance_checks".into(), RawSpecValue::List(vec![" run\r\n".into()])),
            ("dependencies".into(), RawSpecValue::Dependencies(vec![])),
            ("reviewer_role".into(), RawSpecValue::Scalar(" QA ".into())),
        ]
    }

    fn spec() -> NormalizedTaskSpecV1 {
        NormalizedTaskSpecV1::from_fields(&key("A"), fields()).unwrap()
    }

    fn control() -> TaskControlV1 {
        TaskControlV1 {
            task_key: key("A"),
            owner_principal: "INDEX".into(),
            reviewer_role: "QA".into(),
            execution_mode: ExecutionMode::ReviewOnly,
            implementation_authorized: false,
            deployment_authorized: false,
            automatic_dispatch: false,
            allowed_action_names: vec!["zz".into(), "a".into()],
            review_policy_digest: Sha256Digest([0x33; 32]),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn p0_contract_crlf_normalized_and_bare_cr_rejected() {
        assert_eq!(normalize_line_endings("a\r\nb\nc\r\n").unwrap(), "a\nb\nc\n");
        for raw in ["\r", "a\rb", "\r\r\n", "a\r\nb\r"] {
            assert_eq!(normalize_line_endings(raw), Err(TaskContractError::BareCarriageReturn));
        }
    }

    #[test]
    fn p0_contract_whitespace_trim_only_title_and_reviewer_role() {
        let normalized = spec();
        assert_eq!(normalized.task_id(), "A");
        assert_eq!(normalized.title(), "Plan");
        assert_eq!(normalized.reviewer_role(), "QA");
        assert_eq!(normalized.scope(), " a\n");
        assert_eq!(normalized.promised_interfaces(), &[" api\t"]);
        assert_eq!(normalized.acceptance_checks(), &[" run\n"]);
        assert_eq!(normalize_prose("\u{a0}A\u{a0}", "title", 256).unwrap(), "\u{a0}A\u{a0}");
        assert_eq!(normalize_prose(" A  B ", "title", 256).unwrap(), "A  B");
        for raw in ["", " \t ", "a\nb", "a\r\nb"] {
            assert!(normalize_prose(raw, "title", 256).is_err());
        }
    }

    #[test]
    fn p0_contract_unicode_nfc_nfd_preserved_distinct() {
        let mut composed = fields();
        composed[1].1 = RawSpecValue::Scalar("é".into());
        let mut decomposed = fields();
        decomposed[1].1 = RawSpecValue::Scalar("e\u{301}".into());
        let a = NormalizedTaskSpecV1::from_fields(&key("A"), composed).unwrap();
        let b = NormalizedTaskSpecV1::from_fields(&key("A"), decomposed).unwrap();
        assert_eq!(a.title(), "é");
        assert_eq!(b.title(), "e\u{301}");
        assert_ne!(a.task_spec_digest(), b.task_spec_digest());
    }

    #[test]
    fn p0_contract_task_spec_v1_golden_transcript_and_digest() {
        let normalized = spec();
        assert_eq!(normalized.encode().len(), 133);
        assert_eq!(hex(&normalized.encode()), concat!(
            "6368696e7761672d7461736b2d737065632d763100",
            "000000000000000c7461736b2d737065632d7631",
            "0000000000000001410000000000000004506c616e",
            "000000000000000320610a0000000000000001",
            "000000000000000520617069090000000000000001",
            "00000000000000052072756e0a0000000000000000",
            "00000000000000025141"
        ));
        assert_eq!(normalized.task_spec_digest().to_string(),
            "c521339112797b0363fd9d52d8bca2ca128b6c3b17b80b4d6e5890fa0228c7fc");
    }

    #[test]
    fn p0_contract_task_spec_digest_order_and_whitespace_sensitive() {
        let original = spec();
        let mut reordered_fields = fields();
        reordered_fields.reverse();
        assert_eq!(original, NormalizedTaskSpecV1::from_fields(&key("A"), reordered_fields).unwrap());
        for field in [2, 3, 4] {
            let mut changed = fields();
            changed[field].1 = if field == 2 {
                RawSpecValue::Scalar("a\r\n".into())
            } else {
                RawSpecValue::List(vec!["run".into()])
            };
            assert_ne!(original.task_spec_digest(),
                NormalizedTaskSpecV1::from_fields(&key("A"), changed).unwrap().task_spec_digest());
        }
        let mut a = fields();
        a[3].1 = RawSpecValue::List(vec!["a".into(), "b".into()]);
        let mut b = a.clone();
        b[3].1 = RawSpecValue::List(vec!["b".into(), "a".into()]);
        assert_ne!(NormalizedTaskSpecV1::from_fields(&key("A"), a).unwrap().task_spec_digest(),
            NormalizedTaskSpecV1::from_fields(&key("A"), b).unwrap().task_spec_digest());
    }

    #[test]
    fn p0_contract_task_spec_v1_dependency_commitment_sensitivity() {
        let dependency = DependencyCommitment {
            target_key: key("B"),
            target_spec_digest: Sha256Digest([1; 32]),
            completion_policy_digest: Sha256Digest([2; 32]),
        };
        let digest = |dependency| {
            let mut input = fields();
            input[5].1 = RawSpecValue::Dependencies(vec![dependency]);
            NormalizedTaskSpecV1::from_fields(&key("A"), input).unwrap().task_spec_digest()
        };
        let original = digest(dependency.clone());
        assert_ne!(original, spec().task_spec_digest());
        for field in 0..3 {
            let mut changed = dependency.clone();
            match field {
                0 => changed.target_key.task_source_id = "00000000000000000000000000000002".into(),
                1 => changed.target_spec_digest = Sha256Digest([3; 32]),
                _ => changed.completion_policy_digest = Sha256Digest([3; 32]),
            }
            assert_ne!(original, digest(changed));
        }
    }

    #[test]
    fn p0_contract_raw_field_stream_rejects_duplicate_unknown_ambiguous_missing() {
        let mut duplicate = fields();
        duplicate.push(duplicate[1].clone());
        assert_eq!(NormalizedTaskSpecV1::from_fields(&key("A"), duplicate), Err(TaskContractError::DuplicateField("title")));
        let mut unknown = fields();
        unknown.push(("execute".into(), RawSpecValue::Scalar("yes".into())));
        assert!(matches!(NormalizedTaskSpecV1::from_fields(&key("A"), unknown), Err(TaskContractError::UnknownField(_))));
        let mut ambiguous = fields();
        ambiguous[2].1 = RawSpecValue::List(vec!["scope".into()]);
        assert_eq!(NormalizedTaskSpecV1::from_fields(&key("A"), ambiguous), Err(TaskContractError::AmbiguousField("scope")));
        let mut missing = fields();
        missing.pop();
        assert_eq!(NormalizedTaskSpecV1::from_fields(&key("A"), missing), Err(TaskContractError::MissingField("reviewer_role")));
    }

    #[test]
    fn p0_contract_raw_json_rejects_duplicate_unknown_and_scalar_list() {
        let input = r#"{"task_id":"A","title":"Plan","scope":" a\r\n","promised_interfaces":[" api\t"],"acceptance_checks":[" run\r\n"],"dependencies":[],"reviewer_role":"QA"}"#;
        let raw: RawTaskSpecV1 = serde_json::from_str(input).unwrap();
        assert_eq!(raw.normalize(&key("A")).unwrap(), spec());
        for malformed in [
            input.replacen("\"title\":\"Plan\"", "\"title\":\"Plan\",\"title\":\"Other\"", 1),
            input.replacen("\"scope\":\" a\\r\\n\"", "\"scope\":[\"a\"]", 1),
            input.replacen("\"title\":\"Plan\"", "\"title\":\"Plan\",\"execute\":true", 1),
            input.replacen("\"dependencies\":[]", "\"dependencies\":null", 1),
            format!("{input} trailing"),
        ] {
            assert!(serde_json::from_str::<RawTaskSpecV1>(&malformed).is_err(), "{malformed}");
        }
    }

    #[test]
    fn p0_contract_normalization_bounds_and_exact_task_id() {
        assert!(normalize_scalar(&"x".repeat(MAX_SCALAR_BYTES), "scope").is_ok());
        assert!(normalize_scalar(&"x".repeat(MAX_SCALAR_BYTES + 1), "scope").is_err());
        assert!(normalize_scalars(&vec![String::new(); MAX_LIST_ITEMS], "interfaces").is_ok());
        assert!(normalize_scalars(&vec![String::new(); MAX_LIST_ITEMS + 1], "interfaces").is_err());
        for id in [" A", "A ", "A\r\n", "B"] {
            let mut input = fields();
            input[0].1 = RawSpecValue::Scalar(id.into());
            assert!(NormalizedTaskSpecV1::from_fields(&key("A"), input).is_err());
        }
    }

    #[test]
    fn p0_contract_task_control_v1_golden_transcript_and_digest() {
        let value = control();
        let encoded = value.encode().unwrap();
        assert_eq!(encoded.len(), 235);
        assert_eq!(hex(&encoded), concat!(
            "6368696e7761672d7461736b2d636f6e74726f6c2d763100",
            "000000000000004d000000000000001470302d666978747572652d776f726b7370616365",
            "00000000000000203030303030303030303030303030303030303030303030303030303030303031",
            "0000000000000001410000000000000005494e444558",
            "00000000000000025141000000000000000b5245564945575f4f4e4c59",
            "000000000000000000000200000000000000016100000000000000027a7a",
            "00000000000000067368613235360000000000000020",
            "3333333333333333333333333333333333333333333333333333333333333333"
        ));
        assert_eq!(value.task_control_digest().unwrap().to_string(),
            "2402bf136b5eddfe39f1bca7a7fbfa461a2e6e31a016dcbf9f96cbfa940b1c43");
    }

    #[test]
    fn p0_contract_task_control_contradictory_review_only_held() {
        for flag in 0..3 {
            let mut value = control();
            match flag {
                0 => value.implementation_authorized = true,
                1 => value.deployment_authorized = true,
                _ => value.automatic_dispatch = true,
            }
            assert_eq!(value.encode(), Err(TaskContractError::ContradictoryControls));
            value.execution_mode = ExecutionMode::Implementation;
            assert!(value.encode().is_ok());
        }
    }

    #[test]
    fn p0_contract_task_control_missing_owner_role_and_actions_held() {
        for field in 0..4 {
            let mut value = control();
            match field {
                0 => value.owner_principal.clear(),
                1 => value.reviewer_role.clear(),
                2 => value.allowed_action_names.clear(),
                _ => value.allowed_action_names.push(String::new()),
            }
            assert!(value.encode().is_err());
        }
        let mut value = control();
        value.allowed_action_names = vec!["review".into(); 2];
        assert_eq!(value.encode(), Err(TaskContractError::DuplicateSetItem));
    }

    #[test]
    fn p0_contract_task_control_set_order_and_all_commitments_bound() {
        let original = control();
        let digest = original.task_control_digest().unwrap();
        let mut reordered = original.clone();
        reordered.allowed_action_names.reverse();
        assert_eq!(digest, reordered.task_control_digest().unwrap());
        for field in 0..5 {
            let mut value = original.clone();
            match field {
                0 => value.task_key.task_id = "B".into(),
                1 => value.owner_principal = "OTHER".into(),
                2 => value.reviewer_role = "ARCH".into(),
                3 => value.review_policy_digest = Sha256Digest([4; 32]),
                _ => value.execution_mode = ExecutionMode::Implementation,
            }
            assert_ne!(digest, value.task_control_digest().unwrap());
        }
    }

    #[test]
    fn p0_contract_task_spec_dependency_order_canonical_and_duplicates_held() {
        let first = DependencyCommitment {
            target_key: key("B"),
            target_spec_digest: Sha256Digest([1; 32]),
            completion_policy_digest: Sha256Digest([2; 32]),
        };
        let mut second = first.clone();
        second.target_key = key("C");
        let build = |dependencies| {
            let mut input = fields();
            input[5].1 = RawSpecValue::Dependencies(dependencies);
            NormalizedTaskSpecV1::from_fields(&key("A"), input)
        };
        assert_eq!(build(vec![first.clone(), second.clone()]).unwrap(),
            build(vec![second, first.clone()]).unwrap());
        assert_eq!(build(vec![first.clone(), first]), Err(TaskContractError::DuplicateDependency));
    }

    #[test]
    fn p0_contract_task_control_normalizes_role_and_binds_boolean_bytes() {
        let mut value = control();
        value.reviewer_role = " \tQA\t ".into();
        assert_eq!(value.task_control_digest().unwrap(), control().task_control_digest().unwrap());
        value.execution_mode = ExecutionMode::Implementation;
        let original = value.task_control_digest().unwrap();
        for flag in 0..3 {
            let mut changed = value.clone();
            match flag {
                0 => changed.implementation_authorized = true,
                1 => changed.deployment_authorized = true,
                _ => changed.automatic_dispatch = true,
            }
            assert_ne!(original, changed.task_control_digest().unwrap());
        }
    }
}
