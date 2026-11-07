use super::*;

const SOURCE: &str = "0123456789abcdef0123456789abcdef";
const OTHER: &str = "abcdef0123456789abcdef0123456789";

fn indexes() -> TaskRefIndexes {
    TaskRefIndexes::try_new(
        "workspace".into(),
        "repo".into(),
        SOURCE.into(),
        7,
        "spec/tasks.md".into(),
        "P0-10".into(),
        [9; 32],
        8,
        9,
        StoredGitOid::Sha1([10; 20]),
    )
    .unwrap()
}
fn envelope(indexes: TaskRefIndexes) -> TaskRefEnvelope {
    let bytes = indexes.canonical_bytes();
    TaskRefEnvelope::try_new(bytes.clone(), digest(&bytes), indexes).unwrap()
}
fn projection(payload: Vec<u8>) -> QualifiedRecord {
    QualifiedRecord::try_new(
        "projection-observation".into(),
        LogicalKey::projection("workspace".into(), SOURCE.into(), "P0-10".into()).unwrap(),
        vec![envelope(indexes())],
        None,
        payload.clone(),
        digest(&payload),
    )
    .unwrap()
}
fn message(binding: Vec<u8>, phase: Vec<u8>) -> QualifiedRecord {
    let key = LogicalKey::message(
        "workspace".into(),
        "signer".into(),
        "original-message".into(),
    )
    .unwrap();
    let original =
        ImmutableOriginal::try_new(key.clone(), binding.clone(), digest(&binding)).unwrap();
    QualifiedRecord::try_new(
        "message-phase-1".into(),
        key,
        vec![envelope(indexes())],
        Some(original),
        phase.clone(),
        digest(&phase),
    )
    .unwrap()
}

#[test]
fn p010_all_ten_task_ref_indices_and_exact_digest_are_checked() {
    let original = indexes();
    let bytes = original.canonical_bytes();
    let hash = digest(&bytes);
    for field in 0..10 {
        let mut changed = original.clone();
        match field {
            0 => changed.workspace_id = "another".into(),
            1 => changed.repo_id = "another".into(),
            2 => changed.task_source_id = OTHER.into(),
            3 => changed.source_generation += 1,
            4 => changed.canonical_task_path = "other/tasks.md".into(),
            5 => changed.task_id = "other".into(),
            6 => changed.task_spec_digest[0] ^= 1,
            7 => changed.task_status_rev += 1,
            8 => changed.file_cas_rev += 1,
            _ => changed.baseline_commit = StoredGitOid::Sha256([10; 32]),
        }
        assert!(
            matches!(
                TaskRefEnvelope::try_new(bytes.clone(), hash, changed),
                Err(QualifiedError::Mismatch(_))
            ),
            "index {field}"
        );
    }
    let mut wrong_hash = hash;
    wrong_hash[0] ^= 1;
    assert!(TaskRefEnvelope::try_new(bytes.clone(), wrong_hash, original.clone()).is_err());
    assert_eq!(
        TaskRefEnvelope::try_new(bytes, hash, original.clone())
            .unwrap()
            .indexes(),
        &original
    );
}

#[test]
fn p010_task_ref_maximum_profile_u64_and_exact_domain_round_trip() {
    let indexed = TaskRefIndexes::try_new(
        "w".repeat(256),
        "r".repeat(256),
        SOURCE.into(),
        i64::MAX as u64,
        "p".repeat(4096),
        "t".repeat(256),
        [7; 32],
        i64::MAX as u64,
        0,
        StoredGitOid::Sha256([8; 32]),
    )
    .unwrap();
    let bytes = indexed.canonical_bytes();
    assert_eq!(bytes.len(), MAX_TASK_REF_BYTES);
    assert_eq!(TaskRefIndexes::decode(&bytes).unwrap(), indexed);
    let mut wrong_domain = bytes.clone();
    wrong_domain[TASK_REF_DOMAIN.len() - 1] = 1;
    assert!(TaskRefIndexes::decode(&wrong_domain).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(TaskRefIndexes::decode(&trailing).is_err());
    let mut over = bytes.clone();
    let generation = TASK_REF_DOMAIN.len() + 8 + 256 + 8 + 256 + 8 + 32;
    over[generation..generation + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(TaskRefIndexes::decode(&over).is_err());
    let mut impossible_length = bytes;
    impossible_length[TASK_REF_DOMAIN.len()..TASK_REF_DOMAIN.len() + 8]
        .copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        TaskRefIndexes::decode(&impossible_length),
        Err(QualifiedError::OversizeHeld)
    );
}

#[test]
fn p010_keys_preserve_full_original_context_and_numeric_canonical_form() {
    let all = vec![
        LogicalKey::source("workspace".into(), SOURCE.into(), i64::MAX as u64).unwrap(),
        LogicalKey::projection("workspace".into(), SOURCE.into(), "task".into()).unwrap(),
        LogicalKey::dependency(
            "workspace".into(),
            SOURCE.into(),
            "task".into(),
            OTHER.into(),
            "prerequisite".into(),
        )
        .unwrap(),
        LogicalKey::event("workspace".into(), SOURCE.into(), "transition".into()).unwrap(),
        LogicalKey::message("workspace".into(), "signer".into(), "message".into()).unwrap(),
        LogicalKey::assignment("workspace".into(), "assignment".into()).unwrap(),
        LogicalKey::acceptance(
            "workspace".into(),
            SOURCE.into(),
            "task".into(),
            u64::MAX,
            "reviewer".into(),
            "acceptance".into(),
        )
        .unwrap(),
        LogicalKey::source_write_intent("workspace".into(), SOURCE.into(), "operation".into())
            .unwrap(),
        LogicalKey::scheduler_admission("workspace".into(), "admission".into()).unwrap(),
    ];
    for (index, key) in all.iter().enumerate() {
        assert_eq!(key.family().code(), (index + 1) as u8);
        assert_eq!(
            &LogicalKey::from_canonical(&key.canonical_bytes()).unwrap(),
            key
        );
        let mut trailing = key.canonical_bytes();
        trailing.push(0);
        assert!(LogicalKey::from_canonical(&trailing).is_err());
    }
    let context = |workspace: &str, signer: &str| {
        LogicalKey::message(workspace.into(), signer.into(), "same-original".into())
            .unwrap()
            .canonical_bytes()
    };
    assert_ne!(
        context("workspace", "signer"),
        context("workspace", "other")
    );
    assert_ne!(context("workspace", "signer"), context("other", "signer"));
    assert!(LogicalKey::source("workspace".into(), SOURCE.into(), u64::MAX).is_err());
    assert!(
        LogicalKey::acceptance(
            "workspace".into(),
            SOURCE.into(),
            "task".into(),
            0,
            "reviewer".into(),
            "acceptance".into()
        )
        .is_err()
    );
    assert!(LogicalKey::projection("workspace".into(), "".into(), "task".into()).is_err());
    assert!(LogicalKey::message("".into(), "signer".into(), "message".into()).is_err());
}

#[test]
fn p010_family_and_ordered_dependency_refs_must_agree() {
    let mut prerequisite = indexes();
    prerequisite.task_source_id = OTHER.into();
    prerequisite.task_id = "prerequisite".into();
    let key = LogicalKey::dependency(
        "workspace".into(),
        SOURCE.into(),
        "P0-10".into(),
        OTHER.into(),
        "prerequisite".into(),
    )
    .unwrap();
    let refs = vec![envelope(indexes()), envelope(prerequisite)];
    assert!(
        QualifiedRecord::try_new(
            "dep".into(),
            key.clone(),
            refs.clone(),
            None,
            vec![],
            digest(&[])
        )
        .is_ok()
    );
    assert!(
        QualifiedRecord::try_new(
            "dep".into(),
            key.clone(),
            vec![refs[1].clone(), refs[0].clone()],
            None,
            vec![],
            digest(&[])
        )
        .is_err()
    );
    assert!(
        QualifiedRecord::try_new("dep".into(), key, vec![], None, vec![], digest(&[])).is_err()
    );
    let wrong =
        LogicalKey::projection("workspace".into(), SOURCE.into(), "different-task".into()).unwrap();
    assert!(
        QualifiedRecord::try_new(
            "projection".into(),
            wrong,
            vec![envelope(indexes())],
            None,
            vec![],
            digest(&[])
        )
        .is_err()
    );
    let source = LogicalKey::source("workspace".into(), SOURCE.into(), 1).unwrap();
    assert!(
        QualifiedRecord::try_new("source".into(), source, vec![], None, vec![], digest(&[]))
            .is_ok()
    );
}

#[test]
fn p010_original_binding_is_immutable_context_separate_from_phase() {
    let record = message(
        b"exact authenticated canonical frame".to_vec(),
        b"pending".to_vec(),
    );
    let mut phase = record.clone();
    phase.observation_id = "message-phase-2".into();
    phase.payload = b"processed".to_vec();
    phase.payload_digest = digest(&phase.payload);
    let changed = QualifiedRecord::try_new(
        phase.observation_id,
        phase.key,
        phase.references,
        phase.original,
        phase.payload,
        phase.payload_digest,
    )
    .unwrap();
    assert_eq!(record.original(), changed.original());
    assert_ne!(record.canonical_digest(), changed.canonical_digest());
    let wrong_key = LogicalKey::message(
        "workspace".into(),
        "different-signer".into(),
        "original-message".into(),
    )
    .unwrap();
    assert!(
        QualifiedRecord::try_new(
            "wrong".into(),
            wrong_key,
            record.references.clone(),
            record.original.clone(),
            vec![],
            digest(&[])
        )
        .is_err()
    );
    assert!(
        ImmutableOriginal::try_new(
            LogicalKey::projection("workspace".into(), SOURCE.into(), "P0-10".into()).unwrap(),
            vec![1],
            digest(&[1])
        )
        .is_err()
    );
    assert!(ImmutableOriginal::try_new(record.key.clone(), vec![], digest(&[])).is_err());
    assert!(ImmutableOriginal::try_new(record.key.clone(), vec![1], [0; 32]).is_err());
    assert!(
        QualifiedRecord::try_new(
            "missing".into(),
            record.key.clone(),
            record.references.clone(),
            None,
            vec![],
            digest(&[])
        )
        .is_err()
    );
}

#[test]
fn p010_complete_record_codec_never_accepts_truncation_or_trailing_bytes() {
    let record = message(vec![0xa5; 131072], vec![0x5a; 65536]);
    let bytes = encode_record(&record);
    assert_eq!(record.canonical_len(), bytes.len());
    assert_eq!(record.canonical_digest(), digest(&bytes));
    let decoded = decode_record(&bytes).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.original().unwrap().binding(), vec![0xa5; 131072]);
    assert_eq!(decoded.payload(), vec![0x5a; 65536]);
    for length in [0, RECORD_DOMAIN.len() - 1, bytes.len() - 1] {
        assert!(decode_record(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(decode_record(&trailing), Err(QualifiedError::NonCanonical));
    let mut corrupt = bytes;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(matches!(
        decode_record(&corrupt),
        Err(QualifiedError::Mismatch(_))
    ));
    let oversized = vec![0; MAX_QUALIFIED_RECORD_BYTES + 1];
    assert_eq!(decode_record(&oversized), Err(QualifiedError::OversizeHeld));
}

#[test]
fn p010_four_chunk_assembly_preserves_full_wire_and_rejects_every_partial_shape() {
    let record = message(vec![0x7f; 131072], vec![0x42; 65536]);
    let (header, chunks) = split_record(&record);
    assert_eq!(chunks.len(), 4);
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(usize::from(chunk.ordinal()), index);
        assert!(chunk.bytes().len() <= 65536);
    }
    assert_eq!(assemble_record(&header, &chunks).unwrap(), record);
    for missing in 0..chunks.len() {
        let mut partial = chunks.clone();
        partial.remove(missing);
        assert!(assemble_record(&header, &partial).is_err());
    }
    let mut duplicate = chunks.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(assemble_record(&header, &duplicate).is_err());
    let mut reordered = chunks.clone();
    reordered.swap(0, 1);
    assert!(assemble_record(&header, &reordered).is_err());
    let mut extra = chunks.clone();
    extra.push(chunks[0].clone());
    assert!(assemble_record(&header, &extra).is_err());
    let mut shorter = chunks.clone();
    shorter[0].bytes.pop();
    assert!(assemble_record(&header, &shorter).is_err());
    let mut corrupt = chunks.clone();
    corrupt[2].bytes[0] ^= 1;
    assert!(matches!(
        assemble_record(&header, &corrupt),
        Err(QualifiedError::Mismatch(_))
    ));
    let wrong = RecordHeader::try_new(
        header.family(),
        "other-workspace".into(),
        header.observation_id().into(),
        header.record_digest(),
        header.total_length(),
        header.part_count(),
    )
    .unwrap();
    assert!(assemble_record(&wrong, &chunks).is_err());
}

#[test]
fn p010_exact_chunk_multiple_has_full_final_chunk_not_empty_sentinel() {
    let overhead = projection(vec![]).canonical_len();
    let record = projection(vec![0x2a; 65536 - overhead]);
    assert_eq!(record.canonical_len(), 65536);
    let (header, chunks) = split_record(&record);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].bytes().len(), 65536);
    assert_eq!(assemble_record(&header, &chunks).unwrap(), record);
    assert!(RecordChunk::try_new(1, vec![]).is_err());
    assert!(RecordChunk::try_new(4, vec![1]).is_err());
    assert!(RecordChunk::try_new(0, vec![1; 65537]).is_err());
    assert!(
        RecordHeader::try_new(
            header.family(),
            "workspace".into(),
            "obs".into(),
            [0; 32],
            0,
            0
        )
        .is_err()
    );
    assert!(
        RecordHeader::try_new(
            header.family(),
            "workspace".into(),
            "obs".into(),
            [0; 32],
            65536,
            2
        )
        .is_err()
    );
}

#[test]
fn p010_variant_keys_retain_changed_payload_with_no_latest_winner() {
    let first = projection(b"first".to_vec());
    let second = projection(b"second".to_vec());
    let (one, _) = split_record(&first);
    let (two, _) = split_record(&second);
    assert_eq!(one.observation_id(), two.observation_id());
    assert_ne!(record_variant_key(&one), record_variant_key(&two));
    assert_ne!(
        chunk_key(&record_variant_key(&one), 0),
        chunk_key(&record_variant_key(&one), 1)
    );
    // Both variants remain in a typed batch. Transactional ingress and reads
    // adjudicate/quarantine them; the DTO never picks first or latest.
    assert_eq!(
        ObservationBatch::try_new(vec![first, second])
            .unwrap()
            .records()
            .len(),
        2
    );
}

#[test]
fn p010_batch_profiles_bound_bytes_and_keep_authority_journals_local() {
    let local = QualifiedRecord::try_new(
        "journal-observation".into(),
        LogicalKey::scheduler_admission("workspace".into(), "admission".into()).unwrap(),
        vec![envelope(indexes())],
        None,
        vec![],
        digest(&[]),
    )
    .unwrap();
    assert!(ObservationBatch::try_new(vec![local.clone()]).is_err());
    assert!(LocalJournalMirrorBatch::try_new(vec![local]).is_ok());
    assert!(LocalJournalMirrorBatch::try_new(vec![projection(vec![])]).is_err());
    let small = projection(vec![]);
    assert!(ObservationBatch::try_new(vec![small; 129]).is_err());
    let large = message(vec![3; 131072], vec![4; 65536]);
    let five = ObservationBatch::try_new(vec![large.clone(); 5]).unwrap();
    assert!(five.encoded_bytes() <= 1_048_576);
    assert_eq!(
        ObservationBatch::try_new(vec![large; 6]),
        Err(QualifiedError::OversizeHeld)
    );
    assert!(
        ObservationBatch::try_new(vec![])
            .unwrap()
            .records()
            .is_empty()
    );
    let mut over = vec![1; MAX_QUALIFIED_PAYLOAD_BYTES];
    over.push(1);
    assert_eq!(
        QualifiedRecord::try_new(
            "oversize".into(),
            small_key(),
            vec![envelope(indexes())],
            None,
            over.clone(),
            digest(&over)
        ),
        Err(QualifiedError::OversizeHeld)
    );
}
fn small_key() -> LogicalKey {
    LogicalKey::projection("workspace".into(), SOURCE.into(), "P0-10".into()).unwrap()
}
