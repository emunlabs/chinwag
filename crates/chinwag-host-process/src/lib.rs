//! Darwin owned child spawning and process-group metadata.
//!
//! Group inspection requires the caller's still-owned leader to stay unreaped;
//! it never signals or reaps. `owned_spawn` waits only its own newly spawned child.
#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

pub mod owned_spawn;

use std::{collections::BTreeSet, num::NonZeroI32};
#[allow(non_camel_case_types)]
mod layout {
    include!(concat!(env!("OUT_DIR"), "/layout.rs"));
}
use layout::*;
const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupState {
    Quiescent,
    Executing,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid owned group leader")]
    InvalidGroup,
    #[error("Darwin owned-group query failed (OS code {0:?})")]
    Query(Option<i32>),
    #[error("invalid Darwin group snapshot: {0}")]
    Snapshot(&'static str),
    #[error("Darwin process birth query failed: {0}")]
    Sysctl(#[source] std::io::Error),
    #[error("invalid Darwin process birth snapshot: {0}")]
    Decode(&'static str),
    #[error("Darwin process entry size {actual} != {expected}")]
    EntrySize { actual: usize, expected: usize },
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InvalidGroup, Self::InvalidGroup) => true,
            (Self::Query(a), Self::Query(b)) => a == b,
            (Self::Snapshot(a), Self::Snapshot(b)) | (Self::Decode(a), Self::Decode(b)) => a == b,
            (Self::Sysctl(a), Self::Sysctl(b)) => {
                a.raw_os_error() == b.raw_os_error() && a.to_string() == b.to_string()
            }
            (
                Self::EntrySize {
                    actual: a,
                    expected: b,
                },
                Self::EntrySize {
                    actual: c,
                    expected: d,
                },
            ) => a == c && b == d,
            _ => false,
        }
    }
}

impl Eq for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcStatus {
    Idle,
    Running,
    Sleeping,
    Stopped,
    Zombie,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcBirthInfo {
    pub pid: u32,
    pub pgid: u32,
    pub status: ProcStatus,
    /// Kernel process start timestamp in microseconds since UNIX epoch
    /// (`kinfo_proc.kp_proc.p_starttime`: `tv_sec * 1_000_000 + tv_usec`).
    pub start_time_unix_us: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessBirthObservation {
    Alive(ProcBirthInfo),
    NotFoundOrZombie,
}

/// Inspect one PID without signaling or reaping it. A birth timestamp binds
/// ownership to a process incarnation even when the kernel reuses its PID.
#[allow(unsafe_code)]
pub fn inspect_process_birth(pid: u32) -> Result<ProcessBirthObservation, Error> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(Error::Decode("PID outside positive pid_t range"));
    }
    let mut mib = [
        CHINWAG_CTL_KERN as libc::c_int,
        CHINWAG_KERN_PROC as libc::c_int,
        CHINWAG_KERN_PROC_PID as libc::c_int,
        pid as libc::c_int,
    ];
    let mut buffer = [0u8; CHINWAG_KINFO_SIZE as usize];
    let mut size = buffer.len();
    // SAFETY: initialized MIB and writable byte buffer have the supplied lengths.
    // Null newp/newlen=0 is read-only; sysctl retains none of these pointers.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result == -1 {
        let err = std::io::Error::last_os_error();
        return if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(ProcessBirthObservation::NotFoundOrZombie)
        } else {
            Err(Error::Sysctl(err))
        };
    }
    if size == 0 {
        return Ok(ProcessBirthObservation::NotFoundOrZombie);
    }
    if size != buffer.len() {
        return Err(Error::EntrySize {
            actual: size,
            expected: buffer.len(),
        });
    }
    decode_process_birth(&buffer, pid)
}

fn birth_scalar<const N: usize>(bytes: &[u8], offset: u32) -> Result<[u8; N], Error> {
    bytes
        .get(offset as usize..)
        .and_then(|tail| tail.get(..N))
        .and_then(|scalar| scalar.try_into().ok())
        .ok_or(Error::Decode("SDK scalar bounds"))
}

fn decode_process_birth(bytes: &[u8], expected_pid: u32) -> Result<ProcessBirthObservation, Error> {
    if bytes.len() != CHINWAG_KINFO_SIZE as usize {
        return Err(Error::EntrySize {
            actual: bytes.len(),
            expected: CHINWAG_KINFO_SIZE as usize,
        });
    }
    let pid = i32::from_ne_bytes(birth_scalar(bytes, CHINWAG_PID_OFFSET)?);
    if pid == 0 {
        return Ok(ProcessBirthObservation::NotFoundOrZombie);
    }
    if pid < 0 || pid as u32 != expected_pid {
        return Err(Error::Decode("kernel returned a different PID"));
    }
    let status = u32::from(birth_scalar::<1>(bytes, CHINWAG_STATUS_OFFSET)?[0]);
    let status = match status {
        CHINWAG_STATUS_IDLE => ProcStatus::Idle,
        CHINWAG_STATUS_RUN => ProcStatus::Running,
        CHINWAG_STATUS_SLEEP => ProcStatus::Sleeping,
        CHINWAG_STATUS_STOP => ProcStatus::Stopped,
        CHINWAG_STATUS_ZOMBIE => return Ok(ProcessBirthObservation::NotFoundOrZombie),
        _ => return Err(Error::Decode("unknown process status")),
    };
    let pgid = i32::from_ne_bytes(birth_scalar(bytes, CHINWAG_PGID_OFFSET)?);
    if pgid <= 0 {
        return Err(Error::Decode("invalid process group"));
    }
    let tv_sec = i64::from_ne_bytes(birth_scalar(bytes, CHINWAG_START_TVSEC_OFFSET)?);
    let tv_usec = i32::from_ne_bytes(birth_scalar(bytes, CHINWAG_START_TVUSEC_OFFSET)?);
    if tv_sec <= 0 || !(0..1_000_000).contains(&tv_usec) {
        return Err(Error::Decode("invalid process start timeval"));
    }
    let start_time_unix_us = (tv_sec as u64)
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(tv_usec as u64))
        .ok_or(Error::Decode("process start timestamp overflow"))?;
    Ok(ProcessBirthObservation::Alive(ProcBirthInfo {
        pid: pid as u32,
        pgid: pgid as u32,
        status,
        start_time_unix_us,
    }))
}

/// Query only the supplied group. Ownership and its unreaped lifetime are held
/// by the caller; an empty or incomplete listing can never prove quiescence.
pub fn inspect_exited_group(group: NonZeroI32) -> Result<GroupState, Error> {
    classify(&read_group(group)?, group)
}

/// Observe one test fixture member in its original group. Absence or a zombie
/// means stopped for this assertion only; it never authorizes production cleanup.
#[cfg(feature = "test-support")]
pub fn fixture_member_is_executing(group: NonZeroI32, member: NonZeroI32) -> Result<bool, Error> {
    if member.get() <= 1 {
        return Err(Error::InvalidGroup);
    }
    Ok(decode(&read_group(group)?, group)?
        .iter()
        .any(|row| row.pid == member.get() && row.status != CHINWAG_STATUS_ZOMBIE))
}

#[allow(unsafe_code)]
fn read_group(group: NonZeroI32) -> Result<Vec<u8>, Error> {
    if group.get() <= 1 {
        return Err(Error::InvalidGroup);
    }
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PGRP,
        group.get(),
    ];
    let mut buffer = vec![0u8; MAX_BYTES];
    let mut len = buffer.len();
    // SAFETY: four initialized MIB integers select one group. The initialized
    // private byte buffer is writable for `len` bytes. `len` is a live size_t.
    // Null newp/newlen=0 makes this read-only. sysctl retains none of the pointers.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buffer.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(Error::Query(std::io::Error::last_os_error().raw_os_error()));
    }
    if len > buffer.len() {
        return Err(Error::Snapshot("length exceeds capacity"));
    }
    buffer.truncate(len);
    Ok(buffer)
}

fn scalar_i32(row: &[u8], offset: u32) -> Result<i32, Error> {
    let offset = usize::try_from(offset).map_err(|_| Error::Snapshot("SDK offset"))?;
    let end = offset
        .checked_add(4)
        .ok_or(Error::Snapshot("SDK offset overflow"))?;
    let scalar = row
        .get(offset..end)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Snapshot("SDK scalar bounds"))?;
    Ok(i32::from_ne_bytes(scalar))
}

struct Row {
    pid: i32,
    status: u32,
}

fn decode(bytes: &[u8], group: NonZeroI32) -> Result<Vec<Row>, Error> {
    let size = CHINWAG_KINFO_SIZE as usize;
    if size == 0 || bytes.len() > MAX_BYTES || !bytes.len().is_multiple_of(size) {
        return Err(Error::Snapshot("empty or incomplete snapshot"));
    }
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for row in bytes.chunks_exact(size) {
        let pid = scalar_i32(row, CHINWAG_PID_OFFSET)?;
        let pgid = scalar_i32(row, CHINWAG_PGID_OFFSET)?;
        let status = u32::from(
            *row.get(CHINWAG_STATUS_OFFSET as usize)
                .ok_or(Error::Snapshot("SDK status bounds"))?,
        );
        if pid <= 0 || pgid != group.get() || !seen.insert(pid) {
            return Err(Error::Snapshot("invalid pid, wrong group or duplicate pid"));
        }
        if ![
            CHINWAG_STATUS_IDLE,
            CHINWAG_STATUS_RUN,
            CHINWAG_STATUS_SLEEP,
            CHINWAG_STATUS_STOP,
            CHINWAG_STATUS_ZOMBIE,
        ]
        .contains(&status)
        {
            return Err(Error::Snapshot("unknown status"));
        }
        rows.push(Row { pid, status });
    }
    Ok(rows)
}

fn classify(bytes: &[u8], group: NonZeroI32) -> Result<GroupState, Error> {
    let rows = decode(bytes, group)?;
    match rows.iter().find(|row| row.pid == group.get()) {
        Some(row) if row.status == CHINWAG_STATUS_ZOMBIE => {}
        Some(_) => return Err(Error::Snapshot("owned leader is not a zombie")),
        None => return Err(Error::Snapshot("owned leader absent")),
    }
    Ok(
        if rows.iter().any(|row| row.status != CHINWAG_STATUS_ZOMBIE) {
            GroupState::Executing
        } else {
            GroupState::Quiescent
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_birth_matches_pid_and_has_exact_microsecond_timestamp() {
        let pid = std::process::id();
        let ProcessBirthObservation::Alive(info) = inspect_process_birth(pid).unwrap() else {
            panic!("current process must be alive");
        };
        assert_eq!(info.pid, pid);
        assert!(info.pgid > 0);
        assert!(info.start_time_unix_us > 0);
        assert_eq!(
            inspect_process_birth(pid).unwrap(),
            ProcessBirthObservation::Alive(info)
        );
    }

    #[test]
    fn exited_child_process_is_not_found_or_zombie() {
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert_eq!(
            inspect_process_birth(pid).unwrap(),
            ProcessBirthObservation::NotFoundOrZombie
        );
    }

    #[test]
    fn invalid_process_birth_pids_fail_closed() {
        for pid in [0, i32::MAX as u32 + 1, u32::MAX] {
            assert!(matches!(inspect_process_birth(pid), Err(Error::Decode(_))));
        }
    }

    #[test]
    fn synthetic_process_birth_zombie_timeval_bounds_pid_and_size_fail_closed() {
        let mut bytes = row(42, 42, CHINWAG_STATUS_ZOMBIE);
        assert_eq!(
            decode_process_birth(&bytes, 42).unwrap(),
            ProcessBirthObservation::NotFoundOrZombie
        );
        bytes[CHINWAG_STATUS_OFFSET as usize] = CHINWAG_STATUS_RUN as u8;
        let offset = CHINWAG_START_TVSEC_OFFSET as usize;
        bytes[offset..offset + 8].copy_from_slice(&123i64.to_ne_bytes());
        let offset = CHINWAG_START_TVUSEC_OFFSET as usize;
        for usec in [-1i32, 1_000_000, i32::MAX] {
            bytes[offset..offset + 4].copy_from_slice(&usec.to_ne_bytes());
            assert!(matches!(
                decode_process_birth(&bytes, 42),
                Err(Error::Decode(_))
            ));
        }
        bytes[offset..offset + 4].copy_from_slice(&456i32.to_ne_bytes());
        let ProcessBirthObservation::Alive(info) = decode_process_birth(&bytes, 42).unwrap() else {
            panic!("live synthetic row");
        };
        assert_eq!(info.start_time_unix_us, 123_000_456);
        assert!(matches!(
            decode_process_birth(&bytes, 43),
            Err(Error::Decode(_))
        ));
        assert!(matches!(
            decode_process_birth(&bytes[..1], 42),
            Err(Error::EntrySize { .. })
        ));
    }
    fn row(pid: i32, group: i32, status: u32) -> Vec<u8> {
        let mut row = vec![0; CHINWAG_KINFO_SIZE as usize];
        let offset = CHINWAG_PID_OFFSET as usize;
        row[offset..offset + 4].copy_from_slice(&pid.to_ne_bytes());
        let offset = CHINWAG_PGID_OFFSET as usize;
        row[offset..offset + 4].copy_from_slice(&group.to_ne_bytes());
        row[CHINWAG_STATUS_OFFSET as usize] = u8::try_from(status).unwrap();
        row
    }
    #[test]
    fn complete_owned_zombies_are_quiescent_but_any_live_member_is_executing() {
        let group = NonZeroI32::new(42).unwrap();
        let mut bytes = row(42, 42, CHINWAG_STATUS_ZOMBIE);
        assert_eq!(classify(&bytes, group), Ok(GroupState::Quiescent));
        bytes.extend(row(43, 42, CHINWAG_STATUS_ZOMBIE));
        assert_eq!(classify(&bytes, group), Ok(GroupState::Quiescent));
        bytes.extend(row(44, 42, CHINWAG_STATUS_RUN));
        assert_eq!(classify(&bytes, group), Ok(GroupState::Executing));
    }
    #[test]
    fn empty_truncated_wrong_group_missing_leader_duplicate_and_unknown_refuse() {
        let group = NonZeroI32::new(42).unwrap();
        for bytes in [
            vec![],
            vec![0],
            row(42, 43, CHINWAG_STATUS_ZOMBIE),
            row(43, 42, CHINWAG_STATUS_ZOMBIE),
            row(42, 42, CHINWAG_STATUS_RUN),
            row(42, 42, 255),
            [
                row(42, 42, CHINWAG_STATUS_ZOMBIE),
                row(42, 42, CHINWAG_STATUS_ZOMBIE),
            ]
            .concat(),
            vec![0; MAX_BYTES + 1],
        ] {
            assert!(classify(&bytes, group).is_err());
        }
        assert!(scalar_i32(&[], u32::MAX).is_err());
    }
    #[test]
    fn init_and_negative_groups_refuse_before_any_query() {
        assert_eq!(
            inspect_exited_group(NonZeroI32::new(1).unwrap()),
            Err(Error::InvalidGroup)
        );
        assert_eq!(
            inspect_exited_group(NonZeroI32::new(-42).unwrap()),
            Err(Error::InvalidGroup)
        );
    }

    #[test]
    fn test_observation_without_a_zombie_leader_cannot_authorize_production_cleanup() {
        let group = NonZeroI32::new(42).unwrap();
        assert!(decode(&[], group).unwrap().is_empty());
        assert!(classify(&[], group).is_err());
        let bytes = row(43, 42, CHINWAG_STATUS_RUN);
        assert_eq!(decode(&bytes, group).unwrap()[0].pid, 43);
        assert!(classify(&bytes, group).is_err());
    }
}
