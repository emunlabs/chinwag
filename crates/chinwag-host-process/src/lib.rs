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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid owned group leader")]
    InvalidGroup,
    #[error("Darwin owned-group query failed (OS code {0:?})")]
    Query(Option<i32>),
    #[error("invalid Darwin group snapshot: {0}")]
    Snapshot(&'static str),
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
