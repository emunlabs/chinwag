use std::{mem::MaybeUninit, time::SystemTime};

use crate::{
    CANDIDATE_CAPACITY, Coverage, DiscoveryError, HostObservation, InventorySnapshot, PID_CAPACITY,
    ProcessBirth,
    observation::{
        ObservedProcess, PathMatch, candidate_from_pair, classify_path, decode_pid_list,
        finish_candidates,
    },
};

#[allow(
    unsafe_code,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/libproc.rs"));
    #[link(name = "proc")]
    unsafe extern "C" {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Race,
    Permission,
    Unavailable,
    Invalid,
}

fn last_fault() -> Fault {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH | libc::ENOENT) => Fault::Race,
        Some(libc::EPERM | libc::EACCES) => Fault::Permission,
        _ => Fault::Unavailable,
    }
}

fn count_fault(coverage: &mut Coverage, fault: Fault) {
    match fault {
        Fault::Race => coverage.raced_processes += 1,
        Fault::Permission => coverage.permission_denied_processes += 1,
        Fault::Unavailable => coverage.unavailable_processes += 1,
        Fault::Invalid => coverage.invalid_process_metadata += 1,
    }
}

fn bounded_text(bytes: &[u8]) -> Result<&str, Fault> {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(Fault::Invalid)?;
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| Fault::Invalid)?;
    if text.is_empty() {
        return Err(Fault::Invalid);
    }
    Ok(text)
}

#[allow(unsafe_code)]
fn host_observation() -> Result<HostObservation, DiscoveryError> {
    let mut hostname = [0xffu8; 256];
    // SAFETY: initialized fixed buffer, writable length; no pointer is retained.
    if unsafe { libc::gethostname(hostname.as_mut_ptr().cast(), hostname.len()) } != 0 {
        return Err(DiscoveryError::HostMetadata("gethostname failed"));
    }
    let label = bounded_text(&hostname)
        .map_err(|_| DiscoveryError::HostMetadata("invalid hostname"))?
        .to_owned();
    let mut boot = [0xffu8; 64];
    let mut length = boot.len();
    // SAFETY: NUL-terminated fixed sysctl name; writable byte buffer/size pointer.
    // Null newp with zero newlen is read-only. No pointer outlives the call.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            boot.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || length > boot.len() {
        return Err(DiscoveryError::HostMetadata("boot UUID query failed"));
    }
    let boot_uuid = bounded_text(&boot[..length])
        .map_err(|_| DiscoveryError::HostMetadata("invalid boot UUID"))?;
    if boot_uuid.len() != 36
        || !boot_uuid
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
    {
        return Err(DiscoveryError::HostMetadata("malformed boot UUID"));
    }
    Ok(HostObservation {
        label,
        boot_uuid: boot_uuid.to_owned(),
    })
}

#[allow(unsafe_code)]
fn read_process(pid: i32, uid: u32) -> Result<ObservedProcess, Fault> {
    let mut info = MaybeUninit::<ffi::proc_bsdinfo>::uninit();
    let size = size_of::<ffi::proc_bsdinfo>();
    let size_i32 = i32::try_from(size).map_err(|_| Fault::Invalid)?;
    // SAFETY: SDK-derived structure has correct alignment/size; the output is
    // read only after the public API reports the exact initialized structure size.
    let returned = unsafe {
        ffi::proc_pidinfo(
            pid,
            ffi::PROC_PIDTBSDINFO as i32,
            0,
            info.as_mut_ptr().cast(),
            size_i32,
        )
    };
    if returned != size_i32 {
        return Err(if returned <= 0 {
            last_fault()
        } else {
            Fault::Invalid
        });
    }
    // SAFETY: proc_pidinfo returned the complete requested SDK structure.
    let info = unsafe { info.assume_init() };
    let expected_pid = u32::try_from(pid).map_err(|_| Fault::Invalid)?;
    if info.pbi_pid != expected_pid || info.pbi_uid != uid {
        return Err(Fault::Race);
    }
    if info.pbi_start_tvsec == 0 || info.pbi_start_tvusec >= 1_000_000 {
        return Err(Fault::Invalid);
    }
    let path_size = usize::try_from(ffi::PROC_PIDPATHINFO_MAXSIZE).map_err(|_| Fault::Invalid)?;
    if path_size == 0 || path_size > 16 * 1024 {
        return Err(Fault::Invalid);
    }
    // Nonzero initialization ensures we do not mistake an unwritten byte for a
    // terminator supplied by proc_pidpath.
    let mut path = vec![0xffu8; path_size];
    // SAFETY: fixed SDK-bounded writable path buffer; public read-only API.
    let returned = unsafe {
        ffi::proc_pidpath(
            pid,
            path.as_mut_ptr().cast(),
            u32::try_from(path.len()).map_err(|_| Fault::Invalid)?,
        )
    };
    if returned <= 0 {
        return Err(last_fault());
    }
    if usize::try_from(returned).map_err(|_| Fault::Invalid)? > path.len() {
        return Err(Fault::Invalid);
    }
    let executable = bounded_text(&path)?;
    if !executable.starts_with('/') {
        return Err(Fault::Invalid);
    }
    Ok(ObservedProcess {
        birth: ProcessBirth {
            pid: expected_pid,
            start_seconds: info.pbi_start_tvsec,
            start_microseconds: u32::try_from(info.pbi_start_tvusec).map_err(|_| Fault::Invalid)?,
        },
        parent_pid: info.pbi_ppid,
        uid: info.pbi_uid,
        process_group: info.pbi_pgid,
        executable: executable.to_owned(),
    })
}

#[allow(unsafe_code)]
pub(crate) fn snapshot() -> Result<InventorySnapshot, DiscoveryError> {
    let host = host_observation()?;
    // SAFETY: getuid takes no pointers and has no process mutation.
    let uid = unsafe { libc::getuid() };
    let mut pids = [0i32; PID_CAPACITY];
    let byte_capacity = i32::try_from(std::mem::size_of_val(&pids))
        .map_err(|_| DiscoveryError::InvalidSnapshot("PID capacity overflow"))?;
    // SAFETY: current-UID scope, initialized fixed pid_t buffer with exact byte
    // capacity. No process arguments, environment, sockets or files are requested.
    let returned = unsafe {
        ffi::proc_listpids(
            ffi::PROC_UID_ONLY,
            uid,
            pids.as_mut_ptr().cast(),
            byte_capacity,
        )
    };
    if returned <= 0 {
        return Err(DiscoveryError::Enumeration(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    let (pids, pid_capacity_reached, zero_pid_slots) = decode_pid_list(returned, &pids)?;
    let mut coverage = Coverage {
        pid_capacity: PID_CAPACITY,
        candidate_capacity: CANDIDATE_CAPACITY,
        sampled_pid_count: pids.len(),
        pid_capacity_reached,
        zero_pid_slots,
        ..Coverage::default()
    };
    let mut candidates = Vec::new();
    for pid in pids {
        let first = match read_process(pid, uid) {
            Ok(process) => process,
            Err(fault) => {
                count_fault(&mut coverage, fault);
                continue;
            }
        };
        match classify_path(&first.executable) {
            PathMatch::Other => continue,
            PathMatch::Interpreter => {
                coverage.unclassified_interpreters += 1;
                continue;
            }
            PathMatch::Named(..) => {}
        }
        let second = match read_process(pid, uid) {
            Ok(process) => process,
            Err(fault) => {
                count_fault(&mut coverage, fault);
                continue;
            }
        };
        match candidate_from_pair(first, second) {
            Some(candidate) => candidates.push(candidate),
            None => coverage.raced_processes += 1,
        }
    }
    let candidates = finish_candidates(candidates, &mut coverage, CANDIDATE_CAPACITY);
    let observed_at_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| DiscoveryError::Clock)?
            .as_millis(),
    )
    .map_err(|_| DiscoveryError::Clock)?;
    Ok(InventorySnapshot {
        observed_at_unix_ms,
        host,
        uid,
        coverage,
        candidates,
        limitations: vec![
            "Process metadata only: no connector, account, session, protocol, or model readiness verified.".to_owned(),
            "Snapshot only: no lifecycle watch; same-path re-exec and changes after sampling remain unproven.".to_owned(),
            "Path and basename matches are family hints, not authenticated executable or vendor identity.".to_owned(),
            "Generic interpreters, unrecognized paths and out-of-scope UIDs can hide clients; no absence claim.".to_owned(),
            "Parent links describe retained, stable observations from this sample, not continuous ownership.".to_owned(),
            "Host and boot labels are observed metadata, not authenticated host identity.".to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_or_unterminated_metadata_is_not_lossily_accepted() {
        assert_eq!(bounded_text(b"/bin/codex\0junk"), Ok("/bin/codex"));
        for bytes in [&b""[..], &b"\0"[..], &b"unterminated"[..], &[0xff, 0][..]] {
            assert_eq!(bounded_text(bytes), Err(Fault::Invalid));
        }
        assert_eq!(bounded_text(&[b'x'; 4096]), Err(Fault::Invalid));
    }

    #[test]
    fn race_permission_invalid_and_unavailable_counts_are_distinct() {
        let mut coverage = Coverage::default();
        for fault in [
            Fault::Race,
            Fault::Permission,
            Fault::Invalid,
            Fault::Unavailable,
        ] {
            count_fault(&mut coverage, fault);
        }
        assert_eq!(coverage.raced_processes, 1);
        assert_eq!(coverage.permission_denied_processes, 1);
        assert_eq!(coverage.invalid_process_metadata, 1);
        assert_eq!(coverage.unavailable_processes, 1);
        assert!(!coverage.pid_capacity_reached);
    }
}
