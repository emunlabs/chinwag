// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! The only unsafe module: descriptor-bound Darwin security attributes.
//! Mode0600/0700 cannot rule out granting ACLs. A path/proxy listing is not an
//! ACL observation of the held inode. The allocating acl_get_fd_np wrapper can
//! mask an allocation error as ENOENT in the examined Apple Libc source.
//!
//! Request ONLY ATTR_CMN_EXTENDED_SECURITY, with FSOPT_REPORT_FULLSIZE. XNU
//! packs absence as total12/reference-offset8/data-length0. Any ACL blob, error,
//! truncation, unsupported attribute or different shape refuses the operation.
//! No returned-attribute/invalid-attribute packing options are enabled.
//! This is the examined XNU/local filesystem contract, not universal FS support.

use std::os::fd::{AsRawFd, BorrowedFd};

fn exact_absence(reply: &[u8; 12]) -> bool {
    reply[..4] == 12_u32.to_ne_bytes()
        && reply[4..8] == 8_i32.to_ne_bytes()
        && reply[8..12] == 0_u32.to_ne_bytes()
}

pub(crate) fn require_absent(fd: BorrowedFd<'_>) -> Result<(), ()> {
    let mut attributes = libc::attrlist {
        bitmapcount: 5, // ATTR_BIT_MAP_COUNT in sys/attr.h
        reserved: 0,
        commonattr: 0x0040_0000, // ATTR_CMN_EXTENDED_SECURITY
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut reply = [0_u8; 12];
    // SAFETY: fd stays live for this synchronous call. libc::attrlist has the
    // public C ABI and all fields are initialized. The initialized byte array
    // is writable for precisely the supplied length; both pointers remain
    // valid until return. The reply is checked without pointer dereferencing.
    // REPORT_FULLSIZE exposes positive ACLs larger than12 even when their data
    // cannot fit; a successful syscall alone is never treated as absence.
    let status = unsafe {
        libc::fgetattrlist(
            fd.as_raw_fd(),
            (&mut attributes as *mut libc::attrlist).cast(),
            reply.as_mut_ptr().cast(),
            reply.len(),
            4, // FSOPT_REPORT_FULLSIZE
        )
    };
    if status == 0 && exact_absence(&reply) {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_but_truncated_acl_headers_are_not_absence() {
        let mut absent = [0_u8; 12];
        absent[..4].copy_from_slice(&12_u32.to_ne_bytes());
        absent[4..8].copy_from_slice(&8_i32.to_ne_bytes());
        assert!(exact_absence(&absent));
        for (total, blob) in [
            (56_u32, 44_u32),
            (80, 68),
            (3128, 3116),
            (u32::MAX, u32::MAX),
        ] {
            let mut header = absent;
            header[..4].copy_from_slice(&total.to_ne_bytes());
            header[8..].copy_from_slice(&blob.to_ne_bytes());
            assert!(!exact_absence(&header));
        }
        for offset in [0_i32, -1, 4, 12, i32::MAX] {
            let mut header = absent;
            header[4..8].copy_from_slice(&offset.to_ne_bytes());
            assert!(!exact_absence(&header));
        }
        assert!(!exact_absence(&[0; 12]));
    }
}
