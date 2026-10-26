//! Claim reports are observations, never file-write authority.

use chinwag_swarm::room::{ClaimTaskReport, LeaseError, WriteWitness};
use std::path::Path;

/// A single local write attempt backed by this process's opaque live witness.
/// A claim report cannot construct it. This does not fence a remote filesystem.
///
/// ```compile_fail,E0451
/// let permit = chinwag_seed::write_gate::WritePermit { source: panic!() };
/// ```
pub struct WritePermit<'a> {
    source: PermitSource<'a>,
}

enum PermitSource<'a> {
    Live(WriteWitness<'a>),
    #[cfg(test)]
    Fixture {
        path: std::path::PathBuf,
        issued: u64,
        expiry: u64,
        deadline: std::time::Instant,
    },
}

impl<'a> WritePermit<'a> {
    pub(crate) fn from_witness(witness: WriteWitness<'a>) -> Self {
        Self {
            source: PermitSource::Live(witness),
        }
    }

    pub(crate) fn validate(&self, path: &Path) -> Result<(), LeaseError> {
        match &self.source {
            PermitSource::Live(witness) => witness.validate(path),
            #[cfg(test)]
            PermitSource::Fixture {
                path: allowed,
                issued,
                expiry,
                deadline,
            } => {
                if allowed.as_os_str() != path.as_os_str() {
                    return Err(LeaseError::Path);
                }
                let now = chinwag_swarm::room::now_unix().map_err(|_| LeaseError::Expired)?;
                if now < *issued || now >= *expiry || std::time::Instant::now() >= *deadline {
                    return Err(LeaseError::Expired);
                }
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(
        path: &Path,
        issued: u64,
        expiry: u64,
        deadline: std::time::Instant,
    ) -> Self {
        Self {
            source: PermitSource::Fixture {
                path: path.to_owned(),
                issued,
                expiry,
                deadline,
            },
        }
    }
}

#[derive(Debug)]
pub enum NoGrant {}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteDenial {
    NoLiveGrant,
}

/// Neither a reported receipt nor a caller's freshness check grants a write.
///
/// ```compile_fail,E0308
/// fn no_report_permission(report: &chinwag_swarm::room::ClaimTaskReport) {
///     let _: chinwag_seed::write_gate::WritePermit<'_> = report;
/// }
/// ```
pub fn decide_write(report: &ClaimTaskReport) -> Result<NoGrant, WriteDenial> {
    match report {
        ClaimTaskReport::Refused { .. }
        | ClaimTaskReport::OriginalUnresolved
        | ClaimTaskReport::Reported { .. } => Err(WriteDenial::NoLiveGrant),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_current_claim_report_is_denied() {
        for report in [
            ClaimTaskReport::Refused {
                status: 403,
                code: "claim_policy".into(),
                cf_ray: "fixture-TEST".into(),
            },
            ClaimTaskReport::OriginalUnresolved,
            ClaimTaskReport::Reported {
                disposition: "stored_authenticated_outcome",
                cf_ray: "fixture-TEST".into(),
            },
        ] {
            assert_eq!(decide_write(&report).unwrap_err(), WriteDenial::NoLiveGrant);
        }
    }
}
