//! Human-action native opening and read-only recovery on the configured host.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{BusClient, ClientError, read_json, validate_request_id};

const INTENT: &str = "X-Chinwag-Onboarding-Intent";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingStatus {
    pub schema: String,
    pub native_open_allowed: bool,
    pub openable_installation_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOpenRequest {
    pub installation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeOpenState {
    Pending,
    OpenedOrReused,
    Rejected,
    Uncertain,
}

/// An OS opening receipt, never a connection, account or model readiness proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOpenReceipt {
    pub schema: String,
    pub request_id: String,
    pub installation_id: String,
    pub state: NativeOpenState,
    pub message: String,
}

fn opaque_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl OnboardingStatus {
    pub fn validate(&self) -> Result<(), ClientError> {
        let mut ids = HashSet::new();
        if self.schema != "chinwag-native-onboarding/v1"
            || self.openable_installation_ids.len() > 128
            || (!self.native_open_allowed && !self.openable_installation_ids.is_empty())
            || self
                .openable_installation_ids
                .iter()
                .any(|id| !opaque_id(id) || !ids.insert(id))
        {
            return Err(ClientError::InvalidResponse(
                "invalid native onboarding capability".into(),
            ));
        }
        Ok(())
    }
}

impl NativeOpenRequest {
    pub fn validate(&self) -> Result<(), ClientError> {
        if !opaque_id(&self.installation_id) {
            return Err(ClientError::InvalidRequest(
                "select one observed opaque installation ID".into(),
            ));
        }
        Ok(())
    }
}

impl NativeOpenReceipt {
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.schema != "chinwag-native-open/v1"
            || validate_request_id(&self.request_id).is_err()
            || !opaque_id(&self.installation_id)
            || self.message.is_empty()
            || self.message.len() > 240
            || self.message.chars().any(char::is_control)
        {
            return Err(ClientError::InvalidResponse(
                "invalid native opening receipt".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        request_id: &str,
        request: &NativeOpenRequest,
    ) -> Result<(), ClientError> {
        self.validate()?;
        if self.request_id != request_id || self.installation_id != request.installation_id {
            return Err(ClientError::InvalidResponse(
                "opening receipt does not match the selected attempt and application".into(),
            ));
        }
        Ok(())
    }
}

impl BusClient {
    /// Capability lookup only. Does not inventory or open applications.
    pub fn onboarding_status(&self) -> Result<OnboardingStatus, ClientError> {
        let status: OnboardingStatus = read_json(
            self.http
                .get(self.endpoint("/api/onboarding/status"))
                .header(INTENT, "1")
                .send()?,
        )?;
        status.validate()?;
        Ok(status)
    }

    /// One explicit human-action POST. Persist the ID and selected endpoint
    /// before calling. A missing valid receipt never authorizes another POST.
    pub fn open_application(
        &self,
        request_id: &str,
        request: &NativeOpenRequest,
    ) -> Result<NativeOpenReceipt, ClientError> {
        validate_request_id(request_id)?;
        request.validate()?;
        let perform = || -> Result<NativeOpenReceipt, ClientError> {
            let receipt: NativeOpenReceipt = read_json(
                self.http
                    .post(self.endpoint("/api/onboarding/open"))
                    .header(INTENT, "1")
                    .header("X-Chinwag-Request-Id", request_id)
                    .json(request)
                    .send()?,
            )?;
            receipt.validate_for(request_id, request)?;
            Ok(receipt)
        };
        perform().map_err(|error| ClientError::NativeOpenOutcomeUnknown {
            // Even an HTTP error may follow a submitted open. Recovery is GET
            // only, so a later client cannot misclassify an error as replayable.
            reason: error.to_string(),
        })
    }

    /// GET only, including when the original POST response was lost.
    pub fn application_open_receipt(
        &self,
        request_id: &str,
    ) -> Result<Option<NativeOpenReceipt>, ClientError> {
        validate_request_id(request_id)?;
        let response = self
            .http
            .get(self.endpoint(&format!("/api/onboarding/opens/{request_id}")))
            .header(INTENT, "1")
            .send()?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let receipt: NativeOpenReceipt = read_json(response)?;
        receipt.validate()?;
        if receipt.request_id != request_id {
            return Err(ClientError::InvalidResponse(
                "opening lookup returned another attempt".into(),
            ));
        }
        Ok(Some(receipt))
    }
}
