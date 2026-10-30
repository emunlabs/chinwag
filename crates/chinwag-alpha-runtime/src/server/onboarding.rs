//! Explicit native loopback human-action boundary; no discovery on these routes.
//! The intent header is a native-client convention within the loopback trust
//! domain, not authenticated proof of a human, named application or account.
//! Only explicit startup configuration enables opening; default routes cannot.

use super::{AppState, boundary, failure, response};
use crate::onboarding::{OnboardingError, disabled_status};
use crate::{Result, RuntimeError};
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use chinwag_bus_client::{NativeOpenRequest, validate_request_id};
use serde::Serialize;
use serde_json::json;

const MAX_OPEN_BODY: usize = 1024;

fn explicit_boundary(headers: &HeaderMap, uri: &Uri) -> Result<()> {
    boundary(headers)?;
    if headers
        .get_all("x-chinwag-onboarding-intent")
        .iter()
        .count()
        != 1
        || headers
            .get("x-chinwag-onboarding-intent")
            .and_then(|value| value.to_str().ok())
            != Some("1")
    {
        return Err(RuntimeError::Rejected(
            "explicit native onboarding intent required".into(),
        ));
    }
    if uri.query().is_some() {
        return Err(RuntimeError::Invalid(
            "onboarding routes accept no query parameters".into(),
        ));
    }
    Ok(())
}

fn validate_open(headers: &HeaderMap, bytes: &[u8]) -> Result<(String, NativeOpenRequest)> {
    let json_content = headers.get_all("content-type").iter().count() == 1
        && headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                let mut parts = value.split(';').map(str::trim);
                parts
                    .next()
                    .is_some_and(|mime| mime.eq_ignore_ascii_case("application/json"))
                    && parts.all(|part| part.eq_ignore_ascii_case("charset=utf-8"))
            });
    if !json_content {
        return Err(RuntimeError::Invalid(
            "one application/json content type is required".into(),
        ));
    }
    if bytes.is_empty() || bytes.len() > MAX_OPEN_BODY {
        return Err(RuntimeError::Invalid(
            "opening JSON must contain at most 1024 bytes".into(),
        ));
    }
    if headers.get_all("x-chinwag-request-id").iter().count() != 1 {
        return Err(RuntimeError::Invalid(
            "one X-Chinwag-Request-Id is required".into(),
        ));
    }
    let id = headers
        .get("x-chinwag-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|id| validate_request_id(id).is_ok())
        .ok_or_else(|| RuntimeError::Invalid("invalid opening request ID".into()))?
        .to_owned();
    let request: NativeOpenRequest = serde_json::from_slice(bytes).map_err(|_| {
        RuntimeError::Invalid("opening JSON accepts only one observed installation_id".into())
    })?;
    request
        .validate()
        .map_err(|_| RuntimeError::Invalid("invalid observed installation ID".into()))?;
    Ok((id, request))
}

fn unavailable() -> Response {
    response(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"ok":false,"error":"native application opening is unavailable on this runtime"}),
    )
}

fn service_failure(error: OnboardingError) -> Response {
    let (status, message) = match error {
        OnboardingError::Invalid => (StatusCode::BAD_REQUEST, "invalid native opening request"),
        OnboardingError::Conflict => (
            StatusCode::CONFLICT,
            "native opening conflicts with the recorded attempt or current observation",
        ),
        OnboardingError::Busy => (
            StatusCode::CONFLICT,
            "native opening is busy; this request has not started",
        ),
        OnboardingError::Storage => (
            StatusCode::SERVICE_UNAVAILABLE,
            "native opening journal is unavailable; use read-only receipt recovery",
        ),
        OnboardingError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "native application opening is unavailable on this runtime",
        ),
    };
    response(status, json!({"ok":false,"error":message}))
}

fn encoded(value: &impl Serialize) -> Response {
    match serde_json::to_value(value) {
        Ok(value) => response(StatusCode::OK, value),
        Err(_) => unavailable(),
    }
}

pub(super) async fn status(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = explicit_boundary(&headers, &uri) {
        return failure(error);
    }
    let Some(service) = state.2 else {
        return encoded(&disabled_status());
    };
    match tokio::task::spawn_blocking(move || {
        let status = service.status()?;
        if status.validate().is_err() {
            let _ = service.invalidate();
            return Err(OnboardingError::Unavailable);
        }
        Ok(status)
    })
    .await
    {
        Ok(Ok(status)) => encoded(&status),
        Ok(Err(error)) => service_failure(error),
        Err(_) => unavailable(),
    }
}

pub(super) async fn open(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    if let Err(error) = explicit_boundary(&headers, &uri) {
        return failure(error);
    }
    let (id, request) = match validate_open(&headers, &bytes) {
        Ok(value) => value,
        Err(error) => return failure(error),
    };
    let Some(service) = state.2 else {
        return unavailable();
    };
    match tokio::task::spawn_blocking(move || {
        let receipt = service.open(&id, &request)?;
        receipt
            .validate_for(&id, &request)
            .map_err(|_| OnboardingError::Unavailable)?;
        Ok(receipt)
    })
    .await
    {
        Ok(Ok(receipt)) => encoded(&receipt),
        Ok(Err(error)) => service_failure(error),
        Err(_) => unavailable(),
    }
}

pub(super) async fn lookup(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = explicit_boundary(&headers, &uri) {
        return failure(error);
    }
    if validate_request_id(&id).is_err() {
        return failure(RuntimeError::Invalid("invalid opening request ID".into()));
    }
    let Some(service) = state.2 else {
        return unavailable();
    };
    match tokio::task::spawn_blocking(move || {
        let receipt = service.lookup(&id)?;
        if let Some(receipt) = &receipt {
            receipt
                .validate()
                .map_err(|_| OnboardingError::Unavailable)?;
            if receipt.request_id != id {
                return Err(OnboardingError::Unavailable);
            }
        }
        Ok(receipt)
    })
    .await
    {
        Ok(Ok(Some(receipt))) => encoded(&receipt),
        Ok(Ok(None)) => response(
            StatusCode::NOT_FOUND,
            json!({"ok":false,"error":"unknown native opening request ID"}),
        ),
        Ok(Err(error)) => service_failure(error),
        Err(_) => unavailable(),
    }
}

pub(super) async fn deny_get_method() -> Response {
    deny_method("GET")
}
pub(super) async fn deny_post_method() -> Response {
    deny_method("POST")
}

fn deny_method(allowed: &'static str) -> Response {
    let mut result = response(
        StatusCode::METHOD_NOT_ALLOWED,
        json!({"ok":false,"error":"method not permitted for this onboarding route"}),
    );
    result
        .headers_mut()
        .insert("allow", allowed.parse().expect("constant HTTP method"));
    result
}

#[cfg(test)]
mod tests;
