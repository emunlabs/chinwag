//! HTTP discovery responses required by native iroh 1.4.1 net_report.
//! These routes reveal no endpoint identity and do not admit a relay session.
#[derive(Debug, PartialEq, Eq)]
pub struct ProbeResponse {
    pub status: u16,
    pub allow_origin: bool,
    pub challenge_response: Option<String>,
}

pub fn response(is_get: bool, path: &str, challenge: Option<&str>) -> Option<ProbeResponse> {
    if !is_get {
        return None;
    }
    match path {
        "/ping" => Some(ProbeResponse {
            status: 200,
            allow_origin: true,
            challenge_response: None,
        }),
        "/generate_204" => Some(ProbeResponse {
            status: 204,
            allow_origin: false,
            challenge_response: challenge
                .filter(|value| {
                    !value.is_empty()
                        && value.len() < 64
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                        })
                })
                .map(|value| format!("response {value}")),
        }),
        _ => None,
    }
}
