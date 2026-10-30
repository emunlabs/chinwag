use super::*;
use crate::mcp_config::{MAX_COMMAND_BYTES, MAX_ENDPOINT_BYTES};
use serde_json::{Value, json};
use url::Url;

fn spec(binary: &str, endpoint: &str) -> Result<VsCodeMcpInstall, VsCodeMcpInstallError> {
    VsCodeMcpInstall::new(binary.into(), endpoint.into())
}

fn payload(spec: &VsCodeMcpInstall) -> Value {
    let uri = Url::parse(&spec.install_uri).unwrap();
    assert_eq!(uri.scheme(), "vscode");
    assert_eq!(uri.host_str(), None);
    assert_eq!(uri.path(), "mcp/install");
    assert!(uri.fragment().is_none());
    let query = uri.query().unwrap();
    assert!(query.starts_with("%7B%22"));
    assert!(!query.contains(['+', '&', '#', ' ', '"', '{', '}']));
    let decoded: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].1, "");
    serde_json::from_str(&decoded[0].0).unwrap()
}

#[test]
fn vscode_install_query_decodes_to_one_fixed_named_stdio_config() {
    let binary = "/owner/declared/Chinwag tools/native inbox";
    let config = payload(&spec(binary, "http://localhost:4780").unwrap());
    assert_eq!(
        config,
        json!({
            "name": "chinwag-native-inbox-mgmt",
            "type": "stdio",
            "command": binary,
            "args": ["--bus-url", "http://127.0.0.1:4780/", "--allow-room", "#mgmt", "--lease-seconds", "900"]
        })
    );
    assert_eq!(config.as_object().unwrap().len(), 4);
    for absent in [
        "config",
        "mcpServers",
        SERVER_NAME,
        "env",
        "envFile",
        "shell",
        "url",
        "headers",
    ] {
        assert!(config.get(absent).is_none());
    }
}

#[test]
fn vscode_uri_uses_percent_encoded_json_not_cursor_base64_or_form_data() {
    let binary = "/owner/Chinwag tools/📨 inbox\"+?&=()!'~*";
    let spec = spec(binary, "http://[::1]:4780/").unwrap();
    let config = payload(&spec);
    assert_eq!(config["command"], binary);
    assert_eq!(config["args"][1], "http://[::1]:4780/");
    assert!(spec.install_uri.contains("%20"));
    assert!(spec.install_uri.contains("%2B"));
    assert!(spec.install_uri.contains("%26%3D"));
    assert!(spec.install_uri.contains("%F0%9F%93%A8"));
    assert!(spec.install_uri.contains("()!'~*"));
    assert!(!spec.install_uri.contains("?name="));
    assert!(!spec.install_uri.contains("config="));
}

#[test]
fn vscode_construction_does_not_require_the_declared_binary_to_exist() {
    let binary = "/nonexistent-owner-declared-root/chinwag-native-inbox-mcp";
    assert_eq!(
        payload(&spec(binary, "http://127.0.0.1:4780").unwrap())["command"],
        binary
    );
}

#[test]
fn vscode_command_validation_rejects_unnormalized_interpolated_and_unbounded_values() {
    for binary in [
        "",
        "chinwag",
        "./chinwag",
        "/",
        "/owner/../bin/chinwag",
        "/owner/./chinwag",
        "/owner//chinwag",
        "/owner/chinwag/",
        "/owner/${env:BINARY}",
        "/owner/$BINARY",
        "/owner/`binary`",
        "/owner/chinwag\n",
        "/owner/chinwag\0",
    ] {
        assert!(
            matches!(
                spec(binary, "http://127.0.0.1:4780"),
                Err(VsCodeMcpInstallError::InvalidBinary)
            ),
            "{binary:?}"
        );
    }
    assert!(matches!(
        spec(
            &format!("/{}", "a".repeat(MAX_COMMAND_BYTES)),
            "http://127.0.0.1:4780"
        ),
        Err(VsCodeMcpInstallError::InvalidBinary)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        assert!(matches!(
            VsCodeMcpInstall::new(
                PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', 0xff])),
                "http://127.0.0.1:4780".into(),
            ),
            Err(VsCodeMcpInstallError::InvalidBinary)
        ));
    }
}

#[test]
fn vscode_endpoint_validation_preserves_the_same_bounded_loopback_origin_scope() {
    for endpoint in [
        "",
        "https://127.0.0.1:4780",
        "http://192.0.2.1:4780",
        "http://example.com:4780",
        "http://localhost.example.com:4780",
        "http://[::]:4780",
        "http://user@127.0.0.1:4780",
        "http://user:password@127.0.0.1:4780",
        "http://@127.0.0.1:4780",
        "http://127.0.0.1:0",
        "http://127.0.0.1:4780/path",
        "http://127.0.0.1:4780/.",
        "http://127.0.0.1:4780/path/..",
        "http://127.0.0.1:4780/%2e",
        "http://127.0.0.1:4780/?token=private",
        "http://127.0.0.1:4780/?",
        "http://127.0.0.1:4780/#fragment",
        "http://127.0.0.1:4780/#",
        " http://127.0.0.1:4780",
        "http://127.0.0.1:4780\n",
        "http://127.0.0.1:${env:PORT}",
        "http://127.0.0.1:4780\\",
    ] {
        assert!(
            matches!(
                spec("/owner/chinwag", endpoint),
                Err(VsCodeMcpInstallError::InvalidEndpoint)
            ),
            "{endpoint:?}"
        );
    }
    assert!(matches!(
        spec(
            "/owner/chinwag",
            &format!("http://localhost:{}", "1".repeat(MAX_ENDPOINT_BYTES))
        ),
        Err(VsCodeMcpInstallError::InvalidEndpoint)
    ));
}
