use super::*;
use serde_json::{Value, json};

fn spec(binary: &str, endpoint: &str) -> Result<CursorMcpInstall, CursorMcpInstallError> {
    CursorMcpInstall::new(binary.into(), endpoint.into())
}

fn payload(spec: &CursorMcpInstall) -> (Url, Value) {
    let uri = Url::parse(&spec.install_uri).unwrap();
    assert_eq!(uri.scheme(), "cursor");
    assert_eq!(uri.host_str(), Some("anysphere.cursor-deeplink"));
    assert_eq!(uri.path(), "/mcp/install");
    assert!(uri.username().is_empty());
    assert!(uri.password().is_none());
    assert!(uri.fragment().is_none());
    let pairs: Vec<_> = uri.query_pairs().collect();
    assert_eq!(pairs.len(), 2);
    assert_eq!(
        pairs[0],
        ("name".into(), "chinwag-native-inbox-mgmt".into())
    );
    assert_eq!(pairs[1].0, "config");
    let decoded = STANDARD.decode(pairs[1].1.as_bytes()).unwrap();
    assert_eq!(STANDARD.encode(&decoded), pairs[1].1);
    let value = serde_json::from_slice(&decoded).unwrap();
    (uri, value)
}

#[test]
fn cursor_link_decodes_to_fixed_inner_stdio_value_with_separate_name() {
    let binary = "/owner/declared/Chinwag tools/native inbox";
    let spec = spec(binary, "http://localhost:4780").unwrap();
    let (_, value) = payload(&spec);
    assert_eq!(
        value,
        json!({
            "type": "stdio",
            "command": binary,
            "args": ["--bus-url", "http://127.0.0.1:4780/", "--allow-room", "#mgmt", "--lease-seconds", "900"]
        })
    );
    assert_eq!(value.as_object().unwrap().len(), 3);
    for absent in ["mcpServers", SERVER_NAME, "env", "envFile", "shell", "url"] {
        assert!(value.get(absent).is_none());
    }
}

#[test]
fn json_base64_and_query_round_trip_literal_command_without_interpolation() {
    let mut saw_encoded_padding = false;
    for suffix in ["", "1", "12"] {
        let binary = format!("/owner/Chinwag tools/📨 inbox\"+?{suffix}");
        let spec = spec(&binary, "http://[::1]:4780/").unwrap();
        let (uri, value) = payload(&spec);
        assert_eq!(value["command"], binary);
        assert_eq!(value["args"][1], "http://[::1]:4780/");
        assert!(!spec.install_uri.contains(' '));
        assert!(!spec.install_uri.contains('#'));
        assert_eq!(
            uri.query_pairs()
                .filter(|(name, _)| name == "config")
                .count(),
            1
        );
        saw_encoded_padding |= spec.install_uri.contains("%3D");
    }
    assert!(
        saw_encoded_padding,
        "standard Base64 padding must be query encoded"
    );
}

#[test]
fn construction_is_pure_and_preserves_owner_declared_command() {
    let binary = "/nonexistent-owner-declared-root/chinwag-native-inbox-mcp";
    let (_, config) = payload(&spec(binary, "http://127.0.0.1:4780").unwrap());
    assert_eq!(config["command"], binary);
}

#[test]
fn command_path_rejects_relative_unnormalized_interpolated_and_unbounded_values() {
    for binary in [
        "",
        "chinwag-native-inbox-mcp",
        "./chinwag-native-inbox-mcp",
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
                Err(CursorMcpInstallError::InvalidBinary)
            ),
            "{binary:?}"
        );
    }
    assert!(matches!(
        spec(
            &format!("/{}", "a".repeat(MAX_COMMAND_BYTES)),
            "http://127.0.0.1:4780"
        ),
        Err(CursorMcpInstallError::InvalidBinary)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        assert!(matches!(
            CursorMcpInstall::new(
                PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', 0xff])),
                "http://127.0.0.1:4780".into(),
            ),
            Err(CursorMcpInstallError::InvalidBinary)
        ));
    }
}

#[test]
fn endpoint_rejects_nonloopback_credentials_paths_queries_fragments_and_interpolation() {
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
                Err(CursorMcpInstallError::InvalidEndpoint)
            ),
            "{endpoint:?}"
        );
    }
    assert!(matches!(
        spec(
            "/owner/chinwag",
            &format!("http://localhost:{}", "1".repeat(MAX_ENDPOINT_BYTES))
        ),
        Err(CursorMcpInstallError::InvalidEndpoint)
    ));
}
