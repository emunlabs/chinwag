#![forbid(unsafe_code)]
use chinwag_editor_config_private::{
    Editor, Launch, MAX_BYTES, Plan, Refusal, Remote, ServerProfile, plan, plan_profile,
    plan_remote,
};

const COMMAND: &str = "/private fixture/bin/chinwag";
fn proposed(editor: Editor, input: Option<&[u8]>, args: &[String]) -> Vec<u8> {
    let result = plan(
        editor,
        input,
        Launch {
            command: COMMAND,
            args,
        },
    )
    .unwrap();
    match result {
        Plan::Proposed {
            relative_path,
            bytes,
        } => {
            assert_eq!(relative_path, editor.relative_path());
            assert_eq!(
                plan(
                    editor,
                    Some(&bytes),
                    Launch {
                        command: COMMAND,
                        args
                    }
                ),
                Ok(Plan::Unchanged)
            );
            bytes
        }
        Plan::Unchanged => panic!("Expected a new proposal"),
    }
}

#[test]
fn four_current_project_formats_and_idempotency() {
    let args = vec!["serve-private-fixture".into(), "literal fixture 🌱".into()];
    for (editor, path) in [
        (Editor::ClaudeCode, ".mcp.json"),
        (Editor::Cursor, ".cursor/mcp.json"),
        (Editor::Gemini, ".gemini/settings.json"),
    ] {
        assert_eq!(editor.relative_path(), path);
        let bytes = proposed(editor, None, &args);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"mcpServers":{"chinwag":{"type":"stdio","command":COMMAND,"args":args}}})
        );
    }
    let bytes = proposed(Editor::Codex, None, &args);
    let doc: toml_edit::DocumentMut = String::from_utf8(bytes).unwrap().parse().unwrap();
    assert_eq!(
        doc["mcp_servers"]["chinwag"]["command"].as_str(),
        Some(COMMAND)
    );
    assert_eq!(
        doc["mcp_servers"]["chinwag"]["args"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(Editor::Codex.relative_path(), ".codex/config.toml");
}

#[test]
fn json_preserves_every_original_byte_outside_single_insertion_and_numeric_lexemes() {
    let args = vec!["quoted \"arg\" with backslash \\".into()];
    let source = " \n{\"unknown\": [12345678901234567890123456789012345678901234567890,1e400], \"tail\":true  }\t\n";
    let bytes = proposed(Editor::Cursor, Some(source.as_bytes()), &args);
    let text = String::from_utf8(bytes).unwrap();
    let at = source.rfind('}').unwrap();
    assert!(text.starts_with(&source[..at]) && text.ends_with(&source[at..]));
    let source =
        "{\"mcpServers\":{\"other\": {\"command\":\"kept\", \"args\":[] }  },\"suffix\": [1, 2]}\n";
    let text =
        String::from_utf8(proposed(Editor::ClaudeCode, Some(source.as_bytes()), &[])).unwrap();
    let at = source.find("},\"suffix\"").unwrap();
    assert!(text.starts_with(&source[..at]) && text.ends_with(&source[at..]));
}

#[test]
fn malformed_duplicate_escaped_equivalent_and_nonobject_json_refused() {
    for source in [
        "",
        "[]",
        "{",
        "{} trailing",
        "{\"mcpServers\":null}",
        "{\"mcpServers\":{},\"mcpServers\":{}}",
        "{\"mcpServers\":{},\"mcp\\u0053ervers\":{}}",
        "{\"unknown\": [{\"same\":1,\"sa\\u006de\":2}]}",
    ] {
        assert!(
            plan(
                Editor::Cursor,
                Some(source.as_bytes()),
                Launch {
                    command: COMMAND,
                    args: &[]
                }
            )
            .is_err(),
            "{source}"
        );
    }
    assert_eq!(
        plan(
            Editor::Cursor,
            Some(&[0xff]),
            Launch {
                command: COMMAND,
                args: &[]
            }
        ),
        Err(Refusal::InvalidDocument)
    );
}

#[test]
fn existing_customized_json_entry_never_overwritten() {
    for entry in [
        serde_json::json!({"type":"stdio","command":"/different","args":[]}),
        serde_json::json!({"type":"stdio","command":COMMAND,"args":[],"env":{"fixture":"keep"}}),
        serde_json::json!({"command":COMMAND,"args":[]}),
        serde_json::json!({"type":"stdio","command":COMMAND,"args":[],"disabled":true}),
        serde_json::json!(null),
    ] {
        let source =
            serde_json::to_vec(&serde_json::json!({"mcpServers":{"chinwag":entry}})).unwrap();
        let before = source.clone();
        assert_eq!(
            plan(
                Editor::ClaudeCode,
                Some(&source),
                Launch {
                    command: COMMAND,
                    args: &[]
                }
            ),
            Err(Refusal::Conflict)
        );
        assert_eq!(source, before);
    }
}

#[test]
fn toml_preserves_exact_input_prefix_comments_and_unknown_values() {
    let source = "# Keep this comment\nunknown = 0x123456\n[mcp_servers.other]\ncommand = 'custom' # keep spelling\nargs = []\n";
    let args = vec!["tab\t newline\n quote\" slash\\ unicode私".into()];
    let text = String::from_utf8(proposed(Editor::Codex, Some(source.as_bytes()), &args)).unwrap();
    assert!(text.starts_with(source));
    let doc: toml_edit::DocumentMut = text.parse().unwrap();
    assert_eq!(
        doc["mcp_servers"]["other"]["command"].as_str(),
        Some("custom")
    );
    assert_eq!(
        doc["mcp_servers"]["chinwag"]["args"][0].as_str(),
        Some(args[0].as_str())
    );
}

#[test]
fn toml_conflicts_duplicate_keys_and_closed_inline_parent_refused() {
    for source in [
        "a=1\na=2\n",
        "mcp_servers = {}\n",
        "mcp_servers = []\n",
        "[mcp_servers.chinwag]\ncommand='/different'\nargs=[]\n",
        "[mcp_servers.chinwag]\ncommand='/private fixture/bin/chinwag'\nargs=[]\nenabled=false\n",
    ] {
        assert!(
            plan(
                Editor::Codex,
                Some(source.as_bytes()),
                Launch {
                    command: COMMAND,
                    args: &[]
                }
            )
            .is_err()
        );
    }
    let exact = "mcp_servers = { chinwag = {command='/private fixture/bin/chinwag',args=[]} }\n";
    assert_eq!(
        plan(
            Editor::Codex,
            Some(exact.as_bytes()),
            Launch {
                command: COMMAND,
                args: &[]
            }
        ),
        Ok(Plan::Unchanged)
    );
}

#[test]
fn document_depth_node_and_output_limits() {
    for text in [
        format!("{{\"deep\":{}0{}}}", "[".repeat(66), "]".repeat(66)),
        format!("{{\"many\":[{}]}}", vec!["0"; 10_001].join(",")),
        format!("{{\"wide\":\"{}\"}}", "x".repeat(MAX_BYTES)),
        format!("{{\"near\":\"{}\"}}", "x".repeat(MAX_BYTES - 30)),
    ] {
        assert!(
            plan(
                Editor::Cursor,
                Some(text.as_bytes()),
                Launch {
                    command: COMMAND,
                    args: &[]
                }
            )
            .is_err()
        );
    }
}

#[test]
fn launch_is_literal_bounded_and_never_expands_environment() {
    for command in ["relative", "", "/path\0bad", "/path/${WORKSPACE}"] {
        assert_eq!(
            plan(Editor::Codex, None, Launch { command, args: &[] }),
            Err(Refusal::InvalidLaunch)
        );
    }
    for args in [
        vec!["${SECRET}".into()],
        vec!["bad\0arg".into()],
        vec![String::new(); 65],
        vec!["x".repeat(16_385)],
    ] {
        assert_eq!(
            plan(
                Editor::Cursor,
                None,
                Launch {
                    command: COMMAND,
                    args: &args
                }
            ),
            Err(Refusal::InvalidLaunch)
        );
    }
}

#[test]
fn gemini_settings_preserve_unrelated_settings_and_do_not_add_trust() {
    let original = br#" {
  "security": {"folderTrust": {"enabled": true}},
  "general": {"preferredEditor": "vscode"},
  "mcpServers": {"other": {"command": "kept", "args": []} }
}
"#;
    let args = vec![
        "mcp-serve".to_owned(),
        "--repo".to_owned(),
        "/owned/repo".to_owned(),
    ];
    let actual = proposed(Editor::Gemini, Some(original), &args);
    let original = std::str::from_utf8(original).unwrap();
    let at = original.find("} }\n").unwrap() + 2;
    let text = std::str::from_utf8(&actual).unwrap();
    assert!(text.starts_with(&original[..at]) && text.ends_with(&original[at..]));
    let actual: serde_json::Value = serde_json::from_slice(&actual).unwrap();
    assert_eq!(actual["security"]["folderTrust"]["enabled"], true);
    assert_eq!(actual["general"]["preferredEditor"], "vscode");
    assert_eq!(actual["mcpServers"]["other"]["command"], "kept");
    assert_eq!(
        actual["mcpServers"]["chinwag"],
        serde_json::json!({"type":"stdio", "command":COMMAND, "args":args})
    );
}

#[test]
fn gemini_conflicting_and_malformed_settings_are_refused() {
    for original in [
        br#"{"mcpServers":{"chinwag":{"command":"/custom","args":[]}}}"#.as_slice(),
        br#"{"mcpServers":{"chinwag":{"type":"stdio","command":"/private fixture/bin/chinwag","args":[],"trust":true}}}"#.as_slice(),
        br#"{"mcpServers":null}"#.as_slice(),
        br#"{"mcpServers":{},"mcpServers":{}}"#.as_slice(),
        b"[ ]".as_slice(),
    ] {
        let before = original.to_vec();
        assert!(plan(Editor::Gemini, Some(original), Launch { command: COMMAND, args: &[] }).is_err());
        assert_eq!(original, before);
    }
}

#[test]
fn six_editors_local_and_remote_profiles_round_trip_and_replay_unchanged() {
    let local_args = vec![
        "mcp-serve".to_owned(),
        "--repo".to_owned(),
        "/owned/repo".to_owned(),
    ];
    let remote = Remote {
        url: "https://mcp.chinwag.sh/mcp",
    };

    for editor in Editor::ALL {
        // Local profile
        let bytes = proposed(editor, None, &local_args);
        match editor {
            Editor::ClaudeCode | Editor::Cursor | Editor::Gemini => {
                let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    doc["mcpServers"]["chinwag"],
                    serde_json::json!({"type":"stdio","command":COMMAND,"args":local_args})
                );
            }
            Editor::VsCode => {
                assert_eq!(editor.relative_path(), ".vscode/mcp.json");
                let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert!(doc.get("mcpServers").is_none());
                assert_eq!(
                    doc["servers"]["chinwag"],
                    serde_json::json!({"type":"stdio","command":COMMAND,"args":local_args})
                );
            }
            Editor::Codex | Editor::Grok => {
                let text = String::from_utf8(bytes).unwrap();
                let doc: toml_edit::DocumentMut = text.parse().unwrap();
                assert_eq!(
                    doc["mcp_servers"]["chinwag"]["command"].as_str(),
                    Some(COMMAND)
                );
            }
        }

        // Remote profile
        let Plan::Proposed {
            relative_path,
            bytes: remote_bytes,
        } = plan_remote(editor, None, remote).unwrap()
        else {
            panic!("expected remote proposal for {editor:?}");
        };
        assert_eq!(relative_path, editor.relative_path());
        assert_eq!(
            plan_remote(editor, Some(&remote_bytes), remote),
            Ok(Plan::Unchanged)
        );
        match editor {
            Editor::ClaudeCode | Editor::Cursor => {
                let doc: serde_json::Value = serde_json::from_slice(&remote_bytes).unwrap();
                assert_eq!(
                    doc["mcpServers"]["chinwag"],
                    serde_json::json!({"type":"http","url":"https://mcp.chinwag.sh/mcp"})
                );
            }
            Editor::Gemini => {
                let doc: serde_json::Value = serde_json::from_slice(&remote_bytes).unwrap();
                assert_eq!(
                    doc["mcpServers"]["chinwag"],
                    serde_json::json!({"httpUrl":"https://mcp.chinwag.sh/mcp"})
                );
            }
            Editor::VsCode => {
                let doc: serde_json::Value = serde_json::from_slice(&remote_bytes).unwrap();
                assert_eq!(
                    doc["servers"]["chinwag"],
                    serde_json::json!({"type":"http","url":"https://mcp.chinwag.sh/mcp"})
                );
            }
            Editor::Codex | Editor::Grok => {
                let doc: toml_edit::DocumentMut =
                    String::from_utf8(remote_bytes).unwrap().parse().unwrap();
                assert_eq!(
                    doc["mcp_servers"]["chinwag"]["url"].as_str(),
                    Some("https://mcp.chinwag.sh/mcp")
                );
            }
        }
    }
}

#[test]
fn vscode_and_grok_preserve_unrelated_servers_and_refuse_shell_wrappers_or_env_vars() {
    let vscode_existing =
        br#"{"servers":{"github":{"type":"http","url":"https://api.githubcopilot.com/mcp"}},"inputs":[]}"#;
    let Plan::Proposed { bytes: vs_out, .. } = plan_remote(
        Editor::VsCode,
        Some(vscode_existing),
        Remote {
            url: "https://mcp.chinwag.sh/mcp",
        },
    )
    .unwrap() else {
        panic!("expected vscode proposal");
    };
    let vs_doc: serde_json::Value = serde_json::from_slice(&vs_out).unwrap();
    assert_eq!(
        vs_doc["servers"]["github"]["url"],
        "https://api.githubcopilot.com/mcp"
    );
    assert_eq!(
        vs_doc["servers"]["chinwag"]["url"],
        "https://mcp.chinwag.sh/mcp"
    );

    let grok_existing = b"# user comment\n[mcp_servers.other]\nurl = 'https://example.com/mcp'\n";
    let Plan::Proposed {
        bytes: grok_out, ..
    } = plan_remote(
        Editor::Grok,
        Some(grok_existing),
        Remote {
            url: "https://mcp.chinwag.sh/mcp",
        },
    )
    .unwrap()
    else {
        panic!("expected grok proposal");
    };
    assert!(grok_out.starts_with(grok_existing));

    // Shell wrappers and $-interpolation / %-interpolation MUST fail closed
    for bad_cmd in [
        "/bin/sh",
        "/bin/bash",
        "/bin/zsh",
        "/usr/bin/env",
        "/usr/local/bin/pwsh",
        "/owned/../bin/chinwag",
        "/owned/$HOME/chinwag",
    ] {
        assert_eq!(
            plan(
                Editor::VsCode,
                None,
                Launch {
                    command: bad_cmd,
                    args: &[]
                }
            ),
            Err(Refusal::InvalidLaunch),
            "accepted forbidden command {bad_cmd}"
        );
    }
    for bad_args in [
        vec!["-c".to_owned(), "chinwag mcp-serve".to_owned()],
        vec!["-lc".to_owned(), "chinwag".to_owned()],
        vec!["$REPO_ROOT".to_owned()],
        vec!["$(pwd)".to_owned()],
        vec!["%USERPROFILE%\\repo".to_owned()],
        vec!["${env:API_KEY}".to_owned()],
        vec!["${workspaceFolder}".to_owned()],
    ] {
        assert_eq!(
            plan(
                Editor::Grok,
                None,
                Launch {
                    command: COMMAND,
                    args: &bad_args
                }
            ),
            Err(Refusal::InvalidLaunch),
            "accepted forbidden args {bad_args:?}"
        );
    }
    for bad_url in [
        "http://mcp.chinwag.sh/mcp",
        "https://user:secret@mcp.chinwag.sh/mcp",
        "https://mcp.chinwag.sh/mcp?token=secret",
        "https://mcp.chinwag.sh/mcp#frag",
        "https://mcp.chinwag.sh/${ORG}/mcp",
        "https://mcp.chinwag.sh/$ORG/mcp",
        "https://localhost/mcp",
    ] {
        assert_eq!(
            plan_profile(
                Editor::VsCode,
                None,
                ServerProfile::Remote(Remote { url: bad_url })
            ),
            Err(Refusal::InvalidLaunch),
            "accepted forbidden url {bad_url}"
        );
    }
}
