#![forbid(unsafe_code)]
use chinwag_editor_config_private::{Editor, Launch, MAX_BYTES, Plan, Refusal, plan};

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
fn three_current_project_formats_and_idempotency() {
    let args = vec!["serve-private-fixture".into(), "literal fixture 🌱".into()];
    for (editor, path) in [
        (Editor::ClaudeCode, ".mcp.json"),
        (Editor::Cursor, ".cursor/mcp.json"),
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
