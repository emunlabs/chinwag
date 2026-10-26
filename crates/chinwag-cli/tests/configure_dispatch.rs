use chinwag_cli::{Dispatch, Exit, Rejection, dispatch};
use std::ffi::OsStr;
#[test]
fn all_aliases_parse_only_the_explicit_editor_request() {
    for alias in [
        "chinwag",
        "git-chinwag",
        "git-emun",
        "gh-chinwag",
        "gh-emun",
    ] {
        for editor in ["claude-code", "cursor", "codex"] {
            assert!(matches!(
                dispatch(
                    OsStr::new(alias),
                    [
                        "configure-editor",
                        "--repo",
                        "/owned/repo",
                        "--editor",
                        editor
                    ]
                ),
                Dispatch::Configure(_)
            ));
            assert!(matches!(
                dispatch(
                    OsStr::new(alias),
                    [
                        "configure-editor",
                        "--editor",
                        editor,
                        "--repo",
                        "/owned/repo"
                    ]
                ),
                Dispatch::Configure(_)
            ));
        }
        let Dispatch::Immediate(help) = dispatch(OsStr::new(alias), ["configure-editor", "--help"])
        else {
            panic!("help not immediate")
        };
        assert_eq!(help.code(), 0);
        assert!(help.stdout().contains("configure-editor") && help.stdout().contains("--editor"));
    }
}
#[test]
fn duplicate_flags_arbitrary_launch_and_unbounded_paths_are_rejected_before_dispatch() {
    for args in [
        vec!["configure-editor", "--repo", "/owned/repo"],
        vec![
            "configure-editor",
            "--repo",
            "/owned/repo",
            "--repo",
            "/owned/other",
        ],
        vec![
            "configure-editor",
            "--repo",
            "relative",
            "--editor",
            "codex",
        ],
        vec![
            "configure-editor",
            "--repo",
            "/owned/../other",
            "--editor",
            "codex",
        ],
        vec![
            "configure-editor",
            "--repo",
            "/owned/${SECRET}",
            "--editor",
            "cursor",
        ],
        vec![
            "configure-editor",
            "--repo",
            "/owned/repo",
            "--editor",
            "unknown",
        ],
        vec![
            "configure-editor",
            "--repo",
            "/owned/repo",
            "--editor",
            "codex",
            "--command",
            "/arbitrary",
        ],
    ] {
        assert_eq!(
            dispatch(OsStr::new("chinwag"), args),
            Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments))
        );
    }
    let long = format!("/{}", "a".repeat(4096));
    assert_eq!(
        dispatch(
            OsStr::new("chinwag"),
            ["configure-editor", "--repo", &long, "--editor", "codex"]
        ),
        Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments))
    );
}
