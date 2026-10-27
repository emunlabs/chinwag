//! Parser and before-start refusals only. Native init is checked through the
//! normal panic=abort release binary by the separate one-shot QA operator.
#![cfg(target_os = "macos")]
use chinwag_cli::{Dispatch, Exit, Rejection, dispatch, run_init};
use serde_json::Value;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;

const ALIASES: [&str; 5] = [
    "chinwag",
    "git-chinwag",
    "git-emun",
    "gh-chinwag",
    "gh-emun",
];
const REPO: &str = "/synthetic-chinwag-parser-only/repo";
fn arguments() -> Vec<OsString> {
    [
        "init",
        "--repo",
        REPO,
        "--private-dir",
        "/synthetic-chinwag-parser-only/repo/.chinwag",
        "--principal",
        "fixture@chinwag.test",
    ]
    .map(OsString::from)
    .to_vec()
}
#[test]
fn all_aliases_parse_fresh_requests_without_starting_them() {
    for alias in ALIASES {
        assert!(matches!(
            dispatch(OsStr::new(alias), arguments()),
            Dispatch::Init(_)
        ));
        assert!(matches!(
            dispatch(
                OsStr::new(alias),
                [
                    "init",
                    "--repo=/synthetic-chinwag-parser-only/repo",
                    "--private-dir=/synthetic-chinwag-parser-only/repo/.chinwag",
                    "--principal=fixture@chinwag.test"
                ]
            ),
            Dispatch::Init(_)
        ));
    }
}
#[test]
fn malformed_arguments_are_rejected_by_the_dispatcher() {
    let mut cases = vec![vec![OsString::from("init"), OsString::from("--principal")]];
    let mut duplicate = arguments();
    duplicate.extend(["--principal".into(), "fixture@chinwag.test".into()]);
    cases.push(duplicate);
    let mut relative = arguments();
    relative[2] = "relative".into();
    cases.push(relative);
    let mut parent = arguments();
    parent[2] = "/synthetic-chinwag-parser-only/repo/../repo".into();
    cases.push(parent);
    let mut invalid = arguments();
    invalid[4] = OsString::from_vec(vec![0xff]);
    cases.push(invalid);
    for pin in ["bad".to_owned(), "AA".repeat(32)] {
        let mut args = arguments();
        args.extend(["--reuse-public".into(), pin.into()]);
        cases.push(args);
    }
    for flag in ["--global", "--cloud", "--gh"] {
        let mut args = arguments();
        args.push(flag.into());
        cases.push(args);
    }
    for alias in ALIASES {
        for args in &cases {
            assert_eq!(
                dispatch(OsStr::new(alias), args),
                Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments))
            );
        }
    }
}
#[test]
fn unsupported_scopes_refuse_before_any_filesystem_or_entropy_call() {
    for alias in ALIASES {
        for reuse in [false, true] {
            let mut args = arguments();
            let reason = if reuse {
                args.extend(["--reuse-public".into(), "00".repeat(32).into()]);
                "init_reuse_not_supported"
            } else {
                args[4] = "/synthetic-chinwag-parser-only/arbitrary-identity".into();
                "init_private_directory"
            };
            let Dispatch::Init(request) = dispatch(OsStr::new(alias), args) else {
                panic!("expected parsed request")
            };
            let (mut out, mut err) = (Vec::new(), Vec::new());
            assert_eq!(run_init(request, &mut out, &mut err), 1);
            let value: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(value["schema"], 2);
            assert_eq!(value["reason"], reason);
            assert_eq!(value["stage"], "preflight");
            assert_eq!(value["material"], "not_started");
            for field in [
                "signing_configured",
                "signature_verified",
                "signing_binding_current",
                "store_attempted",
                "store_callee_completed",
                "local_store_confirmed",
                "integrated_receipt",
                "full_init_complete",
                "hosted_verified",
            ] {
                assert_eq!(value[field], false);
            }
            assert!(value.get("proof").is_none() && value.get("store").is_none());
            assert_eq!(err, format!("chinwag: {reason}\n").as_bytes());
        }
    }
}
#[test]
fn help_describes_the_fresh_fixed_directory_scope() {
    for alias in ALIASES {
        let Dispatch::Immediate(help) = dispatch(OsStr::new(alias), ["init", "--help"]) else {
            panic!("expected help")
        };
        assert_eq!(help.code(), 0);
        assert!(help.stdout().contains("<repo>/.chinwag"));
        assert!(help.stdout().contains("--reuse-public is unavailable"));
        assert!(help.stdout().contains("offline store"));
    }
}

#[test]
fn normal_defaults_parse_without_reading_the_working_directory() {
    for alias in ALIASES {
        for args in [
            vec!["init", "--principal", "fixture@chinwag.test"],
            vec!["init", "--principal=fixture@chinwag.test"],
            vec![
                "init",
                "--repo",
                REPO,
                "--principal",
                "fixture@chinwag.test",
            ],
            vec![
                "init",
                "--principal",
                "fixture@chinwag.test",
                "--private-dir",
                "/synthetic-chinwag-parser-only/repo/.chinwag",
            ],
        ] {
            assert!(matches!(
                dispatch(OsStr::new(alias), args),
                Dispatch::Init(_)
            ));
        }
        let Dispatch::Immediate(help) = dispatch(OsStr::new(alias), ["init", "--help"]) else {
            panic!("expected help")
        };
        assert!(help.stdout().contains("Run from the repository root"));
        assert!(help.stdout().contains("--private-dir defaults to"));
    }
}

#[test]
fn unsupported_default_reuse_refuses_before_working_directory_resolution() {
    for alias in ALIASES {
        let Dispatch::Init(request) = dispatch(
            OsStr::new(alias),
            [
                "init",
                "--principal",
                "fixture@chinwag.test",
                "--reuse-public",
                &"00".repeat(32),
            ],
        ) else {
            panic!("expected request")
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run_init(request, &mut out, &mut err), 1);
        let value: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["reason"], "init_reuse_not_supported");
        assert_eq!(value["material"], "not_started");
        assert_eq!(value["store_attempted"], false);
    }
}

#[test]
fn init_editor_selection_is_exact_and_parse_only_for_all_aliases() {
    for alias in ALIASES {
        for editor in ["claude-code", "cursor", "codex", "gemini"] {
            assert!(matches!(
                dispatch(
                    OsStr::new(alias),
                    [
                        "init",
                        "--principal",
                        "fixture@chinwag.test",
                        "--editor",
                        editor
                    ]
                ),
                Dispatch::Init(_)
            ));
            let mut explicit = arguments();
            explicit.push(format!("--editor={editor}").into());
            assert!(matches!(
                dispatch(OsStr::new(alias), explicit),
                Dispatch::Init(_)
            ));
        }
        for args in [
            vec![
                "init",
                "--principal",
                "fixture@chinwag.test",
                "--editor",
                "all",
            ],
            vec![
                "init",
                "--principal",
                "fixture@chinwag.test",
                "--editor",
                "cursor",
                "--editor",
                "codex",
            ],
            vec!["init", "--principal", "fixture@chinwag.test", "--editor"],
            vec![
                "init",
                "--principal",
                "fixture@chinwag.test",
                "--editor",
                "",
            ],
        ] {
            assert_eq!(
                dispatch(OsStr::new(alias), args),
                Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments))
            );
        }
    }
}

#[test]
fn bare_local_principal_requests_parse_for_all_aliases_without_filesystem_access() {
    for alias in ALIASES {
        for args in [
            vec!["init"],
            vec!["init", "--repo", REPO],
            vec!["init", "--editor", "claude-code"],
            vec!["init", "--editor=cursor"],
            vec!["init", "--editor", "codex"],
        ] {
            assert!(matches!(
                dispatch(OsStr::new(alias), args),
                Dispatch::Init(_)
            ));
        }
        let Dispatch::Immediate(help) = dispatch(OsStr::new(alias), ["init", "--help"]) else {
            panic!("expected help")
        };
        assert!(help.stdout().contains("repo-local user.email"));
        assert!(
            help.stdout()
                .contains("Global and included identity profiles are unavailable")
        );
    }
}

#[test]
fn automatic_principal_reuse_still_refuses_before_filesystem_or_query() {
    for alias in ALIASES {
        let Dispatch::Init(request) = dispatch(
            OsStr::new(alias),
            ["init", "--repo", REPO, "--reuse-public", &"00".repeat(32)],
        ) else {
            panic!("expected parsed request")
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run_init(request, &mut out, &mut err), 1);
        let value: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["reason"], "init_reuse_not_supported");
        assert_eq!(value["stage"], "preflight");
        assert!(value.get("principal_source").is_none());
    }
}
