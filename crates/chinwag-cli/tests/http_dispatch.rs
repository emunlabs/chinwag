use chinwag_cli::{Dispatch, Exit, Rejection, dispatch};
use std::ffi::OsStr;
#[test]
fn explicit_http_and_default_stdio_are_distinct_for_all_aliases() {
    for alias in [
        "chinwag",
        "git-chinwag",
        "git-emun",
        "gh-chinwag",
        "gh-emun",
    ] {
        assert!(matches!(
            dispatch(OsStr::new(alias), ["mcp-serve", "--repo", "/owned/repo"]),
            Dispatch::Serve(_)
        ));
        assert!(matches!(
            dispatch(
                OsStr::new(alias),
                ["mcp-serve", "--repo", "/owned/repo", "--transport", "stdio"]
            ),
            Dispatch::Serve(_)
        ));
        assert!(matches!(
            dispatch(
                OsStr::new(alias),
                ["mcp-serve", "--repo", "/owned/repo", "--transport", "http"]
            ),
            Dispatch::ServeHttp(_)
        ));
        assert!(matches!(
            dispatch(
                OsStr::new(alias),
                ["mcp-serve", "--transport", "http", "--repo", "/owned/repo"]
            ),
            Dispatch::ServeHttp(_)
        ));
    }
}
#[test]
fn invalid_transport_and_authority_flags_never_reach_startup() {
    for args in [
        vec!["mcp-serve", "--repo", "/owned/repo", "--transport", "sse"],
        vec!["mcp-serve", "--transport", "http"],
        vec!["mcp-serve", "--repo", "/owned/repo", "--repo", "/other"],
        vec![
            "mcp-serve",
            "--repo",
            "/owned/repo",
            "--listen",
            "0.0.0.0:80",
        ],
        vec!["mcp-serve", "--repo", "relative", "--transport", "http"],
        vec![
            "mcp-serve",
            "--repo",
            "/owned/../repo",
            "--transport",
            "http",
        ],
    ] {
        assert!(matches!(
            dispatch(OsStr::new("chinwag"), args),
            Dispatch::Immediate(Exit::Rejected(Rejection::InvalidArguments))
        ));
    }
}
