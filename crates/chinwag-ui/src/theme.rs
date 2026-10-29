// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! Mission Control themes. Token values come from the existing `styles.css` in a later milestone.

use std::{fmt, str::FromStr};

/// The three shipped Mission Control themes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Theme {
    #[default]
    Midnight,
    Daylight,
    Graphite,
}

impl Theme {
    /// All themes in display order.
    pub const ALL: [Theme; 3] = [Theme::Midnight, Theme::Daylight, Theme::Graphite];

    /// Value used for the `data-theme` attribute on the root element.
    pub const fn slug(self) -> &'static str {
        match self {
            Theme::Midnight => "midnight",
            Theme::Daylight => "daylight",
            Theme::Graphite => "graphite",
        }
    }
}

impl fmt::Display for Theme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Error for an unknown theme name.
#[derive(Debug, Eq, PartialEq)]
pub struct UnknownTheme;

impl fmt::Display for UnknownTheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown theme; expected one of: midnight, daylight, graphite")
    }
}

impl std::error::Error for UnknownTheme {}

impl FromStr for Theme {
    type Err = UnknownTheme;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Theme::ALL
            .into_iter()
            .find(|t| t.slug().eq_ignore_ascii_case(s.trim()))
            .ok_or(UnknownTheme)
    }
}

/// Inline CSS keeps the plain shell usable with Cargo and dx alike.
pub const STYLES: &str = r#"
:root { color-scheme: dark; --bg: #16191e; --panel: #20252c; --text: #eef0f3; --muted: #abb4c0; --line: #424c58; }
:root[data-theme="daylight"] { color-scheme: light; --bg: #fff; --panel: #f2f4f6; --text: #18202b; --muted: #4e5968; --line: #abb4c0; }
:root[data-theme="graphite"] { --bg: #252525; --panel: #303030; --text: #fafafa; --muted: #bdbdbd; --line: #666; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; }
a { color: inherit; }
button, textarea { font: inherit; }
button { padding: .5rem 1rem; cursor: pointer; }
button:disabled { cursor: default; opacity: .6; }
.topbar { padding: 1rem 1.5rem; border-bottom: 1px solid var(--line); }
h1 { font-size: 1.25rem; margin: 0; }
h2 { font-size: 1.1rem; }
.workspace { display: grid; grid-template-columns: 15rem minmax(0, 1fr); min-height: calc(100vh - 4rem); }
aside { background: var(--panel); padding: 1rem; border-right: 1px solid var(--line); }
main { padding: 1.5rem; min-width: 0; }
.channel-list { list-style: none; padding: 0; }
.channel-list a { display: block; padding: .65rem; overflow-wrap: anywhere; }
.channel-list a[aria-current="page"] { background: var(--bg); font-weight: bold; }
.messages { list-style: none; padding: 0; }
.message { padding: 1rem 0; border-bottom: 1px solid var(--line); }
.message time { color: var(--muted); margin-left: .75rem; font-size: .85rem; }
.message p { white-space: pre-wrap; overflow-wrap: anywhere; }
.composer { display: grid; gap: .75rem; margin-top: 1.5rem; }
textarea { width: 100%; min-height: 6rem; padding: .75rem; background: var(--panel); color: var(--text); border: 1px solid var(--line); }
.error { color: #ffb3b3; }
:root[data-theme="daylight"] .error { color: #a00000; }
@media (max-width: 600px) { .workspace { grid-template-columns: 1fr; } aside { border-right: 0; border-bottom: 1px solid var(--line); } main { padding: 1rem; } }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_midnight() {
        assert_eq!(Theme::default(), Theme::Midnight);
    }

    #[test]
    fn slug_round_trips() {
        for theme in Theme::ALL {
            assert_eq!(theme.slug().parse::<Theme>(), Ok(theme));
        }
    }

    #[test]
    fn parse_is_case_and_space_insensitive() {
        assert_eq!(" Graphite ".parse::<Theme>(), Ok(Theme::Graphite));
    }

    #[test]
    fn unknown_theme_is_rejected() {
        assert_eq!("solarized".parse::<Theme>(), Err(UnknownTheme));
    }

    #[test]
    fn unknown_theme_displays_and_is_an_error() {
        assert_eq!(
            UnknownTheme.to_string(),
            "unknown theme; expected one of: midnight, daylight, graphite"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(UnknownTheme);
        assert!(boxed.source().is_none());
        // Usable with `?` in a function returning a boxed error.
        fn parse(s: &str) -> Result<Theme, Box<dyn std::error::Error>> {
            Ok(s.parse::<Theme>()?)
        }
        assert_eq!(parse("daylight").unwrap(), Theme::Daylight);
        assert!(parse("nope").is_err());
    }

    #[test]
    fn display_matches_slug() {
        for theme in Theme::ALL {
            assert_eq!(theme.to_string(), theme.slug());
        }
    }
}
