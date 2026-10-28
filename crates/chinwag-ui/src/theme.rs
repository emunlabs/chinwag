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

impl FromStr for Theme {
    type Err = UnknownTheme;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Theme::ALL
            .into_iter()
            .find(|t| t.slug().eq_ignore_ascii_case(s.trim()))
            .ok_or(UnknownTheme)
    }
}

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
}
