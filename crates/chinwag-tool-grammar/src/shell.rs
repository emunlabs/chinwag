// SPDX-License-Identifier: Apache-2.0

use crate::types::{MAX_ARGV_TOKENS, MAX_COMMAND_BYTES};

/// A single simple command segment extracted from a POSIX shell command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellCommandSegment {
    /// Unquoted words of the command (`argv`).
    pub words: Vec<String>,
    /// Per-word flag indicating whether unquoted/double-quoted `$VAR` parameter expansion occurred.
    pub word_has_var_expansion: Vec<bool>,
    /// Per-word flag indicating whether unquoted shell globbing (`*`, `?`, `[...]`) occurred.
    pub word_has_unquoted_glob: Vec<bool>,
    /// Per-word flag indicating whether unquoted brace expansion (`{a,b}`), standalone `{`, or extglob `(...)` occurred.
    pub word_has_unquoted_brace: Vec<bool>,
    /// Output redirection targets (`>`, `>>`, `>|`, `<>`, `&>`, `&>>`, `>&file`, `n>`), excluding `/dev/null` and fd duplications (`2>&1`, `>&-`).
    pub output_redirections: Vec<String>,
    /// Input redirection targets (`< file`, `n< file`), excluding `/dev/null` and fd duplications (`<&0`, `<&-`).
    pub input_redirections: Vec<String>,
    /// True if any redirection target used `$VAR` / `${VAR}` parameter expansion.
    pub redir_has_var_expansion: bool,
    /// True if any redirection target used unquoted glob (`*`, `?`, `[`) or brace (`{`) expansion.
    pub redir_has_unquoted_glob_or_brace: bool,
    /// Inner command strings extracted from unescaped `$(...)` or `` `...` `` command substitutions.
    pub command_substitutions: Vec<String>,
    /// True if process substitution `<(...)` or `>(...)` or subshell `(...)` group was used.
    pub has_subshell_or_proc_subst: bool,
    /// True if piped (`|`) into the next segment.
    pub piped_to_next: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingRedir {
    None,
    OutputFile,
    DupOrOutputFile,
    InputFile,
    InputDup,
}

struct WordState {
    cur_word: String,
    in_word: bool,
    cur_word_var: bool,
    cur_word_glob: bool,
    cur_word_brace: bool,
    cur_word_quoted: bool,
    cur_word_leading_unquoted_eq: bool,
    pending_redir: PendingRedir,
    total_tokens: usize,
}

/// Complete lexical decomposition of a shell command string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexedShellLine {
    pub segments: Vec<ShellCommandSegment>,
    pub fail_closed_error: Option<String>,
}

/// Zero-backtracking single-pass POSIX shell lexer (`<5 µs` typical).
///
/// Handles:
/// - Single quotes (`'...'` — strictly literal, zero `$()` or `` ` `` expansion),
/// - Double quotes (`"..."` — backslash escapes for `"`, `\`, `$`, `` ` ``, plus `$(...)` and `` `...` `` extraction),
/// - ANSI-C `$'...'` quotes,
/// - Unquoted backslash escapes, `#` comments,
/// - Compound command separators (`&&`, `||`, `;`, `|`, `&`, `\n`),
/// - Output redirections (`>`, `>>`, `>|`, `&>`, `1>`, `2>`),
/// - Rejects embedded NUL bytes (`\0`), unclosed quotes, and inputs exceeding [`MAX_COMMAND_BYTES`] / [`MAX_ARGV_TOKENS`].
#[must_use]
pub fn lex_shell_command(input: &str) -> LexedShellLine {
    if input.len() > MAX_COMMAND_BYTES {
        return LexedShellLine {
            segments: Vec::new(),
            fail_closed_error: Some(format!(
                "command length {} exceeds MAX_COMMAND_BYTES ({MAX_COMMAND_BYTES})",
                input.len()
            )),
        };
    }
    if input.as_bytes().contains(&0) {
        return LexedShellLine {
            segments: Vec::new(),
            fail_closed_error: Some("embedded NUL byte in shell command".to_string()),
        };
    }

    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    let mut segments: Vec<ShellCommandSegment> = Vec::new();
    let mut cur_seg = empty_segment();
    let mut ws = WordState {
        cur_word: String::new(),
        in_word: false,
        cur_word_var: false,
        cur_word_glob: false,
        cur_word_brace: false,
        cur_word_quoted: false,
        cur_word_leading_unquoted_eq: false,
        pending_redir: PendingRedir::None,
        total_tokens: 0,
    };

    while i < len {
        let b = bytes[i];

        // Whitespace outside quotes
        if matches!(b, b' ' | b'\t' | b'\r') {
            if ws.in_word && !finish_word(&mut cur_seg, &mut ws) {
                return token_cap_exceeded();
            }
            i += 1;
            continue;
        }

        // Comments at word boundary
        if b == b'#' && !ws.in_word {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Newline or `;` separates commands
        if b == b'\n' || b == b';' {
            if ws.pending_redir != PendingRedir::None && !ws.in_word {
                return syntax_fail("dangling redirection before command separator");
            }
            if ws.in_word && !finish_word(&mut cur_seg, &mut ws) {
                return token_cap_exceeded();
            }
            flush_segment(&mut segments, &mut cur_seg, false);
            i += 1;
            continue;
        }

        // Operators `&`, `&&`, `&>`, `&>>`
        if b == b'&' {
            if i + 1 < len && bytes[i + 1] == b'>' {
                if ws.pending_redir != PendingRedir::None && !ws.in_word {
                    return syntax_fail("dangling redirection before &>");
                }
                if ws.in_word && !finish_word(&mut cur_seg, &mut ws) {
                    return token_cap_exceeded();
                }
                ws.pending_redir = PendingRedir::OutputFile;
                i += 2;
                if i < len && bytes[i] == b'>' {
                    i += 1;
                }
                continue;
            }
            if ws.pending_redir != PendingRedir::None && !ws.in_word {
                return syntax_fail("dangling redirection before &");
            }
            if ws.in_word && !finish_word(&mut cur_seg, &mut ws) {
                return token_cap_exceeded();
            }
            if i + 1 < len && bytes[i + 1] == b'&' {
                flush_segment(&mut segments, &mut cur_seg, false);
                i += 2;
            } else {
                flush_segment(&mut segments, &mut cur_seg, false);
                i += 1;
            }
            continue;
        }

        // Operators `|` and `||`
        if b == b'|' {
            if ws.pending_redir != PendingRedir::None && !ws.in_word {
                return syntax_fail("dangling redirection before |");
            }
            if ws.in_word && !finish_word(&mut cur_seg, &mut ws) {
                return token_cap_exceeded();
            }
            if i + 1 < len && bytes[i + 1] == b'|' {
                flush_segment(&mut segments, &mut cur_seg, false);
                i += 2;
            } else {
                flush_segment(&mut segments, &mut cur_seg, true);
                i += 1;
            }
            continue;
        }

        // Process substitution `<(...)`, `>(...)`, and zsh `=(...)` (including empty-quote prefix `''=(...)`)
        if ((b == b'<' || b == b'>') || (b == b'=' && ws.cur_word.is_empty()))
            && i + 1 < len
            && bytes[i + 1] == b'('
        {
            cur_seg.has_subshell_or_proc_subst = true;
            match extract_balanced_parens(input, i + 1) {
                Ok((inner, next_idx)) => {
                    cur_seg.command_substitutions.push(inner);
                    ws.in_word = true;
                    if b == b'=' {
                        ws.cur_word_glob = true;
                    }
                    ws.cur_word.push_str("__PROC_SUBST__");
                    i = next_idx;
                    continue;
                }
                Err(msg) => return syntax_fail(&msg),
            }
        }

        // Numeric fd prefix (`2>/dev/null`, `3>.env`, `10>.env`, `0<>.env`, `2>&1`, `0<&-`)
        if b.is_ascii_digit() && !ws.in_word {
            let mut d_end = i + 1;
            while d_end < len && bytes[d_end].is_ascii_digit() {
                d_end += 1;
            }
            if d_end < len && (bytes[d_end] == b'>' || bytes[d_end] == b'<') {
                i = d_end;
                continue;
            }
        }

        if b == b'>' {
            if ws.pending_redir != PendingRedir::None && !ws.in_word {
                return syntax_fail("dangling redirection before >");
            }
            if ws.in_word && !finish_word(&mut cur_seg, &mut ws) {
                return token_cap_exceeded();
            }
            i += 1;
            let mut saw_append_or_clobber = false;
            if i < len && (bytes[i] == b'>' || bytes[i] == b'|') {
                saw_append_or_clobber = true;
                i += 1;
            }
            if i < len && bytes[i] == b'&' {
                i += 1;
                ws.pending_redir = if saw_append_or_clobber {
                    PendingRedir::OutputFile
                } else {
                    PendingRedir::DupOrOutputFile
                };
                continue;
            }
            ws.pending_redir = PendingRedir::OutputFile;
            continue;
        }

        if b == b'<' {
            if ws.pending_redir != PendingRedir::None && !ws.in_word {
                return syntax_fail("dangling redirection before <");
            }
            if ws.in_word && !finish_word(&mut cur_seg, &mut ws) {
                return token_cap_exceeded();
            }
            if i + 1 < len && bytes[i + 1] == b'<' {
                return syntax_fail("heredoc or here-string requires shell evaluation");
            }
            if i + 1 < len && bytes[i + 1] == b'>' {
                i += 2;
                ws.pending_redir = PendingRedir::OutputFile;
                continue;
            }
            if i + 1 < len && bytes[i + 1] == b'&' {
                i += 2;
                ws.pending_redir = PendingRedir::InputDup;
                continue;
            }
            i += 1;
            ws.pending_redir = PendingRedir::InputFile;
            continue;
        }

        // Bare subshell `(...)`
        if b == b'(' && !ws.in_word {
            cur_seg.has_subshell_or_proc_subst = true;
            match extract_balanced_parens(input, i) {
                Ok((inner, next_idx)) => {
                    cur_seg.command_substitutions.push(inner);
                    i = next_idx;
                    continue;
                }
                Err(msg) => return syntax_fail(&msg),
            }
        }

        // Single-quoted literal `'...'` (POSIX: zero escapes, zero expansion)
        if b == b'\'' {
            ws.in_word = true;
            ws.cur_word_quoted = true;
            i += 1;
            let start = i;
            while i < len && bytes[i] != b'\'' {
                i += 1;
            }
            if i >= len {
                return syntax_fail("unclosed single quote in shell command");
            }
            ws.cur_word.push_str(&input[start..i]);
            i += 1;
            continue;
        }

        // ANSI-C `$'...'` quote (decodes `\xHH`, octal `\NNN`, `\uHHHH`, `\UHHHHHHHH`, `\cX`, standard escapes)
        if b == b'$' && i + 1 < len && bytes[i + 1] == b'\'' {
            ws.in_word = true;
            ws.cur_word_quoted = true;
            i += 2;
            let mut raw_buf: Vec<u8> = Vec::new();
            while i < len && bytes[i] != b'\'' {
                if bytes[i] == b'\\' {
                    i += 1;
                    if i >= len {
                        return syntax_fail("unclosed ANSI-C escape in $'...'");
                    }
                    match bytes[i] {
                        b'a' => {
                            raw_buf.push(0x07);
                            i += 1;
                        }
                        b'b' => {
                            raw_buf.push(0x08);
                            i += 1;
                        }
                        b'e' | b'E' => {
                            raw_buf.push(0x1b);
                            i += 1;
                        }
                        b'f' => {
                            raw_buf.push(0x0c);
                            i += 1;
                        }
                        b'n' => {
                            raw_buf.push(b'\n');
                            i += 1;
                        }
                        b'r' => {
                            raw_buf.push(b'\r');
                            i += 1;
                        }
                        b't' => {
                            raw_buf.push(b'\t');
                            i += 1;
                        }
                        b'v' => {
                            raw_buf.push(0x0b);
                            i += 1;
                        }
                        b'\\' | b'\'' | b'"' | b'?' => {
                            raw_buf.push(bytes[i]);
                            i += 1;
                        }
                        b'x' => {
                            i += 1;
                            let hex_start = i;
                            while i < len && (i - hex_start) < 2 && bytes[i].is_ascii_hexdigit() {
                                i += 1;
                            }
                            if i == hex_start {
                                return syntax_fail("invalid empty \\x hex escape in $'...'");
                            }
                            let val = u8::from_str_radix(&input[hex_start..i], 16).unwrap_or(0);
                            if val == 0 {
                                return syntax_fail("escaped hex NUL \\x00 inside $'...'");
                            }
                            raw_buf.push(val);
                        }
                        b'0'..=b'7' => {
                            let oct_start = i;
                            while i < len && (i - oct_start) < 3 && matches!(bytes[i], b'0'..=b'7')
                            {
                                i += 1;
                            }
                            let val = u16::from_str_radix(&input[oct_start..i], 8).unwrap_or(0);
                            let byte_val = (val & 0xff) as u8;
                            if byte_val == 0 {
                                return syntax_fail("escaped octal NUL \\0 inside $'...'");
                            }
                            raw_buf.push(byte_val);
                        }
                        b'u' | b'U' => {
                            let max_digits = if bytes[i] == b'u' { 4 } else { 8 };
                            i += 1;
                            let hex_start = i;
                            while i < len
                                && (i - hex_start) < max_digits
                                && bytes[i].is_ascii_hexdigit()
                            {
                                i += 1;
                            }
                            if i == hex_start {
                                return syntax_fail("invalid unicode escape in $'...'");
                            }
                            let cp = u32::from_str_radix(&input[hex_start..i], 16).unwrap_or(0);
                            if cp == 0 {
                                return syntax_fail("escaped unicode NUL \\u0000 inside $'...'");
                            }
                            let Some(ch) = char::from_u32(cp) else {
                                return syntax_fail("invalid unicode scalar value in $'...'");
                            };
                            let mut tmp = [0u8; 4];
                            raw_buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                        }
                        b'c' => {
                            i += 1;
                            if i >= len {
                                return syntax_fail("incomplete \\c control escape in $'...'");
                            }
                            let ctrl = bytes[i] & 0x1f;
                            if ctrl == 0 {
                                return syntax_fail("escaped control NUL \\c@ inside $'...'");
                            }
                            raw_buf.push(ctrl);
                            i += 1;
                        }
                        _ => {
                            if let Some(ch) = input[i..].chars().next() {
                                let mut tmp = [0u8; 4];
                                raw_buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                                i += ch.len_utf8();
                            }
                        }
                    }
                } else {
                    raw_buf.push(bytes[i]);
                    i += 1;
                }
            }
            if i >= len {
                return syntax_fail("unclosed ANSI-C $'...' quote");
            }
            let Ok(decoded) = String::from_utf8(raw_buf) else {
                return syntax_fail("non-UTF8 byte sequence inside ANSI-C $'...' quote");
            };
            ws.cur_word.push_str(&decoded);
            i += 1;
            continue;
        }

        // Double-quoted string `"..."` and bash/ksh/zsh locale-translated `$"..."`
        if b == b'"' || (b == b'$' && i + 1 < len && bytes[i + 1] == b'"') {
            ws.in_word = true;
            ws.cur_word_quoted = true;
            i += if b == b'$' { 2 } else { 1 };
            while i < len && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                    if i >= len {
                        return syntax_fail("trailing backslash inside double quotes");
                    }
                    let esc = bytes[i];
                    if matches!(esc, b'"' | b'\\' | b'$' | b'`' | b'\n') {
                        if esc != b'\n' {
                            ws.cur_word.push(esc as char);
                        }
                        i += 1;
                    } else {
                        ws.cur_word.push('\\');
                        if let Some(ch) = input[i..].chars().next() {
                            ws.cur_word.push(ch);
                            i += ch.len_utf8();
                        }
                    }
                    continue;
                }
                if bytes[i] == b'$' && i + 1 < len && bytes[i + 1] == b'(' {
                    match extract_balanced_parens(input, i + 1) {
                        Ok((inner, next_idx)) => {
                            cur_seg.command_substitutions.push(inner);
                            ws.cur_word_var = true;
                            ws.cur_word.push_str("__CMD_SUBST__");
                            i = next_idx;
                            continue;
                        }
                        Err(msg) => return syntax_fail(&msg),
                    }
                }
                if bytes[i] == b'`' {
                    match extract_backtick(input, i) {
                        Ok((inner, next_idx)) => {
                            cur_seg.command_substitutions.push(inner);
                            ws.cur_word_var = true;
                            ws.cur_word.push_str("__CMD_SUBST__");
                            i = next_idx;
                            continue;
                        }
                        Err(msg) => return syntax_fail(&msg),
                    }
                }
                if bytes[i] == b'$'
                    && i + 1 < len
                    && (bytes[i + 1] == b'{'
                        || bytes[i + 1].is_ascii_alphabetic()
                        || bytes[i + 1] == b'_'
                        || bytes[i + 1].is_ascii_digit()
                        || matches!(bytes[i + 1], b'@' | b'*' | b'?' | b'$' | b'!' | b'#' | b'-'))
                {
                    ws.cur_word_var = true;
                }
                if let Some(ch) = input[i..].chars().next() {
                    ws.cur_word.push(ch);
                    i += ch.len_utf8();
                }
            }
            if i >= len {
                return syntax_fail("unclosed double quote in shell command");
            }
            i += 1;
            continue;
        }

        // Unquoted backslash escape
        if b == b'\\' {
            i += 1;
            if i >= len {
                return syntax_fail("trailing unquoted backslash in shell command");
            }
            if bytes[i] == b'\n' {
                i += 1;
                continue;
            }
            ws.in_word = true;
            ws.cur_word_quoted = true;
            if let Some(ch) = input[i..].chars().next() {
                ws.cur_word.push(ch);
                i += ch.len_utf8();
            }
            continue;
        }

        // Unquoted command substitution `$(...)`
        if b == b'$' && i + 1 < len && bytes[i + 1] == b'(' {
            ws.in_word = true;
            match extract_balanced_parens(input, i + 1) {
                Ok((inner, next_idx)) => {
                    cur_seg.command_substitutions.push(inner);
                    ws.cur_word_var = true;
                    ws.cur_word.push_str("__CMD_SUBST__");
                    i = next_idx;
                    continue;
                }
                Err(msg) => return syntax_fail(&msg),
            }
        }

        // Unquoted backtick substitution `` `...` ``
        if b == b'`' {
            ws.in_word = true;
            match extract_backtick(input, i) {
                Ok((inner, next_idx)) => {
                    cur_seg.command_substitutions.push(inner);
                    ws.cur_word_var = true;
                    ws.cur_word.push_str("__CMD_SUBST__");
                    i = next_idx;
                    continue;
                }
                Err(msg) => return syntax_fail(&msg),
            }
        }

        // Unquoted `$VAR` / `${VAR}` parameter expansion
        if b == b'$'
            && i + 1 < len
            && (bytes[i + 1] == b'{'
                || bytes[i + 1].is_ascii_alphabetic()
                || bytes[i + 1] == b'_'
                || bytes[i + 1].is_ascii_digit()
                || matches!(bytes[i + 1], b'@' | b'*' | b'?' | b'$' | b'!' | b'#' | b'-'))
        {
            ws.cur_word_var = true;
        }

        // Empty `{}` placeholder (`xargs -I{}`, `find -exec ... {}`) is literal across POSIX/bash/zsh
        if b == b'{' && i + 1 < len && bytes[i + 1] == b'}' {
            ws.in_word = true;
            ws.cur_word.push_str("{}");
            i += 2;
            continue;
        }

        // Unquoted shell globbing (`*`, `?`, `[...]`), zsh word-initial unquoted `=` (`=cmd`, `''=cmd`, `=""cmd`),
        // or brace/extglob expansion (`{a,b}`, `@(x)`)
        if matches!(b, b'*' | b'?' | b'[') {
            ws.cur_word_glob = true;
        } else if b == b'=' && ws.cur_word.is_empty() {
            ws.cur_word_leading_unquoted_eq = true;
        } else if matches!(b, b'{' | b'(' | b')') {
            ws.cur_word_brace = true;
        }

        ws.in_word = true;
        if let Some(ch) = input[i..].chars().next() {
            ws.cur_word.push(ch);
            i += ch.len_utf8();
        }
    }

    if ws.pending_redir != PendingRedir::None && !ws.in_word {
        return syntax_fail("dangling redirection at end of command");
    }
    if ws.in_word && !finish_word(&mut cur_seg, &mut ws) {
        return token_cap_exceeded();
    }
    flush_segment(&mut segments, &mut cur_seg, false);

    LexedShellLine {
        segments,
        fail_closed_error: None,
    }
}

fn empty_segment() -> ShellCommandSegment {
    ShellCommandSegment {
        words: Vec::new(),
        word_has_var_expansion: Vec::new(),
        word_has_unquoted_glob: Vec::new(),
        word_has_unquoted_brace: Vec::new(),
        output_redirections: Vec::new(),
        input_redirections: Vec::new(),
        redir_has_var_expansion: false,
        redir_has_unquoted_glob_or_brace: false,
        command_substitutions: Vec::new(),
        has_subshell_or_proc_subst: false,
        piped_to_next: false,
    }
}

fn is_valid_fd_dup_target(word: &str) -> bool {
    if word == "-" {
        return true;
    }
    let digits = word.strip_suffix('-').unwrap_or(word);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn finish_word(seg: &mut ShellCommandSegment, ws: &mut WordState) -> bool {
    ws.total_tokens += 1;
    if ws.total_tokens > MAX_ARGV_TOKENS {
        return false;
    }
    let word = std::mem::take(&mut ws.cur_word);
    let has_var = ws.cur_word_var;
    let leading_unquoted_eq = ws.cur_word_leading_unquoted_eq;
    let zsh_eq_expand = leading_unquoted_eq && word.len() > 1 && word != "==";
    let has_glob = ws.cur_word_glob || zsh_eq_expand;
    let has_brace = ws.cur_word_brace;
    let was_quoted = ws.cur_word_quoted;
    let mode = ws.pending_redir;
    ws.in_word = false;
    ws.cur_word_var = false;
    ws.cur_word_glob = false;
    ws.cur_word_brace = false;
    ws.cur_word_quoted = false;
    ws.cur_word_leading_unquoted_eq = false;
    ws.pending_redir = PendingRedir::None;

    let redir_glob_or_brace = has_glob || has_brace;

    match mode {
        PendingRedir::None => {
            seg.words.push(word);
            seg.word_has_var_expansion.push(has_var);
            seg.word_has_unquoted_glob.push(has_glob);
            seg.word_has_unquoted_brace.push(has_brace);
        }
        PendingRedir::OutputFile => {
            if redir_glob_or_brace {
                seg.redir_has_unquoted_glob_or_brace = true;
            }
            if has_var {
                seg.redir_has_var_expansion = true;
                seg.output_redirections.push(word);
            } else if redir_glob_or_brace || word != "/dev/null" {
                seg.output_redirections.push(word);
            }
        }
        PendingRedir::DupOrOutputFile => {
            if !has_var && !redir_glob_or_brace && !was_quoted && is_valid_fd_dup_target(&word) {
                // Benign POSIX fd duplication/close (`2>&1`, `>&2`, `2>&-`, `1>&2-`)
            } else {
                if redir_glob_or_brace {
                    seg.redir_has_unquoted_glob_or_brace = true;
                }
                if has_var {
                    seg.redir_has_var_expansion = true;
                    seg.output_redirections.push(word);
                } else if redir_glob_or_brace || word != "/dev/null" {
                    seg.output_redirections.push(word);
                }
            }
        }
        PendingRedir::InputFile => {
            if redir_glob_or_brace {
                seg.redir_has_unquoted_glob_or_brace = true;
            }
            if has_var {
                seg.redir_has_var_expansion = true;
                seg.input_redirections.push(word);
            } else if redir_glob_or_brace || word != "/dev/null" {
                seg.input_redirections.push(word);
            }
        }
        PendingRedir::InputDup => {
            if !has_var && !redir_glob_or_brace && !was_quoted && is_valid_fd_dup_target(&word) {
                // Benign POSIX input fd duplication/close (`<&0`, `0<&-`)
            } else {
                if redir_glob_or_brace {
                    seg.redir_has_unquoted_glob_or_brace = true;
                }
                if has_var {
                    seg.redir_has_var_expansion = true;
                    seg.input_redirections.push(word);
                } else if redir_glob_or_brace || word != "/dev/null" {
                    seg.input_redirections.push(word);
                }
            }
        }
    }
    true
}

fn flush_segment(
    segments: &mut Vec<ShellCommandSegment>,
    cur_seg: &mut ShellCommandSegment,
    piped: bool,
) {
    if !cur_seg.words.is_empty()
        || !cur_seg.output_redirections.is_empty()
        || !cur_seg.input_redirections.is_empty()
        || cur_seg.redir_has_var_expansion
        || cur_seg.redir_has_unquoted_glob_or_brace
        || !cur_seg.command_substitutions.is_empty()
        || cur_seg.has_subshell_or_proc_subst
    {
        cur_seg.piped_to_next = piped;
        segments.push(std::mem::replace(cur_seg, empty_segment()));
    }
}

fn extract_balanced_parens(input: &str, open_paren_idx: usize) -> Result<(String, usize), String> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut depth = 0usize;
    let mut i = open_paren_idx;
    let mut in_single = false;
    let mut in_ansi_single = false;
    let mut in_double = false;

    while i < len {
        let b = bytes[i];
        if in_ansi_single {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_ansi_single = false;
            }
            i += 1;
            continue;
        }
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if b == b'$' && i + 1 < len && bytes[i + 1] == b'\'' {
            in_ansi_single = true;
            i += 2;
            continue;
        }
        match b {
            b'\\' => {
                i += 2;
                continue;
            }
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let inner = input[open_paren_idx + 1..i].to_string();
                    return Ok((inner, i + 1));
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err("unclosed '(' in subshell or $(...) command substitution".to_string())
}

fn extract_backtick(input: &str, open_tick_idx: usize) -> Result<(String, usize), String> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = open_tick_idx + 1;
    let mut buf = String::new();
    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            let next = bytes[i + 1];
            if matches!(next, b'`' | b'\\' | b'$') {
                buf.push(next as char);
                i += 2;
                continue;
            }
        }
        if bytes[i] == b'`' {
            return Ok((buf, i + 1));
        }
        if let Some(ch) = input[i..].chars().next() {
            buf.push(ch);
            i += ch.len_utf8();
        }
    }
    Err("unclosed backtick command substitution".to_string())
}

fn syntax_fail(msg: &str) -> LexedShellLine {
    LexedShellLine {
        segments: Vec::new(),
        fail_closed_error: Some(msg.to_string()),
    }
}

fn token_cap_exceeded() -> LexedShellLine {
    LexedShellLine {
        segments: Vec::new(),
        fail_closed_error: Some(format!(
            "token count exceeds MAX_ARGV_TOKENS ({MAX_ARGV_TOKENS})"
        )),
    }
}
