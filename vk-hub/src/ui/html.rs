//! HTML built so that nothing interpolated can be markup: [`Html::raw`] takes only
//! `&'static str` — a literal or constant of this crate's, since nothing built at run time is
//! `'static` short of leaking it — and everything else goes through [`Html::text`], which
//! escapes it for text content and quoted attribute values alike. [`Html::node`] is for a
//! string a host reported — the VMs `vk` lists, their logs: it is made
//! [`vk_hub_proto::display_safe`] again before it is escaped, whatever was done before.
//! [`Html::output`] is for what a command of the host's printed, shown whole in a `<pre>`.
//!
//! A host's strings go only in text content or quoted plain attributes (`title`, `value`),
//! never in an attribute htmx interprets (`hx-*`, `sse-*`). Those and an `href` are the hub's
//! own, built from constants and from IDs the router has checked are hex.

use std::fmt::Display;

/// An HTML fragment under construction.
#[derive(Default)]
pub struct Html(String);

impl Html {
    pub fn new() -> Self {
        Html(String::new())
    }

    /// Markup, verbatim: a literal or constant, never a value from outside.
    pub fn raw(&mut self, markup: &'static str) -> &mut Self {
        self.0.push_str(markup);
        self
    }

    /// `value`'s text, escaped.
    pub fn text(&mut self, value: impl Display) -> &mut Self {
        escape_into(&mut self.0, &value.to_string());
        self
    }

    /// A string a host reported: made display-safe, then escaped.
    pub fn node(&mut self, value: &str) -> &mut Self {
        escape_into(&mut self.0, &vk_hub_proto::display_safe(value));
        self
    }

    /// Make host command output [`terminal_safe`] and escape it for a `<pre>`.
    /// The captured output is already bounded, so no further length limit is applied.
    pub fn output(&mut self, value: &str) -> &mut Self {
        escape_into(&mut self.0, &terminal_safe(value));
        self
    }

    /// Another fragment, already built by these rules.
    pub fn html(&mut self, other: &Html) -> &mut Self {
        self.0.push_str(&other.0);
        self
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// Escape `s` for HTML text and for a single- or double-quoted attribute value.
fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

/// `s`, a terminal's output, as text: its escape sequences dropped whole — CSI (colours,
/// cursor moves), the OSC, DCS, SOS, PM and APC strings (titles, links) up to their
/// terminator, and the shorter ones — rather than the escape alone, which leaves `[0;32m`
/// behind. Lines and tabs are kept; other controls, and the [`vk_hub_proto::invisible`]
/// characters, are dropped.
fn terminal_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.peek() {
                Some('[') => {
                    chars.next();
                    skip_csi(&mut chars);
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    chars.next();
                    skip_string(&mut chars);
                }
                _ => skip_escape(&mut chars),
            },
            '\u{9b}' => skip_csi(&mut chars),
            '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => skip_string(&mut chars),
            '\n' | '\t' => out.push(c),
            c if c.is_control() || vk_hub_proto::invisible(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Skip a CSI sequence's parameters and intermediates, then its final character. A character
/// that can be none of them ends it unread.
fn skip_csi(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&c) = chars.peek() {
        if ('\u{20}'..='\u{3f}').contains(&c) {
            chars.next();
            continue;
        }
        if ('\u{40}'..='\u{7e}').contains(&c) {
            chars.next();
        }
        return;
    }
}

/// Skip the rest of a short escape sequence: its intermediates, then its final character. A
/// character that can be neither ends it unread.
fn skip_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&c) = chars.peek() {
        if ('\u{20}'..='\u{2f}').contains(&c) {
            chars.next();
            continue;
        }
        if ('\u{30}'..='\u{7e}').contains(&c) {
            chars.next();
        }
        return;
    }
}

/// Skip a control string up to its terminator: BEL, ST (`ESC \`), or the end — or up to a
/// newline, which no title or link holds, left unread so that a string never terminated does
/// not take the rest of the output with it.
fn skip_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.next_if(|&c| c != '\n') {
        match c {
            '\u{7}' | '\u{9c}' => return,
            '\u{1b}' => {
                chars.next_if_eq(&'\\');
                return;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolated_text_cannot_be_markup() {
        let mut h = Html::new();
        h.raw("<td title=\"")
            .text("\"><script>x</script>")
            .raw("\">")
            .node("<img src=x onerror=alert(1)>\u{202e}\u{1b}[2J'")
            .raw("</td>");
        assert_eq!(
            h.into_string(),
            "<td title=\"&quot;&gt;&lt;script&gt;x&lt;/script&gt;\">\
             &lt;img src=x onerror=alert(1)&gt;[2J&#39;</td>"
        );
    }

    #[test]
    fn output_drops_terminal_sequences_whole_and_keeps_tabs() {
        let long = "y".repeat(1000);
        let mut h = Html::new();
        h.output(&format!(
            "\u{1b}[0;32mok\u{1b}[0m\tdone\r\n\u{1b}]0;title\u{7}\u{1b}]8;;http://x\u{1b}\\link\
             \u{1b}]8;;\u{1b}\\ \u{1b}(B\u{1b}7\u{9b}2K<b>\u{202e}\u{8}\n{long}"
        ));
        assert_eq!(h.into_string(), format!("ok\tdone\nlink &lt;b&gt;\n{long}"));
    }

    /// An escape sequence torn off by a newline, or a control character, ends there: the line
    /// after it is kept.
    #[test]
    fn output_keeps_the_line_after_a_torn_escape() {
        let mut h = Html::new();
        h.output("a\u{1b}\nb\u{1b}(\nc\u{1b}[1\nd\u{1b}]0;title\ne\u{1b}\u{7}f");
        assert_eq!(h.into_string(), "a\nb\nc\nd\nef");
    }
}
