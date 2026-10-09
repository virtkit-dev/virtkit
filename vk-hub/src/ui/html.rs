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
//! own, built from constants, from IDs the router has checked are hex, and from dev
//! environment names checked to be `[A-Za-z0-9._-]` not starting with `.` or `-`, with the
//! Jobs page's filter values percent-encoded down to unreserved characters — but for a
//! CI job's page on its GitLab, [`Html::external_link`], which goes into an `href` only when
//! it is a plain http(s) URL ([`vk_hub_proto::is_web_link`]), and opens in a tab of its own
//! that learns nothing of the hub's page.

use std::fmt::Display;

/// An HTML fragment under construction.
#[derive(Clone, Default)]
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

    /// Show the host's `label` as a link if `url` passes [`vk_hub_proto::is_web_link`]
    /// (plain HTTP(S)), or as text otherwise. Open links in a new tab with no opener or
    /// referrer. The node- or producer-supplied URL is trusted for nothing else.
    pub fn external_link(&mut self, url: Option<&str>, label: &str) -> &mut Self {
        match url.filter(|u| vk_hub_proto::is_web_link(u)) {
            Some(url) => self
                .raw("<a href=\"")
                .text(url)
                .raw("\" target=\"_blank\" rel=\"noopener noreferrer\">")
                .node(label)
                .raw("</a>"),
            None => self.node(label),
        }
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
pub fn terminal_safe(s: &str) -> String {
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

/// How a run of a terminal's text is drawn, as its SGR sequences (`ESC [ … m`) set it.
/// Colours are the 16 of the basic and bright palettes; a 256-colour or RGB one is taken as
/// the nearest of them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Style {
    pub fg: Option<u8>,
    pub bg: Option<u8>,
    pub bold: bool,
    pub faint: bool,
    pub italic: bool,
    pub underline: bool,
}

impl Style {
    /// Apply the SGR parameters `params`: `;`-separated, each a number (empty for 0, one too
    /// large for a `u16` ignored), or a group of `:`-separated sub-parameters (ITU T.416),
    /// read as one.
    fn apply(&mut self, params: &str) {
        let mut ps = params.split(';');
        while let Some(group) = ps.next() {
            if group.contains(':') {
                self.apply_group(group);
                continue;
            }
            let Some(p) = sgr_number(group) else {
                continue;
            };
            match p {
                0 => *self = Style::default(),
                1 => self.bold = true,
                2 => self.faint = true,
                3 => self.italic = true,
                4 => self.underline = true,
                22 => (self.bold, self.faint) = (false, false),
                23 => self.italic = false,
                24 => self.underline = false,
                30..=37 => self.fg = u8::try_from(p - 30).ok(),
                39 => self.fg = None,
                40..=47 => self.bg = u8::try_from(p - 40).ok(),
                49 => self.bg = None,
                90..=97 => self.fg = u8::try_from(p - 90 + 8).ok(),
                100..=107 => self.bg = u8::try_from(p - 100 + 8).ok(),
                38 | 48 => {
                    let mut next = || ps.next().and_then(sgr_number);
                    let colour = match next() {
                        Some(5) => next().map(palette_256),
                        // All three channels, or no colour.
                        Some(2) => match (next(), next(), next()) {
                            (Some(r), Some(g), Some(b)) => Some(nearest((
                                channel(Some(r)),
                                channel(Some(g)),
                                channel(Some(b)),
                            ))),
                            _ => None,
                        },
                        _ => None,
                    };
                    self.set_colour(p, colour);
                }
                _ => {}
            }
        }
    }

    /// Apply one `:`-separated group: `38`/`48` with `5:n` or `2:[colour space:]r:g:b`, and
    /// `4:n`, underlined unless `n` is 0. Any other is ignored.
    fn apply_group(&mut self, group: &str) {
        let subs: Vec<Option<u16>> = group.split(':').map(sgr_number).collect();
        match subs.as_slice() {
            [Some(p @ (38 | 48)), Some(5), n, ..] => self.set_colour(*p, n.map(palette_256)),
            [Some(p @ (38 | 48)), Some(2), .., r, g, b] if subs.len() >= 5 => {
                self.set_colour(*p, Some(nearest((channel(*r), channel(*g), channel(*b)))));
            }
            [Some(4), n, ..] => self.underline = n.is_some_and(|n| n != 0),
            _ => {}
        }
    }

    /// Set the foreground (`38`) or background (`48`) to `colour`, if one was given.
    fn set_colour(&mut self, p: u16, colour: Option<u8>) {
        let Some(colour) = colour else {
            return;
        };
        if p == 38 {
            self.fg = Some(colour);
        } else {
            self.bg = Some(colour);
        }
    }

    /// The classes `ui.css` draws this style with, space-separated; empty for the default.
    pub fn classes(&self) -> String {
        let mut c = Vec::new();
        if let Some(fg) = self.fg {
            c.push(format!("c-f{fg}"));
        }
        if let Some(bg) = self.bg {
            // `c-on`: black text (`c-f0`) on a background is drawn true black to stay legible.
            c.push(format!("c-b{bg} c-on"));
        }
        for (on, class) in [
            (self.bold, "c-bold"),
            (self.faint, "c-faint"),
            (self.italic, "c-it"),
            (self.underline, "c-ul"),
        ] {
            if on {
                c.push(class.to_string());
            }
        }
        c.join(" ")
    }
}

/// An SGR parameter: empty for 0, `None` for one too large for a `u16` or not a number.
fn sgr_number(p: &str) -> Option<u16> {
    if p.is_empty() {
        return Some(0);
    }
    p.parse().ok()
}

/// An RGB channel: `None`, missing, as 0; past 255 as 255.
fn channel(n: Option<u16>) -> u8 {
    u8::try_from(n.unwrap_or(0).min(255)).unwrap_or(u8::MAX)
}

/// xterm's 16 colours, which the nearest of a 256-colour or RGB one is picked from.
const PALETTE: [(u8, u8, u8); 16] = [
    (0, 0, 0),
    (205, 0, 0),
    (0, 205, 0),
    (205, 205, 0),
    (0, 0, 238),
    (205, 0, 205),
    (0, 205, 205),
    (229, 229, 229),
    (127, 127, 127),
    (255, 0, 0),
    (0, 255, 0),
    (255, 255, 0),
    (92, 92, 255),
    (255, 0, 255),
    (0, 255, 255),
    (255, 255, 255),
];

/// The nearest of the 16 colours to 256-colour `n`.
fn palette_256(n: u16) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    match n {
        0..=15 => u8::try_from(n).unwrap_or(7),
        16..=231 => {
            let i = usize::from(n - 16);
            nearest((LEVELS[i / 36], LEVELS[i / 6 % 6], LEVELS[i % 6]))
        }
        _ => {
            let v = u8::try_from(8 + 10 * (n.min(255) - 232)).unwrap_or(u8::MAX);
            nearest((v, v, v))
        }
    }
}

fn nearest((r, g, b): (u8, u8, u8)) -> u8 {
    let d = |&(pr, pg, pb): &(u8, u8, u8)| {
        let sq = |a: u8, b: u8| (i32::from(a) - i32::from(b)).pow(2);
        sq(r, pr) + sq(g, pg) + sq(b, pb)
    };
    (0..16u8)
        .min_by_key(|&i| d(&PALETTE[usize::from(i)]))
        .unwrap_or(7)
}

/// A run of a terminal line's text drawn in one [`Style`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub style: Style,
    pub text: String,
}

/// Filter a terminal line as [`terminal_safe`] does, retaining SGR styles in text runs.
/// Start with `style` and update it to the line's final state. A carriage return clears
/// the text accumulated so far without resetting the style.
pub fn terminal_runs(line: &str, style: &mut Style) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    let mut chars = line.chars().peekable();
    let push = |runs: &mut Vec<Run>, style: Style, c: char| match runs.last_mut() {
        Some(r) if r.style == style => r.text.push(c),
        _ => runs.push(Run {
            style,
            text: c.to_string(),
        }),
    };
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.peek() {
                Some('[') => {
                    chars.next();
                    csi(&mut chars, style);
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    chars.next();
                    skip_string(&mut chars);
                }
                _ => skip_escape(&mut chars),
            },
            '\u{9b}' => csi(&mut chars, style),
            '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => skip_string(&mut chars),
            '\r' => runs.clear(),
            '\n' | '\t' => push(&mut runs, *style, c),
            c if c.is_control() || vk_hub_proto::invisible(c) => {}
            c => push(&mut runs, *style, c),
        }
    }
    runs
}

/// The longest SGR parameters applied.
const MAX_SGR: usize = 64;

/// Read a CSI sequence as [`skip_csi`] skips it, applying it to `style` when it is an SGR.
fn csi(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, style: &mut Style) {
    let mut params = String::new();
    // Past what any SGR needs, it is skipped unapplied, as half of it would be wrong.
    let mut overflow = false;
    while let Some(&c) = chars.peek() {
        if ('\u{20}'..='\u{3f}').contains(&c) {
            chars.next();
            if params.len() < MAX_SGR {
                params.push(c);
            } else {
                overflow = true;
            }
            continue;
        }
        if ('\u{40}'..='\u{7e}').contains(&c) {
            chars.next();
            if c == 'm'
                && !overflow
                && params
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b';' || b == b':')
            {
                style.apply(&params);
            }
        }
        return;
    }
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
    fn a_terminal_line_s_colours_make_runs() {
        let mut style = Style::default();
        let runs = terminal_runs(
            "\u{1b}[32;1mok\u{1b}[0m plain \u{1b}[38;5;196mred\u{1b}[m\u{1b}]0;title\u{7}",
            &mut style,
        );
        let shown: Vec<(String, &str)> = runs
            .iter()
            .map(|r| (r.style.classes(), r.text.as_str()))
            .collect();
        assert_eq!(
            shown,
            [
                ("c-f2 c-bold".to_string(), "ok"),
                (String::new(), " plain "),
                ("c-f9".to_string(), "red"),
            ]
        );
        // A carriage return starts the line over, in the style then set.
        let runs = terminal_runs("\u{1b}[31m10%\r20%", &mut style);
        assert_eq!(runs.len(), 1);
        assert_eq!((runs[0].style.fg, runs[0].text.as_str()), (Some(1), "20%"));
        // The line leaves the style it set, which the next starts from.
        assert_eq!(style.fg, Some(1));
        let runs = terminal_runs("still red", &mut style);
        assert_eq!(runs[0].style.fg, Some(1));
    }

    /// What each SGR sequence makes of a style set red and bold on a green background.
    #[test]
    fn sgr_sequences_set_the_style() {
        let base = Style {
            fg: Some(1),
            bg: Some(2),
            bold: true,
            faint: true,
            italic: true,
            underline: true,
        };
        let long = format!("\u{1b}[{}1m", "0;".repeat(40));
        let cases: Vec<(String, Style)> = vec![
            (
                "\u{1b}[22m".into(),
                Style {
                    bold: false,
                    faint: false,
                    ..base
                },
            ),
            (
                "\u{1b}[23m".into(),
                Style {
                    italic: false,
                    ..base
                },
            ),
            (
                "\u{1b}[24m".into(),
                Style {
                    underline: false,
                    ..base
                },
            ),
            ("\u{1b}[39m".into(), Style { fg: None, ..base }),
            ("\u{1b}[49m".into(), Style { bg: None, ..base }),
            (
                "\u{1b}[40m".into(),
                Style {
                    bg: Some(0),
                    ..base
                },
            ),
            (
                "\u{1b}[47m".into(),
                Style {
                    bg: Some(7),
                    ..base
                },
            ),
            (
                "\u{1b}[100m".into(),
                Style {
                    bg: Some(8),
                    ..base
                },
            ),
            (
                "\u{1b}[107m".into(),
                Style {
                    bg: Some(15),
                    ..base
                },
            ),
            (
                "\u{1b}[90m".into(),
                Style {
                    fg: Some(8),
                    ..base
                },
            ),
            (
                "\u{1b}[97m".into(),
                Style {
                    fg: Some(15),
                    ..base
                },
            ),
            // The 256 colours' greys, and a cube colour, as the nearest of the 16.
            (
                "\u{1b}[38;5;232m".into(),
                Style {
                    fg: Some(0),
                    ..base
                },
            ),
            (
                "\u{1b}[38;5;255m".into(),
                Style {
                    fg: Some(7),
                    ..base
                },
            ),
            (
                "\u{1b}[38;5;21m".into(),
                Style {
                    fg: Some(4),
                    ..base
                },
            ),
            // No colour given, none set.
            ("\u{1b}[38;5m".into(), base),
            (
                "\u{1b}[48;2;0;0;0m".into(),
                Style {
                    bg: Some(0),
                    ..base
                },
            ),
            // An RGB colour without all three channels sets none.
            ("\u{1b}[48;2m".into(), base),
            ("\u{1b}[38;2;0;0m".into(), base),
            // A parameter too large is ignored; an empty one is 0, a reset.
            ("\u{1b}[99999;3m".into(), base),
            (
                "\u{1b}[;1m".into(),
                Style {
                    bold: true,
                    ..Style::default()
                },
            ),
            ("\u{1b}[m".into(), Style::default()),
            // Past what any SGR needs, nothing is applied.
            (long, base),
            // Other sequences leave the style be.
            ("\u{1b}[?25l\u{1b}[2K".into(), base),
            // Sub-parameters, `:`-separated, as one group.
            (
                "\u{1b}[38:5:196m".into(),
                Style {
                    fg: Some(9),
                    ..base
                },
            ),
            (
                "\u{1b}[48:2::0:0:250m".into(),
                Style {
                    bg: Some(4),
                    ..base
                },
            ),
            (
                "\u{1b}[38:2:0:0:250m".into(),
                Style {
                    fg: Some(4),
                    ..base
                },
            ),
            (
                "\u{1b}[4:0m".into(),
                Style {
                    underline: false,
                    ..base
                },
            ),
            ("\u{1b}[4:3m".into(), base),
            ("\u{1b}[1:2m".into(), base),
            ("\u{1b}[38:5m".into(), base),
        ];
        for (seq, want) in cases {
            let mut style = base;
            let runs = terminal_runs(&format!("{seq}x"), &mut style);
            assert_eq!(style, want, "{seq:?}");
            assert_eq!(runs.len(), 1, "{seq:?}");
            assert_eq!(runs[0].text, "x", "{seq:?}");
        }
        // Invisible characters go, inside a run as anywhere.
        let mut style = Style::default();
        let runs = terminal_runs("a\u{200b}b\u{1b}[1mc\u{202e}d", &mut style);
        let texts: Vec<&str> = runs.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, ["ab", "cd"]);
        // On a background, text reads dark unless it has a colour of its own.
        assert_eq!(
            Style {
                bg: Some(7),
                ..Style::default()
            }
            .classes(),
            "c-b7 c-on"
        );
    }

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

    /// Only a plain http(s) URL becomes a link, escaped; anything else leaves the label as
    /// text, as it would be with no URL at all.
    #[test]
    fn only_a_plain_web_url_becomes_a_link() {
        let link = |url: Option<&str>| {
            let mut h = Html::new();
            h.external_link(url, "acme/web <b> #7");
            h.into_string()
        };
        assert_eq!(
            link(Some("https://gitlab.example.com/acme/web/-/jobs/7?a=1&b=2")),
            "<a href=\"https://gitlab.example.com/acme/web/-/jobs/7?a=1&amp;b=2\" \
             target=\"_blank\" rel=\"noopener noreferrer\">acme/web &lt;b&gt; #7</a>"
        );
        let text = link(None);
        assert_eq!(text, "acme/web &lt;b&gt; #7");
        for bad in [
            "javascript:alert(1)",
            "https://u:p@gitlab.example.com/",
            "https://gitlab.example.com/\"><script>",
            "https://gitlab.example.com/\u{7}",
            "/node/x",
            "",
        ] {
            assert_eq!(link(Some(bad)), text, "{bad:?}");
        }
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
