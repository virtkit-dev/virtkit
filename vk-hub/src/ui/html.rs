//! HTML built so that nothing interpolated can be markup: [`Html::raw`] takes only
//! `&'static str` — a literal or constant of this crate's, since nothing built at run time is
//! `'static` short of leaking it — and everything else goes through [`Html::text`], which
//! escapes it for text content and quoted attribute values alike. [`Html::node`] is for a
//! string a host reported — the VMs `vk` lists, their logs: it is made
//! [`vk_fleet_proto::display_safe`] again before it is escaped, whatever was done before.
//!
//! A host's strings go only in text content or quoted plain attributes (`title`, `value`,
//! `href` built by the hub), never in an attribute htmx interprets (`hx-*`, `sse-*`): those
//! are written from constants, and from IDs the router has checked are hex.

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
        escape_into(&mut self.0, &vk_fleet_proto::display_safe(value));
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
}
