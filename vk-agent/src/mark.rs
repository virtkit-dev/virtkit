//! The line a guest high-water mark is published as: `<used> <total>` in bytes.
//!
//! [`crate::fsmark`] publishes writable-layer figures and [`crate::memmark`] publishes memory
//! demand. Sharing the format keeps their writers and readers aligned.

/// The line a mark file holds, newline included.
pub(crate) fn render(used: u64, total: u64) -> String {
    format!("{used} {total}\n")
}

/// Parse exactly two figures; a partial or otherwise malformed line is not a measurement.
pub(crate) fn parse(text: &str) -> Option<(u64, u64)> {
    let mut figures = text.split_whitespace();
    let used = figures.next()?.parse().ok()?;
    let total = figures.next()?.parse().ok()?;
    if figures.next().is_some() {
        return None;
    }
    Some((used, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rendered_mark_parses_back_to_the_figures_written() {
        assert_eq!(parse(&render(0, 0)), Some((0, 0)));
        assert_eq!(
            parse(&render(u64::MAX, u64::MAX)),
            Some((u64::MAX, u64::MAX))
        );
    }

    #[test]
    fn anything_but_two_figures_is_no_mark() {
        // What a reader catching the file mid-write sees, and what an unrelated file reads as.
        for text in [
            "",
            "9000",
            "9000 ",
            "nine 10000\n",
            "-1 10000\n",
            "9000 10000 trailing\n",
        ] {
            assert_eq!(parse(text), None, "accepted {text:?}");
        }
    }
}
