//! The padded-column table renderer for `vk dev` output.

/// Render `rows` beneath `headers` as padded columns: each column as wide as its widest cell,
/// header included, columns two spaces apart, and a line's trailing padding trimmed. A row
/// shorter than the header keeps the columns it has; a longer one widens the table.
pub(super) fn render(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut width: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            let seen = cell.chars().count();
            match width.get_mut(i) {
                Some(w) => *w = (*w).max(seen),
                None => width.push(seen),
            }
        }
    }
    let header: Vec<String> = headers.iter().map(|h| (*h).to_string()).collect();
    let mut out = String::new();
    for row in std::iter::once(&header).chain(rows) {
        let line: Vec<String> = row
            .iter()
            .zip(&width)
            .map(|(cell, w)| format!("{cell:<width$}", width = *w))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out
}
