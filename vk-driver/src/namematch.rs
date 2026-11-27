//! Names and globs, as `vk list` and `vk dev list` take them to pick VMs by name: a word with
//! a glob character in it (`*`, `?`, `[`) is a glob, any other word a name, matched whole.

/// A name to match exactly, or a glob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    Name(String),
    /// `*` any run of characters, `?` any one, `[abc]`, `[a-z]` and `[!a-z]` one of a set;
    /// a `[` with no closing `]` is itself
    Glob(String),
}

impl Pattern {
    /// A word from the command line: a glob if it holds a glob character, else a name.
    pub fn from_word(word: &str) -> Self {
        match word.contains(['*', '?', '[']) {
            true => Pattern::Glob(word.to_string()),
            false => Pattern::Name(word.to_string()),
        }
    }

    pub fn matches(&self, name: &str) -> bool {
        match self {
            Pattern::Name(n) => n == name,
            Pattern::Glob(g) => {
                let (g, name): (Vec<char>, Vec<char>) =
                    (g.chars().collect(), name.chars().collect());
                glob(&g, &name)
            }
        }
    }
}

/// Whether the glob `p` matches all of `s`.
fn glob(p: &[char], s: &[char]) -> bool {
    match p.first() {
        None => s.is_empty(),
        // Consecutive stars are one: keeps the backtracking linear in their number.
        Some('*') => {
            let rest = &p[p.iter().take_while(|&&c| c == '*').count()..];
            (0..=s.len()).any(|i| glob(rest, &s[i..]))
        }
        Some('?') => !s.is_empty() && glob(&p[1..], &s[1..]),
        Some('[') => match class(&p[1..]) {
            Some((set, len)) => s.first().is_some_and(|&c| set(c)) && glob(&p[1 + len..], &s[1..]),
            None => s.first() == Some(&'[') && glob(&p[1..], &s[1..]),
        },
        Some(&c) => s.first() == Some(&c) && glob(&p[1..], &s[1..]),
    }
}

/// The set a `[...]` class names, `p` starting just past its `[`, and how much of `p` it took,
/// its `]` included; `None` when it is not closed. A `]` first in the set is a member.
#[allow(clippy::type_complexity)]
fn class(p: &[char]) -> Option<(Box<dyn Fn(char) -> bool>, usize)> {
    let negated = matches!(p.first(), Some('!') | Some('^'));
    let start = usize::from(negated);
    let end = start + 1 + p.get(start + 1..)?.iter().position(|&c| c == ']')?;
    let body: Vec<char> = p[start..end].to_vec();
    let set = move |c: char| {
        let mut i = 0;
        let mut hit = false;
        while i < body.len() {
            if i + 2 < body.len() && body[i + 1] == '-' {
                hit |= (body[i]..=body[i + 2]).contains(&c);
                i += 3;
            } else {
                hit |= body[i] == c;
                i += 1;
            }
        }
        hit != negated
    };
    Some((Box::new(set), end + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_word_is_a_glob_only_with_a_glob_character() {
        assert_eq!(Pattern::from_word("wab"), Pattern::Name("wab".into()));
        assert_eq!(
            Pattern::from_word("wab/runner"),
            Pattern::Name("wab/runner".into())
        );
        for g in ["wab*", "wab-wt?", "wab-wt[0-9]"] {
            assert_eq!(Pattern::from_word(g), Pattern::Glob(g.into()));
        }
    }

    #[test]
    fn a_name_matches_whole_and_a_glob_as_a_shell_would() {
        let m = |p: &str, s: &str| Pattern::from_word(p).matches(s);
        assert!(m("wab", "wab") && !m("wab", "wab-wt4") && !m("wab", "wa"));
        assert!(m("wab*", "wab") && m("wab*", "wab-wt4") && m("wab*", "wab/runner"));
        assert!(!m("wab*", "xwab"));
        assert!(m("*-wt?", "wab-wt4") && !m("*-wt?", "wab-wt42"));
        assert!(m("wab-wt[1-4]", "wab-wt3") && !m("wab-wt[1-4]", "wab-wt5"));
        assert!(m("wab-wt[!1-4]", "wab-wt5") && !m("wab-wt[!1-4]", "wab-wt3"));
        assert!(m("[]x]", "]") && m("[]x]", "x"));
        assert!(m("a[b", "a[b"), "an unclosed `[` is itself");
        assert!(m("**a**", "banana") && m("*", ""));
    }
}
