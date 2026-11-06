//! Keystrokes for the VGA console's PS/2 keyboard: what a host terminal (or an input file)
//! sends — UTF-8 text, control characters, and the escape sequences of cursor, editing and
//! function keys — turned into the set-2 scancodes the guest's keyboard driver reads.
//!
//! The layout is US. Characters the layout has no key for (anything outside ASCII) are
//! dropped. A terminal sends Alt+key as ESC and the key; ESC followed by another byte in the
//! same chunk is read that way, and an escape sequence split across two chunks is completed by
//! the next one, so a lone ESC is only sent by [`KeyTranslator::flush`], once the input has
//! been idle.

/// A key on the US keyboard: its set-2 make code, and whether it has the `E0` prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key {
    code: u8,
    extended: bool,
}

const fn key(code: u8) -> Key {
    Key {
        code,
        extended: false,
    }
}

const fn ext(code: u8) -> Key {
    Key {
        code,
        extended: true,
    }
}

const SHIFT: Key = key(0x12);
const CTRL: Key = key(0x14);
const ALT: Key = key(0x11);
const ENTER: Key = key(0x5a);
const TAB: Key = key(0x0d);
const BACKSPACE: Key = key(0x66);
const ESC: Key = key(0x76);
const SPACE: Key = key(0x29);
const UP: Key = ext(0x75);
const DOWN: Key = ext(0x72);
const LEFT: Key = ext(0x6b);
const RIGHT: Key = ext(0x74);
const HOME: Key = ext(0x6c);
const END: Key = ext(0x69);
const INSERT: Key = ext(0x70);
const DELETE: Key = ext(0x71);
const PAGE_UP: Key = ext(0x7d);
const PAGE_DOWN: Key = ext(0x7a);
/// F1 to F12.
const FUNCTION: [Key; 12] = [
    key(0x05),
    key(0x06),
    key(0x04),
    key(0x0c),
    key(0x03),
    key(0x0b),
    key(0x83),
    key(0x0a),
    key(0x01),
    key(0x09),
    key(0x78),
    key(0x07),
];

/// The key a letter is on.
fn letter(c: u8) -> Key {
    const LETTERS: [u8; 26] = [
        0x1c, 0x32, 0x21, 0x23, 0x24, 0x2b, 0x34, 0x33, 0x43, 0x3b, 0x42, 0x4b, 0x3a, 0x31, 0x44,
        0x4d, 0x15, 0x2d, 0x1b, 0x2c, 0x3c, 0x2a, 0x1d, 0x22, 0x35, 0x1a,
    ];
    key(LETTERS[usize::from(c.to_ascii_lowercase() - b'a') % 26])
}

/// The key a printable ASCII character is on, and whether it takes Shift.
fn printable(c: u8) -> Option<(Key, bool)> {
    const DIGITS: [u8; 10] = [0x45, 0x16, 0x1e, 0x26, 0x25, 0x2e, 0x36, 0x3d, 0x3e, 0x46];
    // The shifted digit row, from `)` (on 0) to `(` (on 9).
    const SHIFTED_DIGITS: &[u8; 10] = b")!@#$%^&*(";
    let plain = |code| Some((key(code), false));
    let shifted = |code| Some((key(code), true));
    match c {
        b'a'..=b'z' => Some((letter(c), false)),
        b'A'..=b'Z' => Some((letter(c), true)),
        b'0'..=b'9' => plain(DIGITS[usize::from(c - b'0')]),
        b' ' => Some((SPACE, false)),
        b'`' => plain(0x0e),
        b'~' => shifted(0x0e),
        b'-' => plain(0x4e),
        b'_' => shifted(0x4e),
        b'=' => plain(0x55),
        b'+' => shifted(0x55),
        b'[' => plain(0x54),
        b'{' => shifted(0x54),
        b']' => plain(0x5b),
        b'}' => shifted(0x5b),
        b'\\' => plain(0x5d),
        b'|' => shifted(0x5d),
        b';' => plain(0x4c),
        b':' => shifted(0x4c),
        b'\'' => plain(0x52),
        b'"' => shifted(0x52),
        b',' => plain(0x41),
        b'<' => shifted(0x41),
        b'.' => plain(0x49),
        b'>' => shifted(0x49),
        b'/' => plain(0x4a),
        b'?' => shifted(0x4a),
        _ => SHIFTED_DIGITS
            .iter()
            .position(|&s| s == c)
            .map(|d| (key(DIGITS[d]), true)),
    }
}

/// Append a press of `k` to `out`.
fn make(out: &mut Vec<u8>, k: Key) {
    if k.extended {
        out.push(0xe0);
    }
    out.push(k.code);
}

/// Append a release of `k` to `out`.
fn brk(out: &mut Vec<u8>, k: Key) {
    if k.extended {
        out.push(0xe0);
    }
    out.extend([0xf0, k.code]);
}

/// Append `k` struck with the `modifiers` held.
fn strike(out: &mut Vec<u8>, modifiers: &[Key], k: Key) {
    modifiers.iter().for_each(|&m| make(out, m));
    make(out, k);
    brk(out, k);
    modifiers.iter().rev().for_each(|&m| brk(out, m));
}

/// The key and modifiers one input byte (outside an escape sequence) stands for.
fn byte_key(b: u8) -> Option<(Key, Vec<Key>)> {
    match b {
        b'\r' | b'\n' => Some((ENTER, vec![])),
        b'\t' => Some((TAB, vec![])),
        0x7f | 0x08 => Some((BACKSPACE, vec![])),
        0x00 => Some((SPACE, vec![CTRL])),
        // Ctrl-A to Ctrl-Z, but for those taken above (Ctrl-H, -I, -J, -M).
        0x01..=0x1a => Some((letter(b - 1 + b'a'), vec![CTRL])),
        0x1c => Some((key(0x5d), vec![CTRL])),        // Ctrl-\
        0x1d => Some((key(0x5b), vec![CTRL])),        // Ctrl-]
        0x1e => Some((key(0x36), vec![CTRL, SHIFT])), // Ctrl-^
        0x1f => Some((key(0x4e), vec![CTRL, SHIFT])), // Ctrl-_
        _ => printable(b).map(|(k, shift)| (k, if shift { vec![SHIFT] } else { vec![] })),
    }
}

/// The modifiers an xterm modifier parameter (`1 + bitmask`) asks for.
fn xterm_modifiers(param: Option<u32>) -> Vec<Key> {
    let bits = param.unwrap_or(1).saturating_sub(1);
    let mut mods = Vec::new();
    if bits & 1 != 0 {
        mods.push(SHIFT);
    }
    if bits & 2 != 0 {
        mods.push(ALT);
    }
    if bits & 4 != 0 {
        mods.push(CTRL);
    }
    mods
}

/// What the escape sequence at the start of `input` (which starts with ESC) is.
enum Escape {
    /// More bytes are needed to tell.
    Incomplete,
    /// A key with modifiers, and how many bytes the sequence took.
    Key(Key, Vec<Key>, usize),
    /// A sequence with no key here (mouse reports, focus events...): skip that many bytes.
    Skip(usize),
}

fn escape(input: &[u8]) -> Escape {
    match input.get(1) {
        None => Escape::Incomplete,
        Some(b'[') => csi(input),
        Some(b'O') => match input.get(2) {
            None => Escape::Incomplete,
            Some(&b) => match ss3_key(b) {
                Some(k) => Escape::Key(k, vec![], 3),
                None => Escape::Skip(3),
            },
        },
        // ESC ESC: Esc, the second one starting what follows.
        Some(0x1b) => Escape::Key(ESC, vec![], 1),
        // Alt and a key.
        Some(&b) => match byte_key(b) {
            Some((k, mut mods)) => {
                mods.insert(0, ALT);
                Escape::Key(k, mods, 2)
            }
            None => Escape::Skip(2),
        },
    }
}

/// The key of `ESC O <b>` (cursor keys in application mode, F1-F4).
fn ss3_key(b: u8) -> Option<Key> {
    match b {
        b'A' => Some(UP),
        b'B' => Some(DOWN),
        b'C' => Some(RIGHT),
        b'D' => Some(LEFT),
        b'H' => Some(HOME),
        b'F' => Some(END),
        b'P'..=b'S' => FUNCTION.get(usize::from(b - b'P')).copied(),
        _ => None,
    }
}

/// A control sequence: `ESC [`, parameters, a final byte.
fn csi(input: &[u8]) -> Escape {
    let Some(end) = input
        .iter()
        .skip(2)
        .position(|&b| (0x40..=0x7e).contains(&b))
        .map(|p| p + 2)
    else {
        // Give up on a sequence that never ends rather than hold the input forever.
        return if input.len() > 32 {
            Escape::Skip(input.len())
        } else {
            Escape::Incomplete
        };
    };
    let params: Vec<Option<u32>> = input
        .get(2..end)
        .unwrap_or_default()
        .split(|&b| b == b';')
        .map(|p| std::str::from_utf8(p).ok().and_then(|s| s.parse().ok()))
        .collect();
    let first = params.first().copied().flatten();
    let modifiers = params.get(1).copied().flatten();
    let k = match input.get(end) {
        Some(&b @ (b'A' | b'B' | b'C' | b'D' | b'H' | b'F' | b'P' | b'Q' | b'R' | b'S')) => {
            ss3_key(b)
        }
        Some(b'Z') => {
            // Shift-Tab.
            return Escape::Key(TAB, vec![SHIFT], end + 1);
        }
        Some(b'~') => match first {
            Some(1 | 7) => Some(HOME),
            Some(2) => Some(INSERT),
            Some(3) => Some(DELETE),
            Some(4 | 8) => Some(END),
            Some(5) => Some(PAGE_UP),
            Some(6) => Some(PAGE_DOWN),
            Some(n @ 11..=15) => FUNCTION.get(n as usize - 11).copied(),
            Some(n @ 17..=21) => FUNCTION.get(n as usize - 12).copied(),
            Some(n @ 23..=24) => FUNCTION.get(n as usize - 13).copied(),
            _ => None,
        },
        _ => None,
    };
    match k {
        Some(k) => Escape::Key(k, xterm_modifiers(modifiers), end + 1),
        None => Escape::Skip(end + 1),
    }
}

/// Turns input bytes into scancodes, keeping an escape sequence cut in two between calls.
#[derive(Default)]
pub(crate) struct KeyTranslator {
    pending: Vec<u8>,
}

impl KeyTranslator {
    /// The scancodes `input` types, after what an earlier call left pending.
    pub(crate) fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        let mut bytes = std::mem::take(&mut self.pending);
        bytes.extend_from_slice(input);
        let mut out = Vec::new();
        let mut at = 0;
        while let Some(rest) = bytes.get(at..).filter(|r| !r.is_empty()) {
            if rest[0] == 0x1b {
                match escape(rest) {
                    Escape::Incomplete => {
                        self.pending = rest.to_vec();
                        break;
                    }
                    Escape::Key(k, mods, len) => {
                        strike(&mut out, &mods, k);
                        at += len;
                    }
                    Escape::Skip(len) => at += len,
                }
                continue;
            }
            // A UTF-8 sequence has no key on a US layout: skip it whole.
            let len = match rest[0] {
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf7 => 4,
                _ => 1,
            };
            if len == 1
                && let Some((k, mods)) = byte_key(rest[0])
            {
                strike(&mut out, &mods, k);
            }
            at += len.min(rest.len());
        }
        out
    }

    /// The scancodes of what is pending, once the input has gone idle: a lone ESC is Esc.
    pub(crate) fn flush(&mut self) -> Vec<u8> {
        let pending = std::mem::take(&mut self.pending);
        let mut out = Vec::new();
        if let Some((&first, rest)) = pending.split_first() {
            if first == 0x1b {
                strike(&mut out, &[], ESC);
            }
            out.extend(self.feed(rest));
            // Whatever is still incomplete now is dropped: the input has moved on.
            self.pending.clear();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(input: &[u8]) -> Vec<u8> {
        KeyTranslator::default().feed(input)
    }

    #[test]
    fn letters_digits_and_enter() {
        assert_eq!(typed(b"a"), [0x1c, 0xf0, 0x1c]);
        assert_eq!(typed(b"1"), [0x16, 0xf0, 0x16]);
        assert_eq!(typed(b"\r"), [0x5a, 0xf0, 0x5a]);
        assert_eq!(typed(b"\n"), [0x5a, 0xf0, 0x5a]);
    }

    #[test]
    fn shifted_characters_hold_shift() {
        assert_eq!(typed(b"A"), [0x12, 0x1c, 0xf0, 0x1c, 0xf0, 0x12]);
        assert_eq!(typed(b"!"), [0x12, 0x16, 0xf0, 0x16, 0xf0, 0x12]);
        assert_eq!(typed(b"("), [0x12, 0x46, 0xf0, 0x46, 0xf0, 0x12]);
        assert_eq!(typed(b"~"), [0x12, 0x0e, 0xf0, 0x0e, 0xf0, 0x12]);
    }

    #[test]
    fn control_characters_hold_ctrl() {
        // Ctrl-C.
        assert_eq!(typed(&[0x03]), [0x14, 0x21, 0xf0, 0x21, 0xf0, 0x14]);
        // DEL from a terminal's Backspace key.
        assert_eq!(typed(&[0x7f]), [0x66, 0xf0, 0x66]);
        assert_eq!(typed(b"\t"), [0x0d, 0xf0, 0x0d]);
    }

    #[test]
    fn cursor_and_editing_keys_are_extended() {
        assert_eq!(typed(b"\x1b[A"), [0xe0, 0x75, 0xe0, 0xf0, 0x75]);
        assert_eq!(typed(b"\x1bOD"), [0xe0, 0x6b, 0xe0, 0xf0, 0x6b]);
        assert_eq!(typed(b"\x1b[3~"), [0xe0, 0x71, 0xe0, 0xf0, 0x71]);
        assert_eq!(typed(b"\x1b[6~"), [0xe0, 0x7a, 0xe0, 0xf0, 0x7a]);
    }

    #[test]
    fn function_keys_both_ways() {
        assert_eq!(typed(b"\x1bOP"), [0x05, 0xf0, 0x05]); // F1
        assert_eq!(typed(b"\x1b[15~"), [0x03, 0xf0, 0x03]); // F5
        assert_eq!(typed(b"\x1b[21~"), [0x09, 0xf0, 0x09]); // F10
        assert_eq!(typed(b"\x1b[24~"), [0x07, 0xf0, 0x07]); // F12
    }

    #[test]
    fn modified_keys_and_alt() {
        // Ctrl-Right (xterm: 1 + 4).
        assert_eq!(
            typed(b"\x1b[1;5C"),
            [0x14, 0xe0, 0x74, 0xe0, 0xf0, 0x74, 0xf0, 0x14]
        );
        // Alt-F2 from the console, as `ESC 2`... and Alt-x.
        assert_eq!(typed(b"\x1bx"), [0x11, 0x22, 0xf0, 0x22, 0xf0, 0x11]);
    }

    #[test]
    fn a_sequence_cut_in_two_completes_on_the_next_chunk() {
        let mut t = KeyTranslator::default();
        assert_eq!(t.feed(b"\x1b["), Vec::<u8>::new());
        assert_eq!(t.feed(b"B"), [0xe0, 0x72, 0xe0, 0xf0, 0x72]);
    }

    #[test]
    fn a_lone_escape_is_sent_once_idle() {
        let mut t = KeyTranslator::default();
        assert_eq!(t.feed(b"\x1b"), Vec::<u8>::new());
        assert_eq!(t.flush(), [0x76, 0xf0, 0x76]);
        assert_eq!(t.flush(), Vec::<u8>::new());
    }

    #[test]
    fn non_ascii_and_unknown_sequences_are_dropped() {
        assert_eq!(typed("é".as_bytes()), Vec::<u8>::new());
        assert_eq!(typed(b"\x1b[200~"), Vec::<u8>::new());
        assert_eq!(typed("é!".as_bytes()), [0x12, 0x16, 0xf0, 0x16, 0xf0, 0x12]);
    }
}
