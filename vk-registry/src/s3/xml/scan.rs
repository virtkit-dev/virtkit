//! The XML S3 requests carry (`Delete`, `CreateBucketConfiguration`), read by an element
//! scanner of its own rather than a parser: elements, their text and their children, and
//! nothing XML can make a reader fetch or expand. The prolog, processing instructions and
//! comments are passed over and CDATA is text; the five predefined entities and character
//! references are decoded, and any other entity, or a document type declaration that could
//! define one, makes the document malformed. Elements are known by their local name, so a
//! namespace prefix and the `xmlns` attributes say nothing; attributes are checked for form
//! and dropped. Depth and element count are bounded, so a document costs at most its length
//! in memory, and no input makes it panic.

/// One element: its local name, the text directly inside it, and its child elements.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Element {
    pub(crate) name: String,
    pub(crate) text: String,
    pub(crate) children: Vec<Element>,
}

impl Element {
    /// The children named `name`, in order.
    pub(crate) fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// The child named `name`: `Err` when there are several, which no field of a request
    /// takes.
    pub(crate) fn one(&self, name: &str) -> Result<Option<&Element>, Malformed> {
        let mut all = self.children.iter().filter(|c| c.name == name);
        let first = all.next();
        match all.next() {
            Some(_) => Err(Malformed("an element that is given once is given twice")),
            None => Ok(first),
        }
    }
}

/// Why a document was refused: what S3 calls `MalformedXML`, with what was wrong.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed(pub(crate) &'static str);

/// Deepest nesting taken, the document's element counting as one: S3's request documents
/// are three deep.
const MAX_DEPTH: usize = 16;

/// Longest entity reference between `&` and `;`: `#x10FFFF`.
const MAX_ENTITY: usize = 8;

const TRUNCATED: Malformed = Malformed("the document ends inside an element");

/// The document element of `input`, of at most `max_elements` elements in all.
pub(crate) fn parse(input: &[u8], max_elements: usize) -> Result<Element, Malformed> {
    let text = std::str::from_utf8(input).map_err(|_| Malformed("the document is not UTF-8"))?;
    // What XML 1.0 has no character for, a reference excepted ([`character`]), so that no
    // text taken from a document holds what an answer echoing it could not write.
    if text
        .chars()
        .any(|c| (c < ' ' && !is_space(c)) || matches!(c, '\u{fffe}' | '\u{ffff}'))
    {
        return Err(Malformed(
            "the document holds a character XML does not allow",
        ));
    }
    let rest = misc(text.strip_prefix('\u{feff}').unwrap_or(text))?;
    if rest.is_empty() {
        return Err(Malformed("the document has no element"));
    }
    let mut count = 0usize;
    let (root, rest) = element(rest, 1, &mut count, max_elements)?;
    if !misc(rest)?.is_empty() {
        return Err(Malformed("the document goes on past its element"));
    }
    Ok(root)
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// `s` past what may come before and after the document element: white space, processing
/// instructions (the XML declaration among them) and comments.
fn misc(mut s: &str) -> Result<&str, Malformed> {
    loop {
        s = s.trim_start_matches(is_space);
        if let Some(r) = s.strip_prefix("<?") {
            s = past(r, "?>")?;
        } else if let Some(r) = s.strip_prefix("<!--") {
            s = past(r, "-->")?;
        } else if s.starts_with("<!") {
            return Err(Malformed("a document type declaration is not taken"));
        } else {
            return Ok(s);
        }
    }
}

/// `s` past the first `end`.
fn past<'a>(s: &'a str, end: &str) -> Result<&'a str, Malformed> {
    let at = s.find(end).ok_or(TRUNCATED)?;
    s.get(at.saturating_add(end.len())..).ok_or(TRUNCATED)
}

/// Whether `name` can be an element or attribute name: not empty, and none of the
/// characters that end or quote one. Looser than XML's production, which nothing here
/// depends on.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| is_space(c) || matches!(c, '<' | '>' | '&' | '"' | '\'' | '=' | '/'))
}

/// A qualified name's local part.
fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// The element `s` starts with, at `depth`, and what follows it.
fn element<'a>(
    s: &'a str,
    depth: usize,
    count: &mut usize,
    max: usize,
) -> Result<(Element, &'a str), Malformed> {
    if depth > MAX_DEPTH {
        return Err(Malformed("the document nests too deep"));
    }
    *count = count.saturating_add(1);
    if *count > max {
        return Err(Malformed("the document has too many elements"));
    }
    let s = s
        .strip_prefix('<')
        .ok_or(Malformed("an element was expected"))?;
    let end = s
        .find(|c: char| is_space(c) || c == '/' || c == '>')
        .ok_or(TRUNCATED)?;
    let (qname, mut s) = s.split_at_checked(end).ok_or(TRUNCATED)?;
    if !valid_name(qname) || local(qname).is_empty() {
        return Err(Malformed("an element's name is malformed"));
    }
    let mut el = Element {
        name: local(qname).to_string(),
        ..Element::default()
    };
    // The attributes, checked and dropped.
    loop {
        let trimmed = s.trim_start_matches(is_space);
        if let Some(r) = trimmed.strip_prefix("/>") {
            return Ok((el, r));
        }
        if let Some(r) = trimmed.strip_prefix('>') {
            s = r;
            break;
        }
        if trimmed.len() == s.len() {
            return Err(Malformed("attributes are separated by white space"));
        }
        let eq = trimmed.find('=').ok_or(TRUNCATED)?;
        let (name, r) = trimmed.split_at_checked(eq).ok_or(TRUNCATED)?;
        if !valid_name(name.trim_end_matches(is_space)) {
            return Err(Malformed("an attribute's name is malformed"));
        }
        let r = r.get(1..).ok_or(TRUNCATED)?.trim_start_matches(is_space);
        let quote = r.chars().next().ok_or(TRUNCATED)?;
        if quote != '"' && quote != '\'' {
            return Err(Malformed("an attribute's value is quoted"));
        }
        let r = r.get(1..).ok_or(TRUNCATED)?;
        let close = r.find(quote).ok_or(TRUNCATED)?;
        let (value, r) = r.split_at_checked(close).ok_or(TRUNCATED)?;
        if value.contains('<') {
            return Err(Malformed("an attribute's value holds a <"));
        }
        decode_into(value, &mut String::new())?;
        s = r.get(1..).ok_or(TRUNCATED)?;
    }
    // The content, up to the matching end tag.
    loop {
        let lt = s.find('<').ok_or(TRUNCATED)?;
        let (chars, r) = s.split_at_checked(lt).ok_or(TRUNCATED)?;
        decode_into(chars, &mut el.text)?;
        if let Some(r) = r.strip_prefix("</") {
            let gt = r.find('>').ok_or(TRUNCATED)?;
            let (name, r) = r.split_at_checked(gt).ok_or(TRUNCATED)?;
            if name.trim_end_matches(is_space) != qname {
                return Err(Malformed("an end tag does not match its element"));
            }
            return Ok((el, r.get(1..).ok_or(TRUNCATED)?));
        } else if let Some(r) = r.strip_prefix("<!--") {
            s = past(r, "-->")?;
        } else if let Some(r) = r.strip_prefix("<![CDATA[") {
            let end = r.find("]]>").ok_or(TRUNCATED)?;
            let (data, r) = r.split_at_checked(end).ok_or(TRUNCATED)?;
            el.text.push_str(data);
            s = r.get(3..).ok_or(TRUNCATED)?;
        } else if let Some(r) = r.strip_prefix("<?") {
            s = past(r, "?>")?;
        } else if r.starts_with("<!") {
            return Err(Malformed("a declaration inside an element is not taken"));
        } else {
            let (child, r) = element(r, depth.saturating_add(1), count, max)?;
            el.children.push(child);
            s = r;
        }
    }
}

/// Append character data `s` to `out`, its references decoded: XML's five entities and
/// character references, and nothing else.
fn decode_into(s: &str, out: &mut String) -> Result<(), Malformed> {
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        let (plain, r) = rest.split_at_checked(amp).ok_or(TRUNCATED)?;
        out.push_str(plain);
        let r = r.get(1..).ok_or(TRUNCATED)?;
        let semi = r
            .find(';')
            .filter(|&i| i <= MAX_ENTITY)
            .ok_or(Malformed("an & does not start a reference"))?;
        let (name, r) = r.split_at_checked(semi).ok_or(TRUNCATED)?;
        out.push(match name {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => character(name).ok_or(Malformed(
                "an entity other than lt, gt, amp, quot, apos or a character reference",
            ))?,
        });
        rest = r.get(1..).ok_or(TRUNCATED)?;
    }
    out.push_str(rest);
    Ok(())
}

/// The character a reference `#<decimal>` or `#x<hex>` names, when XML allows it.
fn character(name: &str) -> Option<char> {
    let digits = name.strip_prefix('#')?;
    let (digits, radix) = match digits.strip_prefix('x') {
        Some(hex) => (hex, 16),
        None => (digits, 10),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let c = char::from_u32(u32::from_str_radix(digits, radix).ok()?)?;
    (matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && !matches!(c, '\u{fffe}' | '\u{ffff}')))
        .then_some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delete(objects: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{objects}</Delete>"
        )
    }

    fn keys(el: &Element) -> Vec<String> {
        el.all("Object")
            .filter_map(|o| o.one("Key").ok().flatten())
            .map(|k| k.text.clone())
            .collect()
    }

    #[track_caller]
    fn malformed(input: &str) -> &'static str {
        match parse(input.as_bytes(), 100) {
            Err(Malformed(why)) => why,
            Ok(el) => panic!("took {input:?} as {el:?}"),
        }
    }

    #[test]
    fn a_delete_document_reads_as_sdks_write_it() {
        let doc = delete(
            "<Object><Key>a/b</Key></Object>\n  <Object><Key>c</Key>\
             <VersionId>null</VersionId></Object><Quiet>true</Quiet>",
        );
        let el = parse(doc.as_bytes(), 100).unwrap();
        assert_eq!(el.name, "Delete");
        assert_eq!(keys(&el), ["a/b", "c"]);
        assert_eq!(el.one("Quiet").unwrap().unwrap().text, "true");
        let versioned: Vec<_> = el.all("Object").map(|o| o.one("VersionId")).collect();
        assert_eq!(versioned[0], Ok(None));
        assert_eq!(versioned[1].as_ref().unwrap().unwrap().text, "null");
        // Reordered, prefixed, unknown elements and attributes among them.
        let doc = "<s3:Delete xmlns:s3=\"urn:x\" a='1'><s3:Quiet>false</s3:Quiet>\
                   <Unknown><Deeper x=\"&amp;\">t</Deeper></Unknown>\
                   <s3:Object><Other/><s3:Key>k</s3:Key></s3:Object></s3:Delete>";
        let el = parse(doc.as_bytes(), 100).unwrap();
        assert_eq!((el.name.as_str(), keys(&el)), ("Delete", vec!["k".into()]));
        assert_eq!(el.one("Quiet").unwrap().unwrap().text, "false");
        // A missing field is the caller's to notice.
        let el = parse(delete("<Object></Object>").as_bytes(), 100).unwrap();
        assert_eq!(el.all("Object").count(), 1);
        assert!(keys(&el).is_empty());
        assert_eq!(
            parse(b"<a><b/><b/></a>", 10).unwrap().one("b"),
            Err(Malformed("an element that is given once is given twice"))
        );
    }

    #[test]
    fn text_is_decoded_from_entities_cdata_and_references_only() {
        let el = parse(
            "<K>&lt;a&gt; &amp; &quot;&apos; &#65;&#x42;<!-- no --><![CDATA[<&x;>]]>\u{e9}</K>"
                .as_bytes(),
            10,
        )
        .unwrap();
        assert_eq!(el.text, "<a> & \"' AB<&x;>\u{e9}");
        for bad in [
            "<K>&nbsp;</K>",
            "<K>&xxe;</K>",
            "<K>&</K>",
            "<K>& amp;</K>",
            "<K>&#;</K>",
            "<K>&#x;</K>",
            "<K>&#0;</K>",
            "<K>&#xD800;</K>",
            "<K>&#x110000;</K>",
            "<K>&#1;</K>",
            "<K>&#x1B;</K>",
            "<K>&#xFFFE;</K>",
            "<K>&#12a;</K>",
            "<K>&averyverylongname;</K>",
            "<K a=\"&nbsp;\"/>",
        ] {
            assert!(
                malformed(bad).contains("&") || malformed(bad).contains("entity"),
                "{bad}"
            );
        }
    }

    #[test]
    fn declarations_and_what_is_not_a_document_are_refused() {
        let xxe = "<?xml version=\"1.0\"?><!DOCTYPE d [<!ENTITY x SYSTEM \"file:///etc/passwd\">\
                   ]><Delete><Object><Key>&x;</Key></Object></Delete>";
        assert!(malformed(xxe).contains("document type"));
        assert!(malformed("<a><!DOCTYPE x></a>").contains("declaration"));
        for (bad, why) in [
            ("", "no element"),
            ("  <!-- only -->  ", "no element"),
            ("text", "element was expected"),
            ("<a></b>", "end tag"),
            ("<a><b></a></b>", "end tag"),
            ("<a/><b/>", "past its element"),
            ("<a/>text", "past its element"),
            ("<a x></a>", "ends inside"),
            ("<a x=1></a>", "quoted"),
            ("<a x=\"<\"></a>", "holds a <"),
            ("<a x=\"1\"y=\"2\"></a>", "white space"),
            ("< a/>", "name"),
            ("<:/>", "name"),
            ("<a>\u{0}", "does not allow"),
            ("<a>x\u{1}</a>", "does not allow"),
            ("<a><![CDATA[\u{1b}]]></a>", "does not allow"),
            ("<a>\u{ffff}</a>", "does not allow"),
            ("<a x=\"\u{8}\"/>", "does not allow"),
        ] {
            assert!(malformed(bad).contains(why), "{bad}: {}", malformed(bad));
        }
        assert!(parse(&[0xff, b'<', b'a', b'/', b'>'], 1).is_err());
        // A comment and processing instructions anywhere around and inside.
        let el = parse(
            b"\xef\xbb\xbf<?xml version='1.0'?><!-- c --><a><?pi x?>t<!-- c --></a><!-- c -->\n",
            1,
        )
        .unwrap();
        assert_eq!((el.name.as_str(), el.text.as_str()), ("a", "t"));
    }

    #[test]
    fn depth_and_count_are_bounded() {
        let nested = |n: usize| format!("{}{}", "<a>".repeat(n), "</a>".repeat(n));
        assert!(parse(nested(MAX_DEPTH).as_bytes(), 100).is_ok());
        assert!(malformed(&nested(MAX_DEPTH + 1)).contains("deep"));
        let deep = nested(100_000);
        assert!(parse(deep.as_bytes(), usize::MAX).is_err());
        let wide = |n: usize| format!("<a>{}</a>", "<b/>".repeat(n));
        assert!(parse(wide(99).as_bytes(), 100).is_ok());
        assert!(malformed(&wide(100)).contains("too many"));
        // Nested garbage.
        assert!(parse(b"<a><b><c><<</c></b></a>", 100).is_err());
        assert!(parse(b"<a><b>]]></b><![CDATA[</a>", 100).is_err());
    }

    #[test]
    fn every_truncation_and_mutation_of_a_document_is_answered() {
        let doc = delete(
            "<Object><Key>a&amp;b</Key><VersionId>v</VersionId></Object><!-- x -->\
             <Object><Key><![CDATA[c]]></Key></Object><Quiet>true</Quiet>",
        );
        let bytes = doc.as_bytes();
        let whole = parse(bytes, 100).unwrap();
        assert_eq!(keys(&whole), ["a&b", "c"]);
        for n in 0..bytes.len() {
            assert!(parse(&bytes[..n], 100).is_err(), "{n} bytes");
        }
        // A deterministic run of random single and double byte mutations.
        let mut seed: u64 = 0x5eed_0f5c;
        let mut next = || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) as usize
        };
        let alphabet = b"<>/&;#x!-[]?=\"' aKZ\x00\xff\xc3";
        for _ in 0..20_000 {
            let mut m = bytes.to_vec();
            for _ in 0..1 + next() % 2 {
                let at = next() % m.len();
                m[at] = alphabet[next() % alphabet.len()];
            }
            let _ = parse(&m, 100);
        }
    }
}
