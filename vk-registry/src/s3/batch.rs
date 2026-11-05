//! DeleteObjects: `POST /s3/<bucket>?delete`, up to a thousand keys in one `Delete` document,
//! each deleted as DeleteObject deletes it and answered on its own in the `DeleteResult`. The
//! namespace lock is taken once for the whole batch. The document is bounded (1 MiB, 1000
//! keys) and checked against the digests its request names before a key is touched.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::object::{Deleted, admitted, check_body, delete_one, unwritable_message};
use super::xml::scan::{self, Malformed};
use super::{Ctx, path, read_small, xml};
use crate::files::{self, Unwritable};
use crate::{Authz, Body, ServerState, Store, accounts};

/// Longest `Delete` document taken.
const MAX_DOCUMENT: usize = 1 << 20;

/// Most keys one request deletes: S3's own bound.
const MAX_KEYS: usize = 1000;

/// Most elements a `Delete` document may hold: an `Object` and the five fields S3 defines in
/// it, for each key, and a few more around them.
const MAX_ELEMENTS: usize = 6 * MAX_KEYS + 16;

/// One key a `Delete` document names.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    key: String,
    /// whether it names a version, which this registry does not keep
    versioned: bool,
}

/// What a `Delete` document asks.
#[derive(Debug, PartialEq, Eq)]
struct Asked {
    quiet: bool,
    entries: Vec<Entry>,
}

/// The `Delete` document `body` holds.
fn document(body: &[u8]) -> Result<Asked, Malformed> {
    let root = scan::parse(body, MAX_ELEMENTS)?;
    if root.name != "Delete" {
        return Err(Malformed("the document is not a Delete"));
    }
    let quiet = match root.one("Quiet")?.map(|q| q.text.trim()) {
        None => false,
        Some(q) if q.eq_ignore_ascii_case("true") => true,
        Some(q) if q.eq_ignore_ascii_case("false") => false,
        Some(_) => return Err(Malformed("Quiet is true or false")),
    };
    let mut entries = Vec::new();
    for o in root.all("Object") {
        let key = o
            .one("Key")?
            .ok_or(Malformed("each Object names its Key"))?;
        entries.push(Entry {
            key: key.text.clone(),
            versioned: o.one("VersionId")?.is_some(),
        });
    }
    if entries.is_empty() {
        return Err(Malformed("a Delete names at least one Object"));
    }
    if entries.len() > MAX_KEYS {
        return Err(Malformed("a Delete names at most 1000 objects"));
    }
    Ok(Asked { quiet, entries })
}

/// Why one key was not deleted: an S3 error code and a message.
type KeyError = (&'static str, &'static str);

/// Delete `key` of `bucket` for this caller, the namespace held: as DeleteObject would, a
/// key with no object counting as deleted.
fn delete_key(
    store: &Store,
    namespace: &files::Namespace,
    authz: &Authz<'_>,
    bucket: &str,
    key: &str,
) -> Result<std::result::Result<(), KeyError>> {
    // A key here is text, not a URL: no escape is decoded, and no key holds a `%`.
    if key.contains('%') {
        return Ok(Err((
            "InvalidArgument",
            "a key's components are runs of A-Z a-z 0-9 . _ - only",
        )));
    }
    let segs = match path::parse(&format!("/s3/{bucket}/{key}")) {
        Ok(path::Target::Object { segs, .. }) => segs,
        Ok(_) => return Ok(Err(("InvalidArgument", "the key is empty"))),
        Err(why) => return Ok(Err((why.code, why.message))),
    };
    let denied = ("AccessDenied", "the credential may not delete this key");
    if !admitted(authz, accounts::Action::Write, &segs) {
        return Ok(Err(denied));
    }
    Ok(match delete_one(store, namespace, authz, &segs)? {
        Deleted::Gone => Ok(()),
        Deleted::Denied => Err(denied),
        Deleted::Foreign => Err(("OperationAborted", unwritable_message(Unwritable::Foreign))),
    })
}

/// `POST /s3/<bucket>?delete`: each key of the document deleted, or the reason it was not,
/// in the order asked. A bucket that does not exist holds none of the keys, which all count
/// as deleted, as DeleteObject answers for each.
pub(super) async fn delete(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: String,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    let (parts, body) = req.into_parts();
    let too_long = ctx.error(
        StatusCode::BAD_REQUEST,
        "MalformedXML",
        "a Delete document is at most 1 MiB",
    );
    let body = match read_small(body, MAX_DOCUMENT, too_long, ctx).await? {
        Ok(body) => body,
        Err(resp) => return Ok(resp),
    };
    if let Err((status, code, message)) = check_body(&parts.headers, &body) {
        return Ok(ctx.error(status, code, message));
    }
    let asked = match document(&body) {
        Ok(asked) => asked,
        Err(Malformed(why)) => return Ok(ctx.error(StatusCode::BAD_REQUEST, "MalformedXML", why)),
    };
    crate::dav::blocking(state, authz, move |store, authz| {
        let namespace = files::namespace(store)?;
        let mut out = String::new();
        for entry in &asked.entries {
            let outcome = if entry.versioned {
                Err((
                    "NotImplemented",
                    "this registry keeps no versions: a key is deleted without a VersionId",
                ))
            } else {
                delete_key(store, &namespace, authz, &bucket, &entry.key)?
            };
            match outcome {
                Ok(()) if asked.quiet => {}
                Ok(()) => out.push_str(&format!(
                    "<Deleted>{}</Deleted>",
                    xml::element("Key", &entry.key)
                )),
                Err((code, message)) => out.push_str(&format!(
                    "<Error>{}{}{}</Error>",
                    xml::element("Key", &entry.key),
                    xml::element("Code", code),
                    xml::element("Message", message)
                )),
            }
        }
        Ok(xml::document("DeleteResult", &out))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(objects: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{objects}</Delete>"
        )
        .into_bytes()
    }

    fn entry(key: &str, versioned: bool) -> Entry {
        Entry {
            key: key.into(),
            versioned,
        }
    }

    #[test]
    fn a_delete_names_its_keys_versions_and_quietness() {
        let asked = document(&body(
            "<Quiet>true</Quiet><Object><Key>a/b</Key></Object>\
             <Object><VersionId>v</VersionId><Key>c</Key><ETag>\"x\"</ETag></Object>",
        ))
        .unwrap();
        assert_eq!(
            asked,
            Asked {
                quiet: true,
                entries: vec![entry("a/b", false), entry("c", true)],
            }
        );
        let asked = document(&body("<Object><Key>k</Key></Object><Quiet>False</Quiet>")).unwrap();
        assert!(!asked.quiet);
        // Text is taken as it is, to be judged as a key.
        let asked = document(&body("<Object><Key> a&amp;b </Key></Object>")).unwrap();
        assert_eq!(asked.entries, [entry(" a&b ", false)]);
    }

    #[test]
    fn a_delete_that_is_not_one_is_malformed() {
        let max = (0..MAX_KEYS)
            .map(|i| format!("<Object><Key>k{i}</Key></Object>"))
            .collect::<String>();
        assert_eq!(document(&body(&max)).unwrap().entries.len(), MAX_KEYS);
        let over = format!("{max}<Object><Key>one-more</Key></Object>");
        assert!(document(&body(&over)).is_err());
        for bad in [
            body(""),
            body("<Quiet>true</Quiet>"),
            body("<Object></Object>"),
            body("<Object><Key>a</Key><Key>b</Key></Object>"),
            body("<Object><Key>a</Key></Object><Quiet>yes</Quiet>"),
            body("<Object><Key>a</Key></Object><Quiet>true</Quiet><Quiet>true</Quiet>"),
            body("<Object><Key>&ent;</Key></Object>"),
            b"<Other><Object><Key>a</Key></Object></Other>".to_vec(),
            b"".to_vec(),
        ] {
            assert!(document(&bad).is_err(), "{}", String::from_utf8_lossy(&bad));
        }
        let elements = (0..MAX_ELEMENTS).map(|_| "<x/>").collect::<String>();
        assert!(document(&body(&elements)).is_err());
    }
}
