//! DeleteObjects: `POST /s3/<bucket>?delete`, up to a thousand keys in one `Delete` document,
//! each deleted as DeleteObject deletes it and answered on its own in the `DeleteResult`. The
//! namespace lock is taken once for the whole batch. The document is bounded (1 MiB, 1000
//! keys) and checked against the digests its request names before a key is touched.
//!
//! An `<Object>` may carry conditions on the object it names, as DeleteObject's headers do:
//! its `ETag`, `LastModifiedTime` and `Size`, checked under that lock against the object the
//! key holds, which is deleted only when they all hold (else `PreconditionFailed`, or
//! `NoSuchKey` when there is no object), the batch going on.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::conditional::{self, DeleteConditions};
use super::object::{Deleted, admitted, check_body, delete_one, unwritable_message};
use super::xml::scan::{self, Malformed};
use super::{Ctx, NULL_VERSION, path, read_small, xml};
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
#[derive(Debug, Default, PartialEq, Eq)]
struct Entry {
    key: String,
    /// the `VersionId` it names, echoed in its answer; one other than the object's one,
    /// [`NULL_VERSION`], is one this registry does not keep
    version: Option<String>,
    /// what must hold of the object for it to be deleted
    conditions: DeleteConditions,
}

/// What a `Delete` document asks.
#[derive(Debug, PartialEq, Eq)]
struct Asked {
    quiet: bool,
    entries: Vec<Entry>,
}

/// Why a `Delete` document is refused whole.
#[derive(Debug, PartialEq, Eq)]
enum Refused {
    /// 400 `MalformedXML`
    Malformed(&'static str),
    /// 400 `InvalidRequest`: the first `LastModifiedTime` in the document that is not a
    /// date, as it was sent
    Date(String),
}

impl From<Malformed> for Refused {
    fn from(Malformed(why): Malformed) -> Self {
        Refused::Malformed(why)
    }
}

/// The `Delete` document `body` holds. An empty `LastModifiedTime` makes it malformed, which
/// S3 reports ahead of one that is not a date.
fn document(body: &[u8]) -> Result<Asked, Refused> {
    let root = scan::parse(body, MAX_ELEMENTS)?;
    if root.name != "Delete" {
        return Err(Malformed("the document is not a Delete").into());
    }
    let quiet = match root.one("Quiet")?.map(|q| q.text.trim()) {
        None => false,
        Some(q) if q.eq_ignore_ascii_case("true") => true,
        Some(q) if q.eq_ignore_ascii_case("false") => false,
        Some(_) => return Err(Malformed("Quiet is true or false").into()),
    };
    let mut entries = Vec::new();
    let mut bad_date = None;
    for o in root.all("Object") {
        let key = o
            .one("Key")?
            .ok_or(Malformed("each Object names its Key"))?;
        let modified = match o.one("LastModifiedTime")? {
            None => None,
            Some(t) if t.text.trim().is_empty() => {
                return Err(Malformed("a LastModifiedTime is a date").into());
            }
            Some(t) => match conditional::parse_time(&t.text) {
                Some(time) => Some(conditional::whole_seconds(time)),
                None => {
                    bad_date.get_or_insert_with(|| t.text.clone());
                    None
                }
            },
        };
        let size = match o.one("Size")? {
            None => None,
            Some(s) => Some(
                conditional::parse_size(&s.text).ok_or(Malformed("a Size is a count of bytes"))?,
            ),
        };
        entries.push(Entry {
            key: key.text.clone(),
            version: o.one("VersionId")?.map(|v| v.text.clone()),
            conditions: DeleteConditions {
                etag: o.one("ETag")?.map(|e| e.text.clone()),
                modified,
                size,
            },
        });
    }
    if let Some(date) = bad_date {
        return Err(Refused::Date(date));
    }
    if entries.is_empty() {
        return Err(Malformed("a Delete names at least one Object").into());
    }
    if entries.len() > MAX_KEYS {
        return Err(Malformed("a Delete names at most 1000 objects").into());
    }
    Ok(Asked { quiet, entries })
}

/// Why one key was not deleted: an S3 error code and a message.
type KeyError = (&'static str, &'static str);

/// Delete `key` of `bucket` for this caller when `conditions` hold of its object, the
/// namespace held: as DeleteObject would, a key with no object counting as deleted when no
/// condition is asked.
fn delete_key(
    store: &Store,
    namespace: &files::Namespace,
    authz: &Authz<'_>,
    bucket: &str,
    key: &str,
    conditions: &DeleteConditions,
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
    Ok(
        match delete_one(store, namespace, authz, &segs, conditions)? {
            Deleted::Gone => Ok(()),
            Deleted::Denied => Err(denied),
            Deleted::Foreign => Err(("OperationAborted", unwritable_message(Unwritable::Foreign))),
            Deleted::Absent => Err(("NoSuchKey", "The specified key does not exist.")),
            Deleted::Failed => Err(("PreconditionFailed", conditional::PRECONDITION_FAILED)),
        },
    )
}

/// Why `entry` is refused before its key is looked at: a version this registry does not
/// keep, an empty `ETag`, or a condition on a version, which S3 applies to the current
/// object only.
fn refused(entry: &Entry) -> Option<KeyError> {
    let conditions = &entry.conditions;
    if conditions
        .etag
        .as_deref()
        .is_some_and(|e| e.trim().is_empty())
    {
        return Some((
            "InvalidArgument",
            "The value provided for the ETag field cannot be empty for this API.",
        ));
    }
    match entry.version.as_deref() {
        Some(_) if !conditions.is_empty() => Some((
            "NotImplemented",
            "A form field you provided implies functionality that is not implemented",
        )),
        Some(v) if v != NULL_VERSION => Some((
            "NotImplemented",
            "this registry keeps no versions: a key's one VersionId is null",
        )),
        _ => None,
    }
}

/// `POST /s3/<bucket>?delete`: each key of the document deleted, or the reason it was not,
/// in the order asked, a key the store fails on included. A bucket that does not exist holds none of the keys, which all count
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
        Err(Refused::Malformed(why)) => {
            return Ok(ctx.error(StatusCode::BAD_REQUEST, "MalformedXML", why));
        }
        Err(Refused::Date(date)) => {
            let message = format!("Invalid value for date attribute: {date}");
            return Ok(ctx.error(StatusCode::BAD_REQUEST, "InvalidRequest", &message));
        }
    };
    let id = ctx.id.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        let namespace = files::namespace(store)?;
        let mut out = String::new();
        for entry in &asked.entries {
            let outcome = if let Some(why) = refused(entry) {
                Err(why)
            } else {
                // A key the store fails on is that key's error; the batch goes on.
                let conditions = &entry.conditions;
                delete_key(store, &namespace, authz, &bucket, &entry.key, conditions)
                    .unwrap_or_else(|e| {
                        eprintln!(
                            "vk-registry: S3 request {id} could not delete {:?}: {e:#}",
                            entry.key
                        );
                        Err((
                            "InternalError",
                            "the server could not delete this key; its log names this request id",
                        ))
                    })
            };
            let version = entry
                .version
                .as_deref()
                .map(|v| xml::element("VersionId", v))
                .unwrap_or_default();
            match outcome {
                Ok(()) if asked.quiet => {}
                Ok(()) => out.push_str(&format!(
                    "<Deleted>{}{version}</Deleted>",
                    xml::element("Key", &entry.key)
                )),
                Err((code, message)) => out.push_str(&format!(
                    "<Error>{}{version}{}{}</Error>",
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

    fn entry(key: &str, version: Option<&str>) -> Entry {
        Entry {
            key: key.into(),
            version: version.map(str::to_string),
            ..Entry::default()
        }
    }

    #[test]
    fn a_delete_names_its_keys_versions_and_quietness() {
        let asked = document(&body(
            "<Quiet>true</Quiet><Object><Key>a/b</Key></Object>\
             <Object><VersionId>v</VersionId><Key>c</Key></Object>\
             <Object><Key>d</Key><VersionId>null</VersionId></Object>",
        ))
        .unwrap();
        assert_eq!(
            asked,
            Asked {
                quiet: true,
                entries: vec![
                    entry("a/b", None),
                    entry("c", Some("v")),
                    entry("d", Some("null"))
                ],
            }
        );
        let asked = document(&body("<Object><Key>k</Key></Object><Quiet>False</Quiet>")).unwrap();
        assert!(!asked.quiet);
        // Text is taken as it is, to be judged as a key.
        let asked = document(&body("<Object><Key> a&amp;b </Key></Object>")).unwrap();
        assert_eq!(asked.entries, [entry(" a&b ", None)]);
    }

    #[test]
    fn an_object_carries_its_conditions() {
        let asked = document(&body(
            "<Object><Key>a</Key><ETag>\"x\"</ETag><Size>13</Size>\
             <LastModifiedTime>Sun, 06 Nov 1994 08:49:37 GMT</LastModifiedTime></Object>\
             <Object><Key>b</Key><LastModifiedTime> Sun, 06 Nov 1994 10:49:37 +0200 \
             </LastModifiedTime><ETag></ETag></Object>",
        ))
        .unwrap();
        let conditions = |etag: &str, size| DeleteConditions {
            etag: Some(etag.into()),
            modified: Some(784_111_777),
            size,
        };
        assert_eq!(asked.entries[0].conditions, conditions("\"x\"", Some(13)));
        assert_eq!(asked.entries[1].conditions, conditions("", None));
        // An empty ETag is that key's error; a condition on a version is not served.
        assert_eq!(refused(&asked.entries[1]).unwrap().0, "InvalidArgument");
        assert!(refused(&asked.entries[0]).is_none());
        let versioned = Entry {
            version: Some("null".into()),
            ..asked.entries.into_iter().next().unwrap()
        };
        assert_eq!(refused(&versioned).unwrap().0, "NotImplemented");
        assert!(refused(&entry("k", Some("null"))).is_none());
        assert_eq!(refused(&entry("k", Some("v"))).unwrap().0, "NotImplemented");
    }

    #[test]
    fn a_condition_that_is_not_one_refuses_the_document() {
        let one = |inner: &str| document(&body(&format!("<Object><Key>k</Key>{inner}</Object>")));
        assert_eq!(
            one("<LastModifiedTime>2024-01-01T00:00:00Z</LastModifiedTime>"),
            Err(Refused::Date("2024-01-01T00:00:00Z".into()))
        );
        assert_eq!(
            one("<LastModifiedTime>  not a date  </LastModifiedTime>"),
            Err(Refused::Date("  not a date  ".into()))
        );
        for bad in [
            "<LastModifiedTime></LastModifiedTime>",
            "<LastModifiedTime>   </LastModifiedTime>",
            "<Size>-1</Size>",
            "<Size>1.0</Size>",
            "<Size></Size>",
            "<ETag>a</ETag><ETag>b</ETag>",
        ] {
            assert!(matches!(one(bad), Err(Refused::Malformed(_))), "{bad}");
        }
        // The first date that is not one is named; an empty one outranks it.
        let two = |a: &str, b: &str| {
            document(&body(&format!(
                "<Object><Key>k</Key><LastModifiedTime>{a}</LastModifiedTime></Object>\
                 <Object><Key>k</Key><LastModifiedTime>{b}</LastModifiedTime></Object>"
            )))
        };
        assert_eq!(two("first", "second"), Err(Refused::Date("first".into())));
        assert!(matches!(two("not a date", ""), Err(Refused::Malformed(_))));
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
            // What an answer echoing the key could not write.
            body("<Object><Key>a&#1;</Key></Object>"),
            body("<Object><Key>a\u{1}</Key></Object>"),
            body("<Object><Key><![CDATA[a\u{1}]]></Key></Object>"),
            b"<Other><Object><Key>a</Key></Object></Other>".to_vec(),
            b"".to_vec(),
        ] {
            assert!(document(&bad).is_err(), "{}", String::from_utf8_lossy(&bad));
        }
        let elements = (0..MAX_ELEMENTS).map(|_| "<x/>").collect::<String>();
        assert!(document(&body(&elements)).is_err());
    }
}
