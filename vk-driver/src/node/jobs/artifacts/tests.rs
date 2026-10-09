//! The upload and download expectations of gitlab-runner v19.5's
//! `network/gitlab_test.go` (`checkTestArtifactsUploadHandlerContent`, `TestArtifactsUpload`,
//! `TestArtifactsDownload`), against a GitLab played by a socket (MIT; see
//! [`crate::node::jobs::mask`] for the notice).

use vk_hub_proto::job::When;

use super::*;
use crate::node::jobs::testkit::{Fixture, answer, gitlab};

fn artifact() -> ArtifactSpec {
    ArtifactSpec {
        name: "artifacts".into(),
        untracked: false,
        paths: vec!["target/report".into()],
        exclude: vec![],
        when: When::OnSuccess,
        artifact_type: "archive".into(),
        format: ArtifactFormat::Zip,
        expire_in: "7 days".into(),
    }
}

fn archive_file(f: &Fixture) -> std::path::PathBuf {
    let path = f.dir.join("archive.zip");
    std::fs::write(&path, b"PK\x05\x06 the archive").unwrap();
    path
}

#[tokio::test]
async fn an_upload_is_the_multipart_post_gitlab_expects() {
    let (url, seen) = gitlab(vec![answer("201 Created", &[], b"")]).await;
    let f = Fixture::new("upload", &url);
    let ctx = f.ctx();
    let state = send(&ctx, &client(&ctx).unwrap(), &artifact(), &archive_file(&f))
        .await
        .unwrap();
    assert_eq!(state, UploadState::Uploaded);
    let reqs = seen.lock().unwrap().clone();
    assert_eq!(reqs.len(), 1);
    let req = &reqs[0];
    assert_eq!(
        req.line,
        "POST /api/v4/jobs/4242/artifacts?artifact_format=zip&artifact_type=archive\
         &expire_in=7+days HTTP/1.1"
    );
    assert_eq!(req.header("job-token"), Some("glcbt-64_jobtoken123"));
    let ct = req.header("content-type").unwrap();
    let boundary = ct.strip_prefix("multipart/form-data; boundary=").unwrap();
    let body = String::from_utf8_lossy(&req.body);
    assert!(body.starts_with(&format!("--{boundary}\r\n")), "{body}");
    assert!(
        body.contains("Content-Disposition: form-data; name=\"file\"; filename=\"artifacts.zip\""),
        "{body}"
    );
    assert!(
        body.contains("\r\n\r\nPK\x05\x06 the archive\r\n"),
        "{body}"
    );
    assert!(body.ends_with(&format!("\r\n--{boundary}--\r\n")), "{body}");
    assert!(
        f.output()
            .contains("Uploading artifacts as \"archive\" to coordinator... 201 Created  id=4242 token=64_jobtok"),
        "{}",
        f.output()
    );
}

#[tokio::test]
async fn a_too_large_upload_is_not_retried() {
    let (url, seen) = gitlab(vec![answer("413 Payload Too Large", &[], b"")]).await;
    let f = Fixture::new("toolarge", &url);
    let ctx = f.ctx();
    let state = send(&ctx, &client(&ctx).unwrap(), &artifact(), &archive_file(&f))
        .await
        .unwrap();
    assert_eq!(state, UploadState::TooLarge);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_redirected_upload_is_posted_again_where_it_was_sent() {
    let (there, seen_there) = gitlab(vec![answer("201 Created", &[], b"")]).await;
    let location = format!("{there}/elsewhere?ignored=1");
    let (url, seen) = gitlab(vec![answer(
        "307 Temporary Redirect",
        &[("Location", &location)],
        b"",
    )])
    .await;
    let f = Fixture::new("redirect", &url);
    let ctx = f.ctx();
    let state = send(&ctx, &client(&ctx).unwrap(), &artifact(), &archive_file(&f))
        .await
        .unwrap();
    assert_eq!(state, UploadState::Uploaded);
    assert_eq!(seen.lock().unwrap().len(), 1);
    let again = seen_there.lock().unwrap().clone();
    assert!(
        again[0]
            .line
            .starts_with("POST /api/v4/jobs/4242/artifacts?"),
        "{}",
        again[0].line
    );
    assert!(!again[0].body.is_empty());
    // Another origin than GitLab's: the job's token stays behind.
    assert_eq!(
        seen.lock().unwrap()[0].header("job-token"),
        Some("glcbt-64_jobtoken123")
    );
    assert_eq!(again[0].header("job-token"), None);
}

#[test]
fn a_redirect_keeps_the_token_home_and_never_downgrades() {
    let home = reqwest::Url::parse("https://gl.example/api/v4").unwrap();
    assert_eq!(
        redirected(&home, "https://gl.example:443/x?y=1").unwrap(),
        ("https://gl.example/api/v4".to_string(), true)
    );
    assert_eq!(
        redirected(&home, "https://store.example:8443/x/y?z=1").unwrap(),
        ("https://store.example:8443/api/v4".to_string(), false)
    );
    assert_eq!(
        redirected(&home, "/elsewhere").unwrap(),
        ("https://gl.example/api/v4".to_string(), true)
    );
    let err = redirected(&home, "http://gl.example/x").unwrap_err();
    assert!(err.to_string().contains("from https"), "{err}");
    let plain = reqwest::Url::parse("http://gl.example/api/v4").unwrap();
    assert_eq!(
        redirected(&plain, "https://gl.example/x").unwrap(),
        ("https://gl.example/api/v4".to_string(), false)
    );
}

#[tokio::test]
async fn an_unavailable_gitlab_is_asked_again() {
    let (url, seen) = gitlab(vec![
        answer("503 Service Unavailable", &[("Retry-After", "0")], b""),
        answer("201 Created", &[], b""),
    ])
    .await;
    let f = Fixture::new("unavailable", &url);
    let ctx = f.ctx();
    let state = send(&ctx, &client(&ctx).unwrap(), &artifact(), &archive_file(&f))
        .await
        .unwrap();
    assert_eq!(state, UploadState::Uploaded);
    assert_eq!(seen.lock().unwrap().len(), 2);
}

fn dependency() -> Dependency {
    Dependency {
        id: 4241,
        token: "glcbt-64_deptoken".into(),
        name: "build".into(),
        artifacts_file: None,
    }
}

#[tokio::test]
async fn a_download_follows_redirects_without_taking_the_token_elsewhere() {
    let (store, seen_store) = gitlab(vec![answer("200 OK", &[], b"the zip")]).await;
    let location = format!("{store}/bucket/artifacts.zip?X-Amz-Signature=x");
    let (url, seen) = gitlab(vec![answer("302 Found", &[("Location", &location)], b"")]).await;
    let f = Fixture::new("download", &url);
    let ctx = f.ctx();
    let dest = f.dir.join("dep.zip");
    if let Err(Fetch::Final(e) | Fetch::Retry(e)) =
        fetch(&ctx, &client(&ctx).unwrap(), &dependency(), &dest).await
    {
        panic!("{e:#}");
    }
    assert_eq!(std::fs::read(&dest).unwrap(), b"the zip");
    let first = seen.lock().unwrap()[0].clone();
    assert_eq!(first.line, "GET /api/v4/jobs/4241/artifacts HTTP/1.1");
    assert_eq!(first.header("job-token"), Some("glcbt-64_deptoken"));
    let second = seen_store.lock().unwrap()[0].clone();
    assert!(second.line.starts_with("GET /bucket/artifacts.zip?"));
    assert_eq!(second.header("job-token"), None);
    assert!(
        f.output()
            .contains("Downloading artifacts from coordinator... ok")
    );
}

#[tokio::test]
async fn a_missing_download_is_final() {
    let (url, seen) = gitlab(vec![answer("404 Not Found", &[], b"")]).await;
    let f = Fixture::new("missing", &url);
    let ctx = f.ctx();
    let out = fetch(
        &ctx,
        &client(&ctx).unwrap(),
        &dependency(),
        &f.dir.join("x"),
    )
    .await;
    assert!(matches!(out, Err(Fetch::Final(_))));
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(f.output().contains("not found"));
}

#[test]
fn the_upload_url_carries_the_query_gitlab_reads() {
    let mut a = artifact();
    a.expire_in.clear();
    a.format = ArtifactFormat::Gzip;
    a.artifact_type = "junit".into();
    assert_eq!(
        upload_url("https://gl.example/api/v4", 7, &a),
        "https://gl.example/api/v4/jobs/7/artifacts?artifact_format=gzip&artifact_type=junit"
    );
    assert_eq!(query_escape("1 week&a=b"), "1+week%26a%3Db");
}

#[test]
fn archive_names_follow_the_uploader() {
    assert_eq!(
        artifact_filename("artifacts", ArtifactFormat::Zip),
        "artifacts.zip"
    );
    assert_eq!(artifact_filename("", ArtifactFormat::Zip), "default.zip");
    assert_eq!(
        artifact_filename("a/junit", ArtifactFormat::Gzip),
        "junit.gz"
    );
    assert_eq!(
        artifact_filename("report.json", ArtifactFormat::Raw),
        "report.json"
    );
    let (head, tail) = multipart("B", "we\"ird.zip");
    assert_eq!(
        String::from_utf8(head).unwrap(),
        "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"we\\\"ird.zip\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n"
    );
    assert_eq!(tail, b"\r\n--B--\r\n");
}

#[test]
fn tokens_are_shortened_as_gitlab_runner_logs_them() {
    assert_eq!(short_token("glcbt-64_abcdefghijk"), "64_abcdef");
    assert_eq!(short_token("acme-glcbt-xyz"), "xyz");
    assert_eq!(short_token("_abcdefghij"), "r_abcdefg");
}

#[tokio::test]
async fn an_artifact_selecting_nothing_or_not_due_is_skipped() {
    let f = Fixture::new("skipped", "https://gl.example");
    let mut f = f;
    f.job.artifacts = vec![
        ArtifactSpec {
            paths: vec![],
            ..artifact()
        },
        ArtifactSpec {
            when: When::OnFailure,
            ..artifact()
        },
    ];
    let ctx = f.ctx();
    assert!(!upload_applies(&ctx, true));
    let (outcomes, out) = upload(&ctx, true).await;
    assert!(out.is_ok());
    assert!(outcomes.iter().all(|o| o.state == UploadState::Skipped));
}

#[test]
fn a_download_that_is_no_zip_is_refused() {
    let f = Fixture::new("notzip", "https://gl.example");
    let path = f.dir.join("dep.zip");
    std::fs::write(&path, b"\x1f\x8b gzip, not zip").unwrap();
    let err = unzip_to_tar(&path, &mut Vec::new()).unwrap_err();
    assert!(err.to_string().contains("not a zip"), "{err}");
    std::fs::write(&path, b"P").unwrap();
    assert!(unzip_to_tar(&path, &mut Vec::new()).is_err());
}

#[tokio::test]
async fn a_download_past_the_cap_is_refused() {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_STAGED + 1
    );
    let (url, _) = gitlab(vec![head.into_bytes()]).await;
    let f = Fixture::new("toobig", &url);
    let ctx = f.ctx();
    let dest = f.dir.join("x");
    let Err(Fetch::Final(e)) = fetch(&ctx, &client(&ctx).unwrap(), &dependency(), &dest).await
    else {
        panic!("a download past the cap was taken");
    };
    assert!(e.to_string().contains("MiB a job may stage"), "{e}");
    assert!(!dest.exists());
}

/// A tar header block of `kind`, `size` written by `set`, checksummed.
fn tar_block(kind: tar::EntryType, name: &str, set: impl FnOnce(&mut tar::Header)) -> Vec<u8> {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(kind);
    h.set_path(name).unwrap();
    h.set_mode(0o644);
    set(&mut h);
    h.set_cksum();
    h.as_bytes().to_vec()
}

fn padded(mut data: Vec<u8>) -> Vec<u8> {
    data.resize(data.len().div_ceil(512) * 512, 0);
    data
}

/// A GNU long name of `len` bytes after `prefix`, then a file and the end of the archive.
fn long_name_after(prefix: Vec<u8>, size_field: &[u8; 12], len: usize) -> Vec<u8> {
    let mut tar = prefix;
    tar.extend(tar_block(
        tar::EntryType::GNULongName,
        "././@LongLink",
        |h| {
            h.as_old_mut().size = *size_field;
        },
    ));
    tar.extend(padded(vec![b'a'; len]));
    tar.extend(tar_block(tar::EntryType::Regular, "f", |h| h.set_size(0)));
    tar.extend([0u8; 1024]);
    tar
}

/// Whatever the headers claim, the converter reads no more than its bound of them: a
/// header it would otherwise hold whole fails the conversion.
#[test]
fn an_archive_cannot_make_the_converter_hold_a_huge_header() {
    let dir = std::env::temp_dir().join(format!("vk-convert-headers-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let len = 4 << 20;
    // A pax `size=0` makes the file header after it carry no data, whatever its own size.
    let mut pax = tar_block(tar::EntryType::XHeader, "pax", |h| h.set_size(10));
    pax.extend(padded(b"10 size=0\n".to_vec()));
    pax.extend(tar_block(tar::EntryType::Regular, "g", |h| {
        h.set_size(1024)
    }));
    let octal = format!("{len:011o}\0");
    let pax_then_long = long_name_after(pax, octal.as_bytes().try_into().unwrap(), len);
    // A size the counter in the stream would read as 0.
    let plus = format!("+{len:010o}\0");
    let plus_long = long_name_after(Vec::new(), plus.as_bytes().try_into().unwrap(), len);
    for (what, tar) in [("pax size", pax_then_long), ("+ size", plus_long)] {
        for format in [
            ArtifactFormat::Zip,
            ArtifactFormat::Gzip,
            ArtifactFormat::Raw,
        ] {
            let err = convert(&mut tar.as_slice(), &dir.join("out"), format).unwrap_err();
            assert!(
                format!("{err:#}").contains("entry header over"),
                "{what} {format:?}: {err:#}"
            );
        }
    }
    // Within the bound, the same layout converts.
    let small = long_name_after(Vec::new(), b"00000000144\0", 100);
    convert(&mut small.as_slice(), &dir.join("out"), ArtifactFormat::Zip).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
