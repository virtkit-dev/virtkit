//! Kept output, stored zstd-compressed. A packed value starts with its format: [`RAW`], then
//! the bytes as they are, for what zstd would not make smaller; [`PLAIN`], then a zstd frame.
//! Kept output is any bytes, so a hub before packing kept it in a table of its own
//! ([`LEGACY_TAILS`]), read as it is, and packed in the background a bounded step at a time
//! ([`Db::pack_legacy_tails`]): redb reuses the pages it frees, though the file does not
//! shrink.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable};

use super::Db;
use super::jobs::{CACHED_BYTES, JOB_CACHE, JOB_META, JOB_TAIL_LENS, JOB_TAILS, LEGACY_TAILS};

/// The bytes follow as they are.
const RAW: u8 = 0;
/// A zstd frame follows.
const PLAIN: u8 = 1;
/// The zstd level kept output is packed at: higher levels gain a few percent on it, for
/// several times the time.
pub(super) const TAIL_LEVEL: i32 = 1;
/// The most a packed value unpacks to, well past the largest kept output (4 MiB): a frame
/// recording a larger size is refused before anything is allocated, and one recording none
/// gets no more than this.
const MAX_UNPACKED: usize = 16 << 20;

/// About how much legacy kept output one step of [`Db::pack_legacy_tails`] packs, in bytes as
/// read: the step stops once past it, so its write holds at most one end more.
const PACK_BYTES: usize = 8 << 20;

/// `data` packed at zstd `level`, or kept [`RAW`] when that is not smaller.
pub(super) fn pack(data: &[u8], level: i32) -> Result<Vec<u8>> {
    let frame = zstd::bulk::compress(data, level).context("compressing a stored value")?;
    let (format, body) = match frame.len() < data.len() {
        true => (PLAIN, frame.as_slice()),
        false => (RAW, data),
    };
    let mut out = Vec::with_capacity(body.len().saturating_add(1));
    out.push(format);
    out.extend_from_slice(body);
    Ok(out)
}

/// Packed `value` unpacked.
pub(super) fn unpack(value: &[u8]) -> Result<Vec<u8>> {
    match value {
        [RAW, bytes @ ..] => Ok(bytes.to_vec()),
        [PLAIN, frame @ ..] => {
            zstd::bulk::decompress(frame, MAX_UNPACKED).context("decompressing a stored value")
        }
        [format, ..] => bail!("a stored value of unknown format {format}"),
        [] => bail!("an empty stored value"),
    }
}

impl Db {
    /// Pack up to [`PACK_BYTES`] of the kept output a hub before packing stored
    /// ([`LEGACY_TAILS`]), the cache's count following what they take now: how many ends this
    /// step took off that table, packed or found gone or kept again since, 0 once none is
    /// left. They are read and packed before the write.
    pub fn pack_legacy_tails(&self) -> Result<usize> {
        let mut packed = Vec::new();
        {
            let txn = self.db.begin_read().context("starting a read")?;
            let legacy = txn.open_table(LEGACY_TAILS)?;
            let mut bytes = 0usize;
            for entry in legacy.iter()? {
                if bytes >= PACK_BYTES {
                    break;
                }
                let (id, tail) = entry?;
                bytes = bytes.saturating_add(tail.value().len());
                packed.push((id.value().to_string(), pack(tail.value(), TAIL_LEVEL)?));
            }
        }
        if packed.is_empty() {
            return Ok(0);
        }
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut legacy = txn.open_table(LEGACY_TAILS)?;
            let mut tails = txn.open_table(JOB_TAILS)?;
            let mut lens = txn.open_table(JOB_TAIL_LENS)?;
            let mut meta = txn.open_table(JOB_META)?;
            let mut cached_ids = HashSet::new();
            for entry in txn.open_table(JOB_CACHE)?.iter()? {
                cached_ids.insert(entry?.1.value().to_string());
            }
            let before = meta.get(CACHED_BYTES)?.map_or(0, |g| g.value());
            let mut cached = before;
            for (id, value) in &packed {
                // Dropped since it was read, or kept again packed: nothing to pack.
                if legacy.remove(id.as_str())?.is_none() || tails.get(id.as_str())?.is_some() {
                    continue;
                }
                tails.insert(id.as_str(), value.as_slice())?;
                let len = value.len() as u64;
                let counted = lens.insert(id.as_str(), len)?.map(|g| g.value());
                if let Some(counted) = counted.filter(|_| cached_ids.contains(id)) {
                    cached = cached.saturating_sub(counted).saturating_add(len);
                }
            }
            if cached != before {
                meta.insert(CACHED_BYTES, cached)?;
            }
        }
        txn.commit().context("packing kept job output")?;
        Ok(packed.len())
    }
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::egress::EgressReport;

    use super::*;
    use crate::egress::testing::job;
    use crate::store::jobs::{index_job_cache, order_jobs};

    fn id(n: u64) -> String {
        format!("{n:032x}")
    }

    /// Job `n`, finished and settled, submitted with `spec`.
    fn submit(db: &Db, n: u64, spec: &[u8]) {
        let mut row = job(n, EgressReport::default());
        row.settled_at = row.finished_at;
        let submitted = db.submit_job(&id(n), &row, &id(n), spec, "key gitlab", 1_000);
        assert!(matches!(submitted.unwrap(), crate::store::Submitted::New));
    }

    /// The bytes the output cache counts.
    fn cached(db: &Db) -> u64 {
        let txn = db.db.begin_read().unwrap();
        let meta = txn.open_table(JOB_META).unwrap();
        meta.get(CACHED_BYTES).unwrap().map_or(0, |g| g.value())
    }

    /// Output as a CI job writes it: lines much alike.
    fn log(lines: u64) -> Vec<u8> {
        (0..lines)
            .flat_map(|n| {
                format!("[{n:06}] compiling crate-{} v0.{}.0\n", n % 40, n % 9).into_bytes()
            })
            .collect()
    }

    /// Each format reads back what was packed: what does not compress raw, what does in a
    /// zstd frame; a format unknown is refused.
    #[test]
    fn a_value_reads_back_in_every_format() {
        for data in [&b""[..], b"one\n"] {
            let packed = pack(data, TAIL_LEVEL).unwrap();
            assert_eq!(packed.first(), Some(&RAW));
            assert_eq!(packed.len(), data.len() + 1);
            assert_eq!(unpack(&packed).unwrap(), data);
        }
        let output = log(1000);
        let packed = pack(&output, TAIL_LEVEL).unwrap();
        assert_eq!(packed.first(), Some(&PLAIN));
        assert!(packed.len() * 8 < output.len(), "{}", packed.len());
        assert_eq!(unpack(&packed).unwrap(), output);

        assert!(unpack(b"\x09data").is_err());
        assert!(unpack(b"").is_err());
        // A frame cut short, or not one at all
        assert!(unpack(&packed[..packed.len() / 2]).is_err());
        assert!(unpack(b"\x01\x28\xb5").is_err());
    }

    /// A tail stored packed since the step read it is preserved; its legacy copy is removed
    /// without changing the cache count.
    #[test]
    fn an_end_kept_again_since_it_was_read_is_left_alone() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, b"{}");
        let old = log(1000);
        let new = pack(b"kept again\n", TAIL_LEVEL).unwrap();
        let txn = db.db.begin_write().unwrap();
        {
            let mut legacy = txn.open_table(LEGACY_TAILS).unwrap();
            let mut tails = txn.open_table(JOB_TAILS).unwrap();
            let mut lens = txn.open_table(JOB_TAIL_LENS).unwrap();
            legacy.insert(id(1).as_str(), old.as_slice()).unwrap();
            tails.insert(id(1).as_str(), new.as_slice()).unwrap();
            lens.insert(id(1).as_str(), new.len() as u64).unwrap();
        }
        order_jobs(&txn).unwrap();
        index_job_cache(&txn).unwrap();
        txn.commit().unwrap();
        let before = cached(&db);

        assert_eq!(db.pack_legacy_tails().unwrap(), 1);
        assert_eq!(db.pack_legacy_tails().unwrap(), 0);
        assert_eq!(
            db.job_tail(&id(1)).unwrap().as_deref(),
            Some(&b"kept again\n"[..])
        );
        assert_eq!(cached(&db), before);
    }

    /// Legacy tails read unchanged from their own table and count at their unpacked size.
    /// Packing in steps updates their stored lengths without changing the output.
    #[test]
    fn what_a_hub_before_packing_stored_reads_and_is_packed() {
        let db = Db::open_memory().unwrap();
        for n in 1..=4 {
            submit(&db, n, b"{}");
        }
        let mut failed = job(4, EgressReport::default());
        failed.revision = 4;
        if let Some(r) = failed.result.as_mut() {
            r.failure = Some(vk_hub_proto::job::FailureClass::Script);
        }
        assert!(db.put_job(&id(4), &failed, &[], 1_000).unwrap());
        // Three ends of just over 4 MiB — two make a step — and a failed job's, outside the
        // cache.
        let big = log(130_000);
        assert!(big.len() > 4 << 20);
        let txn = db.db.begin_write().unwrap();
        {
            let mut legacy = txn.open_table(LEGACY_TAILS).unwrap();
            let mut lens = txn.open_table(JOB_TAIL_LENS).unwrap();
            for n in 1..=3 {
                legacy.insert(id(n).as_str(), big.as_slice()).unwrap();
                lens.insert(id(n).as_str(), big.len() as u64).unwrap();
            }
            legacy.insert(id(4).as_str(), &b"boom\n"[..]).unwrap();
            lens.insert(id(4).as_str(), 5).unwrap();
        }
        order_jobs(&txn).unwrap();
        index_job_cache(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(cached(&db), 3 * big.len() as u64);
        assert_eq!(db.job_tail(&id(2)).unwrap().unwrap(), big);

        assert_eq!(db.pack_legacy_tails().unwrap(), 2);
        assert_eq!(db.pack_legacy_tails().unwrap(), 2);
        assert_eq!(db.pack_legacy_tails().unwrap(), 0);
        let stored = pack(&big, TAIL_LEVEL).unwrap().len() as u64;
        assert!(stored * 8 < big.len() as u64);
        assert_eq!(cached(&db), 3 * stored);
        for n in 1..=3 {
            assert_eq!(db.job_tail(&id(n)).unwrap().unwrap(), big);
        }
        assert_eq!(
            db.job_tail(&id(4)).unwrap().as_deref(),
            Some(&b"boom\n"[..])
        );
        // Rebuilt at start, the count is the same.
        let txn = db.db.begin_write().unwrap();
        index_job_cache(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(cached(&db), 3 * stored);
    }

    /// Kept output counts in the cache as stored: a total holds as many ends as fit packed,
    /// the oldest evicted first.
    #[test]
    fn the_cache_counts_ends_as_stored() {
        let db = Db::open_memory().unwrap();
        let tail = log(2000);
        let stored = pack(&tail, TAIL_LEVEL).unwrap().len() as u64;
        let total = 3 * stored;
        assert!(total < tail.len() as u64);
        for n in 1..=5 {
            submit(&db, n, b"{}");
            assert!(db.cache_job_tail(&id(n), &tail, total).unwrap());
        }
        assert_eq!(cached(&db), total);
        for n in 1..=2 {
            assert_eq!(db.job_tail(&id(n)).unwrap(), None);
        }
        for n in 3..=5 {
            assert_eq!(db.job_tail(&id(n)).unwrap().unwrap(), tail);
        }
    }
}
