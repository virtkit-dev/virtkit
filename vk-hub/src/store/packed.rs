//! Kept output and job specs, stored zstd-compressed. A packed value starts with its format:
//! [`RAW`] followed by unchanged bytes when zstd would not make them smaller; [`PLAIN`]
//! followed by a zstd frame; or [`DICT`] followed by a dictionary ID (`u32`, big-endian)
//! and a zstd frame compressed with that dictionary from [`SPEC_DICTS`]. Legacy specs are
//! JSON starting with `{`, which is not a format byte. Kept output can contain any bytes,
//! so legacy output has its own table ([`LEGACY_TAILS`]) and is read unchanged.
//!
//! Job specs share images, scripts and variables, so they use a dictionary trained on the
//! newest specs ([`TRAINING`]). The first training requires enough stored specs; later
//! trainings require enough submissions since the last. Each spec names its dictionary,
//! so retraining leaves older packed specs unchanged. Unreferenced dictionaries are dropped,
//! except the newest. Until the first dictionary is trained, specs are packed without one.
//!
//! Legacy data is packed in bounded background steps ([`Db::pack_legacy_tails`],
//! [`Db::pack_specs`]). redb reuses freed pages, but the file does not shrink.

use std::collections::{HashMap, HashSet};
use std::ops::Bound;
use std::sync::{Arc, MutexGuard, PoisonError};

use anyhow::{Context, Result, anyhow, bail};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use zstd::bulk::{Compressor, Decompressor};
use zstd::dict::{DecoderDictionary, EncoderDictionary};

use super::Db;
use super::jobs::{
    CACHED_BYTES, JOB_CACHE, JOB_META, JOB_ORDER, JOB_SPECS, JOB_TAIL_LENS, JOB_TAILS, LEGACY_TAILS,
};

/// The bytes follow as they are.
const RAW: u8 = 0;
/// A zstd frame follows.
const PLAIN: u8 = 1;
/// A dictionary's ID follows, then a zstd frame compressed with it.
const DICT: u8 = 2;

/// The zstd level kept output is packed at: higher levels gain a few percent on it, for
/// several times the time.
pub(super) const TAIL_LEVEL: i32 = 1;
/// The zstd level job specs are packed at, with a dictionary or without.
const SPEC_LEVEL: i32 = 3;

/// The most a packed value unpacks to, well past the largest kept output (4 MiB) and spec
/// ([`vk_hub_proto::job::MAX_JOB_SPEC`]): a frame recording a larger size is refused before
/// anything is allocated, and one recording none gets no more than this.
const MAX_UNPACKED: usize = 16 << 20;

/// Key: a dictionary's ID, oldest first. Value: the [`JOB_ORDER`] sequence the history had
/// reached when it was trained, and the dictionary.
pub(super) const SPEC_DICTS: TableDefinition<u32, (u64, &[u8])> =
    TableDefinition::new("job_spec_dicts");

/// About how much legacy kept output one step of [`Db::pack_legacy_tails`] packs, in bytes as
/// read: the step stops once past it, so its write holds at most one end more.
const PACK_BYTES: usize = 8 << 20;
/// How many specs one step of [`Db::pack_specs`] packs at most.
const PACK_SPECS: usize = 256;
/// How many specs one step of [`Db::pack_specs`] reads at most, packed or not.
const PACK_SCAN: usize = 4096;

/// When the job specs' dictionary is trained, and on what.
pub(super) struct Training {
    /// The fewest specs the history must hold for a dictionary to be trained on them.
    pub min_specs: u64,
    /// How many jobs are submitted after a dictionary was trained before the next is.
    pub retrain_after: u64,
    /// The most specs, newest first, one training reads.
    pub samples: usize,
    /// The most bytes of them it reads.
    pub sample_bytes: usize,
    /// The largest dictionary it makes.
    pub dict_size: usize,
}

/// A few hundred specs make a dictionary that packs specs about ten times smaller than zstd
/// without a dictionary; trained again every few thousand jobs, it follows what the fleet runs.
pub(super) const TRAINING: Training = Training {
    min_specs: 500,
    retrain_after: 5000,
    samples: 1000,
    sample_bytes: 16 << 20,
    dict_size: 100 << 10,
};

/// The job specs' dictionaries in memory, prepared once rather than at every read.
#[derive(Default)]
pub(super) struct SpecDicts {
    /// The newest dictionary, which specs are packed with.
    current: Option<Current>,
    /// The dictionaries read so far, by ID, prepared for unpacking.
    decoders: HashMap<u32, Arc<DecoderDictionary<'static>>>,
    /// The dictionaries dropped, kept out of [`SpecDicts::decoders`]: a reader whose read began
    /// before the drop still finds one, and would keep it prepared for good.
    dropped: HashSet<u32>,
    /// No training is tried before the history reaches this [`JOB_ORDER`] sequence: one
    /// failed below it.
    retry_at: u64,
}

/// The newest dictionary of [`SPEC_DICTS`].
#[derive(Clone)]
struct Current {
    id: u32,
    /// The [`JOB_ORDER`] sequence it was trained at.
    trained_at: u64,
    encoder: Arc<EncoderDictionary<'static>>,
}

impl SpecDicts {
    /// The dictionaries of `db`, with its newest prepared for packing.
    pub(super) fn load(db: &Database) -> Result<Self> {
        let txn = db.begin_read().context("starting a read")?;
        let table = txn.open_table(SPEC_DICTS)?;
        let current = match table.last()? {
            Some((id, row)) => {
                let (trained_at, dict) = row.value();
                Some(Current {
                    id: id.value(),
                    trained_at,
                    encoder: Arc::new(encoder(dict)?),
                })
            }
            None => None,
        };
        Ok(SpecDicts {
            current,
            ..SpecDicts::default()
        })
    }
}

/// A [`JOB_ORDER`] entry: a sequence and the job's ID.
type OrderEntry = (u64, String);

/// `dict` prepared for packing specs.
fn encoder(dict: &[u8]) -> Result<EncoderDictionary<'static>> {
    EncoderDictionary::try_copy(dict, SPEC_LEVEL).context("preparing a job spec dictionary")
}

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

/// A compressor for packing job specs with `dict`, to reuse across them.
fn spec_compressor<'a>(dict: &'a EncoderDictionary<'_>) -> Result<Compressor<'a>> {
    Compressor::with_prepared_dictionary(dict).context("preparing a job spec compressor")
}

/// `data` packed with dictionary `id`, which `compressor` compresses with.
fn pack_with(data: &[u8], id: u32, compressor: &mut Compressor<'_>) -> Result<Vec<u8>> {
    let frame = compressor
        .compress(data)
        .context("compressing a job spec")?;
    let mut out = Vec::with_capacity(frame.len().saturating_add(5));
    out.push(DICT);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&frame);
    Ok(out)
}

/// Return `packed`, prepared from `spec` by [`Db::pack_spec`] before `txn`, unless its
/// dictionary was dropped. [`Db::drop_unused_spec_dicts`] can drop it before any stored spec
/// names it; in that case, repack `spec` without a dictionary.
pub(super) fn spec_to_store(
    txn: &redb::WriteTransaction,
    spec: &[u8],
    packed: Vec<u8>,
) -> Result<Vec<u8>> {
    match dict_of(&packed) {
        Some(id) if txn.open_table(SPEC_DICTS)?.get(id)?.is_none() => pack(spec, SPEC_LEVEL),
        _ => Ok(packed),
    }
}

/// The dictionary packed `value` names, if it names one.
pub(super) fn dict_of(value: &[u8]) -> Option<u32> {
    match value {
        [DICT, a, b, c, d, ..] => Some(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => None,
    }
}

/// Packed `value` unpacked, `dict` preparing the dictionary it names.
pub(super) fn unpack(
    value: &[u8],
    dict: impl FnOnce(u32) -> Result<Arc<DecoderDictionary<'static>>>,
) -> Result<Vec<u8>> {
    match value {
        [RAW, bytes @ ..] => Ok(bytes.to_vec()),
        [PLAIN, frame @ ..] => {
            zstd::bulk::decompress(frame, MAX_UNPACKED).context("decompressing a stored value")
        }
        [DICT, a, b, c, d, frame @ ..] => {
            let id = u32::from_be_bytes([*a, *b, *c, *d]);
            let dict = dict(id)?;
            Decompressor::with_prepared_dictionary(&dict)
                .and_then(|mut d| d.decompress(frame, MAX_UNPACKED))
                .with_context(|| format!("decompressing a job spec with dictionary {id}"))
        }
        [format, ..] => bail!("a stored value of unknown format {format}"),
        [] => bail!("an empty stored value"),
    }
}

impl Db {
    /// The job specs' dictionaries in memory. One a panic left half-updated is still sound:
    /// each entry is replaced whole.
    fn spec_dicts(&self) -> MutexGuard<'_, SpecDicts> {
        self.spec_dicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Job spec `spec` packed with the newest dictionary, or without one before the first.
    pub(super) fn pack_spec(&self, spec: &[u8]) -> Result<Vec<u8>> {
        let current = self.spec_dicts().current.clone();
        match current {
            Some(c) => pack_with(spec, c.id, &mut spec_compressor(&c.encoder)?),
            None => pack(spec, SPEC_LEVEL),
        }
    }

    /// Job spec `value` as [`JOB_SPECS`] holds it, unpacked, with `dicts` the dictionaries of
    /// the same transaction.
    pub(super) fn unpack_spec(
        &self,
        dicts: &impl ReadableTable<u32, (u64, &'static [u8])>,
        value: &[u8],
    ) -> Result<Vec<u8>> {
        // Stored by a hub before packing: JSON, as submitted.
        if value.first() == Some(&b'{') {
            return Ok(value.to_vec());
        }
        unpack(value, |id| self.spec_decoder(dicts, id))
    }

    /// Dictionary `id` of `dicts`, prepared for unpacking once and kept so.
    fn spec_decoder(
        &self,
        dicts: &impl ReadableTable<u32, (u64, &'static [u8])>,
        id: u32,
    ) -> Result<Arc<DecoderDictionary<'static>>> {
        if let Some(decoder) = self.spec_dicts().decoders.get(&id) {
            return Ok(decoder.clone());
        }
        let row = dicts
            .get(id)?
            .with_context(|| format!("job spec dictionary {id} is missing"))?;
        let decoder = DecoderDictionary::try_copy(row.value().1)
            .with_context(|| format!("preparing job spec dictionary {id}"))?;
        let decoder = Arc::new(decoder);
        let mut cached = self.spec_dicts();
        if !cached.dropped.contains(&id) {
            cached.decoders.insert(id, decoder.clone());
        }
        Ok(decoder)
    }

    /// Train the job specs' next dictionary when [`TRAINING`] says it is due: its ID, `None`
    /// when none was due.
    pub fn train_spec_dict(&self) -> Result<Option<u32>> {
        self.train_spec_dict_with(&TRAINING)
    }

    /// [`Db::train_spec_dict`] as `training` says. A training that fails is not tried again
    /// until `min_specs` more jobs were submitted.
    fn train_spec_dict_with(&self, training: &Training) -> Result<Option<u32>> {
        let (current, retry_at) = {
            let dicts = self.spec_dicts();
            (dicts.current.clone(), dicts.retry_at)
        };
        let (next, samples) = {
            let txn = self.db.begin_read().context("starting a read")?;
            let order = txn.open_table(JOB_ORDER)?;
            let specs = txn.open_table(JOB_SPECS)?;
            let dicts = txn.open_table(SPEC_DICTS)?;
            let next = order
                .last()?
                .map_or(0, |(k, _)| k.value().saturating_add(1));
            let due = specs.len()? >= training.min_specs
                && next >= retry_at
                && current
                    .as_ref()
                    .is_none_or(|c| next.saturating_sub(c.trained_at) >= training.retrain_after);
            if !due {
                return Ok(None);
            }
            let (mut samples, mut bytes) = (Vec::new(), 0usize);
            for entry in order.iter()?.rev() {
                if samples.len() >= training.samples {
                    break;
                }
                let id = entry?.1.value().to_string();
                let Some(value) = specs.get(id.as_str())? else {
                    continue;
                };
                // One that does not unpack is left out of the samples, not fatal to them.
                let Ok(spec) = self.unpack_spec(&dicts, value.value()) else {
                    continue;
                };
                bytes = bytes.saturating_add(spec.len());
                if bytes > training.sample_bytes {
                    break;
                }
                samples.push(spec);
            }
            (next, samples)
        };
        let trained = zstd::dict::from_samples(&samples, training.dict_size)
            .map_err(|e| anyhow!(e))
            .and_then(|dict| Ok((encoder(&dict)?, dict)));
        let (encoder, dict) = match trained {
            Ok(trained) => trained,
            Err(e) => {
                self.spec_dicts().retry_at = next.saturating_add(training.min_specs);
                return Err(e.context(format!(
                    "training a job spec dictionary on {} specs",
                    samples.len()
                )));
            }
        };
        let txn = self.db.begin_write().context("starting a write")?;
        let id = {
            let mut dicts = txn.open_table(SPEC_DICTS)?;
            let id = match dicts.last()? {
                Some((k, _)) => k
                    .value()
                    .checked_add(1)
                    .context("job spec dictionary IDs exhausted")?,
                None => 1,
            };
            dicts.insert(id, (next, dict.as_slice()))?;
            id
        };
        txn.commit().context("storing a job spec dictionary")?;
        self.spec_dicts().current = Some(Current {
            id,
            trained_at: next,
            encoder: Arc::new(encoder),
        });
        Ok(Some(id))
    }

    /// Drop unreferenced dictionaries except the newest, returning their IDs.
    ///
    /// Scan specs in a read transaction to avoid blocking hub writes for the whole history.
    /// A submit packs with the newest dictionary before its write, so a later commit can
    /// reference a candidate. The write rechecks specs submitted after the read's last
    /// [`JOB_ORDER`] sequence. If that entry was pruned or its sequence reused for another
    /// job, scan every spec instead. Job IDs are random and never placed twice.
    pub fn drop_unused_spec_dicts(&self) -> Result<Vec<u32>> {
        let (candidates, last) = self.unused_spec_dicts()?;
        self.drop_spec_dicts(candidates, last)
    }

    /// The read of [`Db::drop_unused_spec_dicts`]: the dictionaries no spec names, but the
    /// newest, and the last [`JOB_ORDER`] entry then.
    fn unused_spec_dicts(&self) -> Result<(Vec<u32>, Option<OrderEntry>)> {
        let txn = self.db.begin_read().context("starting a read")?;
        let dicts = txn.open_table(SPEC_DICTS)?;
        // The newest is never dropped, so with one there is nothing to look for.
        if dicts.len()? <= 1 {
            return Ok((Vec::new(), None));
        }
        let Some(newest) = dicts.last()?.map(|(k, _)| k.value()) else {
            return Ok((Vec::new(), None));
        };
        let mut named = HashSet::from([newest]);
        for entry in txn.open_table(JOB_SPECS)?.iter()? {
            named.extend(dict_of(entry?.1.value()));
        }
        let mut candidates = Vec::new();
        for entry in dicts.iter()? {
            let id = entry?.0.value();
            if !named.contains(&id) {
                candidates.push(id);
            }
        }
        let last = txn
            .open_table(JOB_ORDER)?
            .last()?
            .map(|(k, v)| (k.value(), v.value().to_string()));
        Ok((candidates, last))
    }

    /// The write of [`Db::drop_unused_spec_dicts`]: drop `candidates` that no spec submitted
    /// since the read, its last [`JOB_ORDER`] entry `last`, names.
    fn drop_spec_dicts(&self, candidates: Vec<u32>, last: Option<OrderEntry>) -> Result<Vec<u32>> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let txn = self.db.begin_write().context("starting a write")?;
        let dropped = {
            let mut dicts = txn.open_table(SPEC_DICTS)?;
            let newest = dicts.last()?.map(|(k, _)| k.value());
            let specs = txn.open_table(JOB_SPECS)?;
            let order = txn.open_table(JOB_ORDER)?;
            let mut named: HashSet<u32> = newest.into_iter().collect();
            let since = match &last {
                Some((seq, id)) if order.get(seq)?.is_some_and(|g| g.value() == id) => {
                    Some(seq.saturating_add(1))
                }
                None => Some(0),
                Some(_) => None,
            };
            match since {
                Some(since) => {
                    for entry in order.range(since..)? {
                        if let Some(spec) = specs.get(entry?.1.value())? {
                            named.extend(dict_of(spec.value()));
                        }
                    }
                }
                None => {
                    for entry in specs.iter()? {
                        named.extend(dict_of(entry?.1.value()));
                    }
                }
            }
            let mut unused = Vec::new();
            for id in candidates {
                if !named.contains(&id) && dicts.remove(id)?.is_some() {
                    unused.push(id);
                }
            }
            unused
        };
        if dropped.is_empty() {
            // Nothing changed: the write is let go uncommitted.
            return Ok(dropped);
        }
        txn.commit().context("dropping job spec dictionaries")?;
        let mut dicts = self.spec_dicts();
        for id in &dropped {
            dicts.decoders.remove(id);
            dicts.dropped.insert(*id);
        }
        Ok(dropped)
    }

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

    /// Pack with the newest dictionary up to [`PACK_SPECS`] of the specs keyed past `after`
    /// that were stored without one: by a hub before packing, or before the first dictionary.
    /// How many were packed, and where the next step goes on from: `None` once the last spec
    /// was read, with no dictionary yet, or with the newest dropped since the step began. They
    /// are read and packed before the write.
    pub fn pack_specs(&self, after: Option<&str>) -> Result<(usize, Option<String>)> {
        self.pack_specs_with(after, PACK_SPECS, PACK_SCAN)
    }

    /// [`Db::pack_specs`] packing at most `max_specs` specs of the `max_scan` it reads.
    fn pack_specs_with(
        &self,
        after: Option<&str>,
        max_specs: usize,
        max_scan: usize,
    ) -> Result<(usize, Option<String>)> {
        let Some(current) = self.spec_dicts().current.clone() else {
            return Ok((0, None));
        };
        let mut compressor = spec_compressor(&current.encoder)?;
        let (mut packed, mut last) = (Vec::new(), None);
        let done = {
            let txn = self.db.begin_read().context("starting a read")?;
            let specs = txn.open_table(JOB_SPECS)?;
            let dicts = txn.open_table(SPEC_DICTS)?;
            let from = after.map_or(Bound::Unbounded, Bound::Excluded);
            let mut range = specs.range::<&str>((from, Bound::Unbounded))?;
            let mut read = 0usize;
            loop {
                if read >= max_scan || packed.len() >= max_specs {
                    break false;
                }
                let Some(entry) = range.next() else {
                    break true;
                };
                read = read.saturating_add(1);
                let (id, value) = entry?;
                let id = id.value().to_string();
                last = Some(id.clone());
                if dict_of(value.value()).is_some() {
                    continue;
                }
                // One that does not unpack stays as it is, for its readers to report.
                let Ok(spec) = self.unpack_spec(&dicts, value.value()) else {
                    continue;
                };
                packed.push((id, pack_with(&spec, current.id, &mut compressor)?));
            }
        };
        if !packed.is_empty() {
            let txn = self.db.begin_write().context("starting a write")?;
            // Dropped since the step began, the dictionary would leave what it packed unreadable:
            // nothing is stored, and the pass ends for the next to pack with the newest.
            if txn.open_table(SPEC_DICTS)?.get(current.id)?.is_none() {
                return Ok((0, None));
            }
            {
                let mut specs = txn.open_table(JOB_SPECS)?;
                for (id, value) in &packed {
                    // Dropped since it was read: nothing to pack.
                    let stored = specs.get(id.as_str())?;
                    if stored.is_some_and(|g| dict_of(g.value()).is_none()) {
                        specs.insert(id.as_str(), value.as_slice())?;
                    }
                }
            }
            txn.commit().context("packing job specs")?;
        }
        Ok((packed.len(), last.filter(|_| !done)))
    }
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::egress::EgressReport;

    use super::*;
    use crate::egress::testing::job;
    use crate::store::jobs::{index_job_cache, order_jobs};

    /// A training small enough for a test's few specs.
    const SMALL: Training = Training {
        min_specs: 20,
        retrain_after: 10,
        samples: 50,
        sample_bytes: 1 << 20,
        dict_size: 8 << 10,
    };

    fn id(n: u64) -> String {
        format!("{n:032x}")
    }

    /// Spec `n`: much like the others, as a fleet's are, with a little of its own.
    fn spec(n: u64) -> Vec<u8> {
        let vars: Vec<String> = (0..60)
            .map(|v| {
                let value = (v * 7 + n) % 13;
                format!(r#"{{"key":"CI_VAR_{v}","value":"value-{value}","public":true}}"#)
            })
            .collect();
        let (name, tag, vars) = (n % 5, n % 3, vars.join(","));
        format!(
            r#"{{"gitlab_ci":{{"job":{{"id":{n},"name":"build-{name}"}},"image":"registry.example.com/ci/build:{tag}","variables":[{vars}],"script":["make -j8 all","make check","echo job {n} done"]}}}}"#
        )
        .into_bytes()
    }

    /// Job `n`, finished and settled, submitted with `spec`.
    fn submit(db: &Db, n: u64, spec: &[u8]) {
        let mut row = job(n, EgressReport::default());
        row.settled_at = row.finished_at;
        let submitted = db.submit_job(&id(n), &row, &id(n), spec, "key gitlab", 1_000);
        assert!(matches!(submitted.unwrap(), crate::store::Submitted::New));
    }

    /// Job `n`'s spec as stored.
    fn stored_spec(db: &Db, n: u64) -> Vec<u8> {
        let txn = db.db.begin_read().unwrap();
        let specs = txn.open_table(JOB_SPECS).unwrap();
        specs.get(id(n).as_str()).unwrap().unwrap().value().to_vec()
    }

    /// The dictionaries' IDs.
    fn dicts(db: &Db) -> Vec<u32> {
        let txn = db.db.begin_read().unwrap();
        let table = txn.open_table(SPEC_DICTS).unwrap();
        (table.iter().unwrap())
            .map(|e| e.unwrap().0.value())
            .collect()
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
    /// zstd frame, and a spec with the dictionary it names; a format unknown is refused.
    #[test]
    fn a_value_reads_back_in_every_format() {
        let none = |d: u32| -> Result<Arc<DecoderDictionary<'static>>> { bail!("dictionary {d}") };
        for data in [&b""[..], b"one\n"] {
            let packed = pack(data, TAIL_LEVEL).unwrap();
            assert_eq!(packed.first(), Some(&RAW));
            assert_eq!(packed.len(), data.len() + 1);
            assert_eq!(unpack(&packed, none).unwrap(), data);
        }
        let output = log(1000);
        let packed = pack(&output, TAIL_LEVEL).unwrap();
        assert_eq!(packed.first(), Some(&PLAIN));
        assert!(packed.len() * 8 < output.len(), "{}", packed.len());
        assert_eq!(unpack(&packed, none).unwrap(), output);
        assert_eq!(dict_of(&packed), None);

        let samples: Vec<Vec<u8>> = (0..40).map(spec).collect();
        let dict = zstd::dict::from_samples(&samples, SMALL.dict_size).unwrap();
        let encoder = encoder(&dict).unwrap();
        let packed = pack_with(&spec(99), 7, &mut spec_compressor(&encoder).unwrap()).unwrap();
        assert_eq!(dict_of(&packed), Some(7));
        assert!(packed.len() < pack(&spec(99), SPEC_LEVEL).unwrap().len());
        let decoder = Arc::new(DecoderDictionary::try_copy(&dict).unwrap());
        assert_eq!(unpack(&packed, |_| Ok(decoder)).unwrap(), spec(99));
        assert!(unpack(&packed, none).is_err());

        assert!(unpack(b"\x09data", none).is_err());
        assert!(unpack(b"", none).is_err());
        // A frame cut short, or not one at all
        let packed = pack(&output, TAIL_LEVEL).unwrap();
        assert!(unpack(&packed[..packed.len() / 2], none).is_err());
        assert!(unpack(b"\x01\x28\xb5", none).is_err());
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

    /// Legacy JSON specs and output in its own table read unchanged. Output counts at its
    /// original size until packed in steps, then at its packed size, and still reads the same.
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
            let json = br#"{"gitlab_ci":{}}"#;
            txn.open_table(JOB_SPECS)
                .unwrap()
                .insert(id(1).as_str(), &json[..])
                .unwrap();
        }
        order_jobs(&txn).unwrap();
        index_job_cache(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(cached(&db), 3 * big.len() as u64);
        assert_eq!(db.job_tail(&id(2)).unwrap().unwrap(), big);
        assert_eq!(
            db.job_spec(&id(1)).unwrap().unwrap(),
            br#"{"gitlab_ci":{}}"#
        );

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

    /// Specs are packed without a dictionary until one is trained, then with the newest; one
    /// packed with an older dictionary still reads, after a reopen too, and that dictionary
    /// goes once no spec names it. Specs packed without one are packed again with the newest.
    #[test]
    fn specs_are_packed_with_the_newest_dictionary() {
        let db = Db::open_memory().unwrap();
        for n in 1..=19 {
            submit(&db, n, &spec(n));
        }
        assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), None);
        submit(&db, 20, &spec(20));
        assert_eq!(dict_of(&stored_spec(&db, 20)), None);
        assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), Some(1));
        assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), None);
        for n in 21..=30 {
            submit(&db, n, &spec(n));
            assert_eq!(dict_of(&stored_spec(&db, n)), Some(1));
        }
        // Ten jobs on, the next.
        assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), Some(2));
        submit(&db, 31, &spec(31));
        assert_eq!(dict_of(&stored_spec(&db, 31)), Some(2));
        // Reopened: the newest packs, the older still reads.
        *db.spec_dicts() = SpecDicts::load(&db.db).unwrap();
        submit(&db, 32, &spec(32));
        assert_eq!(dict_of(&stored_spec(&db, 32)), Some(2));
        for n in [1, 20, 25, 31, 32] {
            assert_eq!(db.job_spec(&id(n)).unwrap().unwrap(), spec(n), "{n}");
        }
        assert!(db.drop_unused_spec_dicts().unwrap().is_empty());

        // Packed again, from past job 9 on, then from the start.
        let (packed, next) = db.pack_specs(Some(&id(9))).unwrap();
        assert_eq!((packed, next), (11, None));
        assert_eq!(dict_of(&stored_spec(&db, 9)), None);
        assert_eq!(dict_of(&stored_spec(&db, 10)), Some(2));
        assert_eq!(db.pack_specs(None).unwrap(), (9, None));
        for n in 1..=20 {
            assert_eq!(dict_of(&stored_spec(&db, n)), Some(2));
            assert_eq!(db.job_spec(&id(n)).unwrap().unwrap(), spec(n));
        }
        // Jobs 21 to 30 gone with the oldest, dictionary 1 goes with them.
        db.prune_jobs(1_000, 2).unwrap();
        assert_eq!(dicts(&db), [1, 2]);
        assert_eq!(db.drop_unused_spec_dicts().unwrap(), [1]);
        assert_eq!(dicts(&db), [2]);
        assert_eq!(db.job_spec(&id(32)).unwrap().unwrap(), spec(32));
        // The newest stays, named or not.
        db.prune_jobs(1_000, 0).unwrap();
        assert!(db.drop_unused_spec_dicts().unwrap().is_empty());
        assert_eq!(dicts(&db), [2]);
    }

    /// A spec submitted between the drop's read and its write, packed with a dictionary the
    /// read found unused, keeps that dictionary: through the jobs submitted since the read, or
    /// through every spec once the read's last job is gone.
    #[test]
    fn a_dictionary_named_since_the_drop_read_stays() {
        for trimmed in [false, true] {
            let db = Db::open_memory().unwrap();
            for n in 1..=20 {
                submit(&db, n, &spec(n));
            }
            assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), Some(1));
            let first = db.spec_dicts().current.clone().unwrap();
            for n in 21..=30 {
                submit(&db, n, &spec(n));
            }
            assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), Some(2));
            submit(&db, 31, &spec(31));
            // Every spec on 1 gone: the read finds it unused.
            db.prune_jobs(1_000, 1).unwrap();
            let (candidates, last) = db.unused_spec_dicts().unwrap();
            assert_eq!(candidates, [1], "trimmed={trimmed}");
            if trimmed {
                db.prune_jobs(1_000, 0).unwrap();
            }
            // A submit that took 1 as the newest before 2 was trained commits now.
            let newest = db.spec_dicts().current.replace(first);
            submit(&db, 40, &spec(40));
            db.spec_dicts().current = newest;
            assert_eq!(dict_of(&stored_spec(&db, 40)), Some(1));

            assert!(db.drop_spec_dicts(candidates, last).unwrap().is_empty());
            assert_eq!(dicts(&db), [1, 2], "trimmed={trimmed}");
            assert_eq!(db.job_spec(&id(40)).unwrap().unwrap(), spec(40));
        }
    }

    /// A spec packed with a dictionary dropped before its write is stored without one.
    #[test]
    fn a_spec_packed_with_a_dropped_dictionary_is_stored_without_it() {
        let db = Db::open_memory().unwrap();
        for n in 1..=20 {
            submit(&db, n, &spec(n));
        }
        assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), Some(1));
        let packed = db.pack_spec(&spec(99)).unwrap();
        assert_eq!(dict_of(&packed), Some(1));
        let txn = db.db.begin_write().unwrap();
        let kept = spec_to_store(&txn, &spec(99), packed.clone()).unwrap();
        assert_eq!(kept, packed);
        txn.open_table(SPEC_DICTS).unwrap().remove(1).unwrap();
        let stored = spec_to_store(&txn, &spec(99), packed).unwrap();
        assert_eq!(dict_of(&stored), None);
        let none = |d: u32| -> Result<Arc<DecoderDictionary<'static>>> { bail!("dictionary {d}") };
        assert_eq!(unpack(&stored, none).unwrap(), spec(99));
    }

    /// A spec a hub before packing stored as JSON is packed with the dictionary, once there is
    /// one, and reads back the same.
    #[test]
    fn a_json_spec_is_packed_with_the_dictionary() {
        let db = Db::open_memory().unwrap();
        for n in 1..=20 {
            submit(&db, n, &spec(n));
        }
        assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), Some(1));
        assert_eq!(db.pack_specs(None).unwrap(), (20, None));
        let txn = db.db.begin_write().unwrap();
        txn.open_table(JOB_SPECS)
            .unwrap()
            .insert(id(5).as_str(), spec(5).as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(stored_spec(&db, 5), spec(5));

        assert_eq!(db.pack_specs(None).unwrap(), (1, None));
        assert_eq!(dict_of(&stored_spec(&db, 5)), Some(1));
        assert_eq!(db.job_spec(&id(5)).unwrap().unwrap(), spec(5));
    }

    /// Each step stops at its packing or scanning limit. The next resumes after the last
    /// spec read until all specs have been scanned.
    #[test]
    fn packing_specs_goes_on_where_the_last_step_stopped() {
        let db = Db::open_memory().unwrap();
        for n in 1..=20 {
            submit(&db, n, &spec(n));
        }
        assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), Some(1));
        for n in 21..=24 {
            submit(&db, n, &spec(n));
        }
        // Three packed of the first three read.
        assert_eq!(db.pack_specs_with(None, 3, 100).unwrap(), (3, Some(id(3))));
        assert_eq!(dict_of(&stored_spec(&db, 3)), Some(1));
        assert_eq!(dict_of(&stored_spec(&db, 4)), None);
        // Two read, already packed.
        assert_eq!(
            db.pack_specs_with(Some(&id(20)), 3, 2).unwrap(),
            (0, Some(id(22)))
        );
        let (mut total, mut after) = (3, Some(id(3)));
        while let Some(from) = after {
            let (n, next) = db.pack_specs_with(Some(&from), 3, 5).unwrap();
            assert!(n <= 3);
            total += n;
            after = next;
        }
        assert_eq!(total, 20);
        for n in 1..=24 {
            assert_eq!(dict_of(&stored_spec(&db, n)), Some(1), "{n}");
            assert_eq!(db.job_spec(&id(n)).unwrap().unwrap(), spec(n), "{n}");
        }
    }

    /// A training that fails is not tried again before `min_specs` more jobs were submitted.
    #[test]
    fn a_failed_training_waits_for_more_specs() {
        // zstd refuses to make a dictionary smaller than 256 bytes.
        let failing = Training {
            dict_size: 100,
            ..SMALL
        };
        let db = Db::open_memory().unwrap();
        for n in 1..=20 {
            submit(&db, n, &spec(n));
        }
        assert!(db.train_spec_dict_with(&failing).is_err());
        for n in 21..=39 {
            submit(&db, n, &spec(n));
            assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), None, "{n}");
        }
        submit(&db, 40, &spec(40));
        assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), Some(1));
    }

    /// A dictionary dropped is not prepared again for a reader whose read began before.
    #[test]
    fn a_dropped_dictionary_is_not_prepared_again() {
        let db = Db::open_memory().unwrap();
        for n in 1..=20 {
            submit(&db, n, &spec(n));
        }
        assert_eq!(db.train_spec_dict_with(&SMALL).unwrap(), Some(1));
        // Dictionary 2, the same, as the newest: no spec names 1.
        let txn = db.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SPEC_DICTS).unwrap();
            let dict = table.get(1).unwrap().unwrap().value().1.to_vec();
            table.insert(2, (20, dict.as_slice())).unwrap();
        }
        txn.commit().unwrap();
        *db.spec_dicts() = SpecDicts::load(&db.db).unwrap();

        let before = db.db.begin_read().unwrap();
        assert_eq!(db.drop_unused_spec_dicts().unwrap(), [1]);
        let table = before.open_table(SPEC_DICTS).unwrap();
        assert!(db.spec_decoder(&table, 1).is_ok());
        assert!(!db.spec_dicts().decoders.contains_key(&1));
        assert!(db.spec_decoder(&table, 2).is_ok());
        assert!(db.spec_dicts().decoders.contains_key(&2));
    }
}
