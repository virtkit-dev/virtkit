//! Claimed relay admissions, kept across hub restarts until their outcome is reconciled.

use anyhow::Result;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::{AdmissionOutcome, Placement};

use super::{Db, SchedulingIdentity, decode, encode};

/// Key: admission ID. Value: JSON [`StoredAdmission`].
pub(super) const ADMISSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("admissions");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAdmission {
    pub principal: String,
    pub identity: SchedulingIdentity,
    pub runner: Option<String>,
    pub placement: Placement,
    pub probe: bool,
    pub reservation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<AdmissionOutcome>,
}

impl Db {
    /// Update an existing admission without recreating one concurrently retired by pruning.
    pub fn update_admission_outcome(
        &self,
        id: &str,
        outcome: AdmissionOutcome,
    ) -> Result<Option<StoredAdmission>> {
        let txn = self.db.begin_write()?;
        let previous = {
            let mut table = txn.open_table(ADMISSIONS)?;
            let previous = table
                .get(id)?
                .map(|row| decode::<StoredAdmission>(row.value()))
                .transpose()?;
            if let Some(mut updated) = previous.clone() {
                updated.outcome = Some(outcome);
                table.insert(id, encode(&updated)?.as_slice())?;
            }
            previous
        };
        txn.commit()?;
        Ok(previous)
    }

    /// Restore a raced transition only if its admission still exists.
    pub fn restore_admission_if_present(
        &self,
        id: &str,
        admission: &StoredAdmission,
    ) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ADMISSIONS)?;
            let exists = table.get(id)?.is_some();
            if exists {
                table.insert(id, encode(admission)?.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Hold the database's write lock: signal `ready` once it is held, and let go on
    /// `release`, so a test can stall the writes of admissions.
    #[cfg(test)]
    pub(crate) fn hold_admission_writer(
        &self,
        ready: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        let txn = self.db.begin_write().unwrap();
        ready.send(()).unwrap();
        let _ = release.recv();
        drop(txn);
    }

    /// Apply reconciliation updates in one transaction. A job outcome only advances an
    /// unresolved admission; a concurrent final outcome must not be overwritten.
    pub fn reconcile_admissions(
        &self,
        changes: &[(String, Option<AdmissionOutcome>)],
    ) -> Result<()> {
        if changes.is_empty() {
            return Ok(());
        }
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ADMISSIONS)?;
            for (id, outcome) in changes {
                if let Some(outcome) = outcome {
                    let row = table
                        .get(id.as_str())?
                        .map(|row| decode::<StoredAdmission>(row.value()))
                        .transpose()?;
                    if let Some(mut row) = row
                        && row.outcome.is_none()
                    {
                        row.outcome = Some(*outcome);
                        let bytes = encode(&row)?;
                        table.insert(id.as_str(), bytes.as_slice())?;
                    }
                } else {
                    table.remove(id.as_str())?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Store admission `id`, replacing any stored before.
    pub fn put_admission(&self, id: &str, admission: &StoredAdmission) -> Result<()> {
        let bytes = encode(admission)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ADMISSIONS)?;
            table.insert(id, bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn admission(&self, id: &str) -> Result<Option<StoredAdmission>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ADMISSIONS)?;
        let row = table.get(id)?;
        row.map(|row| decode(row.value())).transpose()
    }

    /// Every stored admission, by ID.
    pub fn admissions(&self) -> Result<Vec<(String, StoredAdmission)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ADMISSIONS)?;
        let mut result = Vec::new();
        for entry in table.iter()? {
            let (id, row) = entry?;
            result.push((id.value().to_owned(), decode(row.value())?));
        }
        Ok(result)
    }

    pub fn remove_admission(&self, id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ADMISSIONS)?;
            table.remove(id)?;
        }
        txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Class;

    #[test]
    fn admissions_are_durable_and_replaceable() {
        let dir = std::env::temp_dir().join(format!("vk-hub-admissions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hub.redb");
        let db = Db::open(&path).unwrap();
        let id = "a".repeat(32);
        let mut admission = StoredAdmission {
            principal: "relay".into(),
            identity: SchedulingIdentity {
                tenant: "project".into(),
                class: Class::Production,
                gitlab: Some("https://gitlab.example".into()),
                runner_id: Some(42),
            },
            runner: Some("prod".into()),
            placement: Placement::default(),
            probe: true,
            reservation: "b".repeat(32),
            outcome: None,
        };
        db.put_admission(&id, &admission).unwrap();
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.admission(&id).unwrap(), Some(admission.clone()));
        admission.outcome = Some(AdmissionOutcome::Job);
        db.put_admission(&id, &admission).unwrap();
        assert_eq!(db.admissions().unwrap(), vec![(id.clone(), admission)]);
        db.reconcile_admissions(&[(id.clone(), Some(AdmissionOutcome::Empty))])
            .unwrap();
        assert_eq!(
            db.admission(&id).unwrap().unwrap().outcome,
            Some(AdmissionOutcome::Job)
        );
        db.reconcile_admissions(&[(id.clone(), None)]).unwrap();
        assert_eq!(db.admission(&id).unwrap(), None);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
