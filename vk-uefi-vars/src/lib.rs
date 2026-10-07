//! The UEFI variable service of a Windows guest, on the host.
//!
//! edk2's VariableSmmRuntimeDxe, the firmware's variable driver in this configuration, keeps no
//! variables: it forwards GetVariable, GetNextVariableName, SetVariable and QueryVariableInfo,
//! as MM communication messages, to libkrun's uefi-vars device, which hands each one to
//! [`Service::communicate`]. The service keeps the variables, checks authenticated writes
//! (the Secure Boot keys and databases above all) and enforces the firmware's variable
//! policies, as edk2's variable driver does inside SMM on a physical machine. The guest's kernel
//! cannot reach the store, and no signature is checked in the guest's address space, where
//! the firmware's own checks failed once Windows had mapped its runtime services.
//!
//! The non-volatile variables live in an edk2 variable store flash image (`edk2`), the format
//! the machines' stores already had. See docs/uefi-vars-design.md.

mod auth;
mod codec;
mod der;
pub mod edk2;
mod guid;
mod pkcs7;
mod policy;
mod siglist;
mod store;

#[cfg(test)]
mod tests;

use codec::{Reader, display_name, get, get_u64, put, ucs2_bytes, ucs2_name};
pub use guid::Guid;
use guid::{
    CERT_DB, GLOBAL_VARIABLE, IMAGE_SECURITY_DATABASE, SECURE_BOOT_ENABLE_DISABLE, VENDOR_KEYS_NV,
};
use policy::{Policies, Policy};
pub use store::Status;
use store::{
    APPEND_WRITE, AUTHENTICATED_WRITE_ACCESS, BOOTSERVICE_ACCESS, EfiTime, HARDWARE_ERROR_RECORD,
    MAX_VARIABLE_SIZE, NON_VOLATILE, NV_STORAGE_SIZE, RUNTIME_ACCESS, STORED_ATTRIBUTES, Store,
    TIME_BASED_AUTHENTICATED_WRITE_ACCESS, VOLATILE_STORAGE_SIZE, Variable,
};

/// EFI_MM_COMMUNICATE_HEADER: HeaderGuid, MessageLength (UINTN).
const MM_HEADER: usize = 24;
/// SMM_VARIABLE_COMMUNICATE_HEADER: Function, ReturnStatus (UINTN each).
const VAR_HEADER: usize = 16;
/// OFFSET_OF (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name).
const ACCESS_NAME: usize = 36;
/// OFFSET_OF (SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name).
const NEXT_NAME: usize = 24;
/// VAR_CHECK_POLICY_COMM_HEADER: Signature, Revision, Command, (pad), Result.
const POLICY_HEADER: usize = 24;
const POLICY_SIGNATURE: u32 = u32::from_le_bytes(*b"VCPC");
const POLICY_REVISION: u32 = 1;

/// The largest message the firmware is told it may send (GET_PAYLOAD_SIZE): a variable as
/// large as the service takes, its name, and the access structure.
const PAYLOAD_SIZE: usize = MAX_VARIABLE_SIZE + 0x400;

/// Volatile, read-only variables of the global namespace the service keeps up to date.
const SETUP_MODE: &str = "SetupMode";
const SECURE_BOOT: &str = "SecureBoot";
const AUDIT_MODE: &str = "AuditMode";
const DEPLOYED_MODE: &str = "DeployedMode";
const SIGNATURE_SUPPORT: &str = "SignatureSupport";
const VENDOR_KEYS: &str = "VendorKeys";
/// Read-only defaults a store may carry.
const DEFAULTS: [&str; 6] = [
    "PKDefault",
    "KEKDefault",
    "dbDefault",
    "dbxDefault",
    "dbtDefault",
    "dbrDefault",
];
/// The service's record of the signers of private authenticated variables, in edk2's certdb
/// namespace, boot-service only and written by the service alone.
const SIGNERS: &str = "VkAuthVarSigners";

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// A message the service could not take at all (the device reports it as a device error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmError {
    /// A header or length runs past the buffer.
    Malformed,
    /// No handler for the message's GUID.
    Unsupported,
}

/// The variable service of one machine.
#[derive(Clone, Debug)]
pub struct Service {
    store: Store,
    /// The store image the non-volatile variables persist in.
    image: edk2::Image,
    policies: Policies,
    /// Variables locked through EDKII_VARIABLE_LOCK_PROTOCOL, read-only from the end of DXE.
    locks: Vec<(Guid, Vec<u16>)>,
    /// Past READY_TO_BOOT: the end of DXE, from which locks hold.
    end_of_dxe: bool,
    /// Past EXIT_BOOT_SERVICE: only runtime variables are visible.
    runtime: bool,
    /// The non-volatile variables changed since the image was last taken.
    dirty: bool,
}

impl Service {
    /// The service over the store image `bytes` (the machine's store file).
    pub fn new(bytes: Vec<u8>) -> Result<Service, edk2::StoreError> {
        let image = edk2::Image::parse(bytes)?;
        let mut store = Store::default();
        for var in image.variables()?.iter().filter(|v| v.non_volatile()) {
            store.put(None, var.clone());
        }
        let mut service = Service {
            store,
            image,
            policies: Policies::default(),
            locks: Vec::new(),
            end_of_dxe: false,
            runtime: false,
            dirty: false,
        };
        service.refresh_modes();
        Ok(service)
    }

    /// A new boot (the device's RESET): volatile variables gone, policies and locks dropped,
    /// back before the end of DXE.
    pub fn reset(&mut self) {
        let nv: Vec<Variable> = self
            .store
            .iter()
            .filter(|v| v.non_volatile())
            .cloned()
            .collect();
        self.store = Store::default();
        for var in nv {
            self.store.put(None, var);
        }
        self.policies = Policies::default();
        self.locks.clear();
        self.end_of_dxe = false;
        self.runtime = false;
        self.refresh_modes();
    }

    /// The store image with the current non-volatile variables, if they changed since the last
    /// call: what the device writes back to the machine's store file.
    pub fn take_image(&mut self) -> Result<Option<&[u8]>, edk2::StoreError> {
        if !self.dirty {
            return Ok(None);
        }
        self.image.write(&self.store)?;
        self.dirty = false;
        Ok(Some(self.image.bytes()))
    }

    /// Handle one MM communication buffer in place: EFI_MM_COMMUNICATE_HEADER, then the message.
    pub fn communicate(&mut self, buf: &mut [u8]) -> Result<(), MmError> {
        let mut r = Reader::new(buf);
        let handler = r.guid().map_err(|_| MmError::Malformed)?;
        let length = usize::try_from(r.u64().map_err(|_| MmError::Malformed)?)
            .map_err(|_| MmError::Malformed)?;
        let end = MM_HEADER.checked_add(length).ok_or(MmError::Malformed)?;
        let message = buf.get_mut(MM_HEADER..end).ok_or(MmError::Malformed)?;
        match handler {
            guid::SMM_VARIABLE_PROTOCOL => self.variable_message(message),
            guid::VAR_CHECK_POLICY_MMI => self.policy_message(message),
            _ => Err(MmError::Unsupported),
        }
    }

    fn variable_message(&mut self, msg: &mut [u8]) -> Result<(), MmError> {
        let function = get_u64(msg, 0).map_err(|_| MmError::Malformed)?;
        let payload_size = msg
            .len()
            .checked_sub(VAR_HEADER)
            .ok_or(MmError::Malformed)?;
        if payload_size > PAYLOAD_SIZE {
            return Ok(()); // as edk2: refused without an answer
        }
        let Some(payload) = msg.get_mut(VAR_HEADER..) else {
            return Err(MmError::Malformed);
        };
        let status = match function {
            1 => self.mm_get_variable(payload),
            2 => self.mm_get_next(payload),
            3 => self.mm_set_variable(payload),
            4 => self.mm_query(payload),
            5 => self.ready_to_boot(),
            6 => {
                self.runtime = true;
                Some(Status::SUCCESS)
            }
            8 => self.mm_lock(payload),
            9 => Some(if self.end_of_dxe {
                Status::ACCESS_DENIED
            } else {
                Status::SUCCESS
            }),
            10 => Some(Status::NOT_FOUND),
            11 => put(payload, 0, &(PAYLOAD_SIZE as u64).to_le_bytes())
                .ok()
                .map(|()| Status::SUCCESS),
            _ => Some(Status::UNSUPPORTED),
        };
        if let Some(status) = status {
            put(msg, 8, &status.0.to_le_bytes()).map_err(|_| MmError::Malformed)?;
        }
        Ok(())
    }

    /// SMM_VARIABLE_FUNCTION_GET_VARIABLE: Guid, DataSize, NameSize, Attributes, Name, Data.
    fn mm_get_variable(&self, p: &mut [u8]) -> Option<Status> {
        let (guid, data_size, name) = match access_header(p) {
            Ok(fields) => fields,
            Err(status) => return Some(status),
        };
        let name_size = usize::try_from(get_u64(p, 24).ok()?).ok()?;
        let data_at = ACCESS_NAME.checked_add(name_size)?;
        let (status, attributes, data) = self.get_variable(&guid, &name, data_size);
        if let Some(attributes) = attributes {
            put(p, 32, &attributes.to_le_bytes()).ok()?;
        }
        if let Some(data) = data {
            put(p, 16, &(data.len() as u64).to_le_bytes()).ok()?;
            if status == Status::SUCCESS {
                put(p, data_at, &data).ok()?;
            }
        }
        Some(status)
    }

    /// SMM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME: Guid, NameSize, Name.
    fn mm_get_next(&self, p: &mut [u8]) -> Option<Status> {
        let guid = Reader::new(p).guid().ok()?;
        let name_size = usize::try_from(get_u64(p, 16).ok()?).ok()?;
        let room = p.len().checked_sub(NEXT_NAME)?;
        if name_size > room {
            return Some(Status::ACCESS_DENIED);
        }
        let name_buf = p.get(NEXT_NAME..)?;
        // The current name: up to its NUL within the buffer.
        let current: Vec<u16> = name_buf
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|u| *u != 0)
            .collect();
        if current.len().saturating_mul(2) >= room {
            return Some(Status::ACCESS_DENIED); // no NUL in the buffer
        }
        match self.next_variable(&guid, &current) {
            Err(status) => Some(status),
            Ok(var) => {
                let bytes = ucs2_bytes(&var.name);
                put(p, 16, &(bytes.len() as u64).to_le_bytes()).ok()?;
                if bytes.len() > name_size {
                    return Some(Status::BUFFER_TOO_SMALL);
                }
                put(p, 0, &var.guid.0).ok()?;
                put(p, NEXT_NAME, &bytes).ok()?;
                Some(Status::SUCCESS)
            }
        }
    }

    /// SMM_VARIABLE_FUNCTION_SET_VARIABLE.
    fn mm_set_variable(&mut self, p: &mut [u8]) -> Option<Status> {
        let (guid, data_size, name) = match access_header(p) {
            Ok(fields) => fields,
            Err(status) => return Some(status),
        };
        let name_size = usize::try_from(get_u64(p, 24).ok()?).ok()?;
        let attributes = codec::get_u32(p, 32).ok()?;
        let data_at = ACCESS_NAME.checked_add(name_size)?;
        let data = get(p, data_at, data_size).ok()?.to_vec();
        Some(self.set_variable(&guid, &name, attributes, &data))
    }

    /// SMM_VARIABLE_FUNCTION_QUERY_VARIABLE_INFO.
    fn mm_query(&self, p: &mut [u8]) -> Option<Status> {
        let attributes = codec::get_u32(p, 24).ok()?;
        match self.query(attributes) {
            Err(status) => Some(status),
            Ok((max, remaining, max_var)) => {
                put(p, 0, &max.to_le_bytes()).ok()?;
                put(p, 8, &remaining.to_le_bytes()).ok()?;
                put(p, 16, &max_var.to_le_bytes()).ok()?;
                Some(Status::SUCCESS)
            }
        }
    }

    /// SMM_VARIABLE_FUNCTION_LOCK_VARIABLE: Guid, NameSize, Name.
    fn mm_lock(&mut self, p: &mut [u8]) -> Option<Status> {
        if self.end_of_dxe {
            return Some(Status::ACCESS_DENIED);
        }
        let guid = Reader::new(p).guid().ok()?;
        let name_size = usize::try_from(get_u64(p, 16).ok()?).ok()?;
        let Some(name) = ucs2_name(get(p, NEXT_NAME, name_size).ok()?) else {
            return Some(Status::INVALID_PARAMETER);
        };
        if !self.locks.contains(&(guid, name.clone())) {
            self.locks.push((guid, name));
        }
        Some(Status::SUCCESS)
    }

    fn ready_to_boot(&mut self) -> Option<Status> {
        if self.runtime {
            return Some(Status::UNSUPPORTED);
        }
        self.end_of_dxe = true;
        self.policies.lock();
        Some(Status::SUCCESS)
    }

    /// The VarCheckPolicy handler: VAR_CHECK_POLICY_COMM_HEADER, then the command's parameters.
    fn policy_message(&mut self, msg: &mut [u8]) -> Result<(), MmError> {
        let mut r = Reader::new(msg);
        let signature = r.u32().map_err(|_| MmError::Malformed)?;
        let revision = r.u32().map_err(|_| MmError::Malformed)?;
        let command = r.u32().map_err(|_| MmError::Malformed)?;
        if signature != POLICY_SIGNATURE || revision != POLICY_REVISION {
            return Ok(());
        }
        let status = match command {
            // DISABLE
            1 => self.policies.disable(),
            // IS_ENABLED: a BOOLEAN after the header.
            2 => {
                put(msg, POLICY_HEADER, &[u8::from(self.policies.enabled())])
                    .map_err(|_| MmError::Malformed)?;
                Status::SUCCESS
            }
            // REGISTER: a VARIABLE_POLICY_ENTRY after the header.
            3 => match msg.get(POLICY_HEADER..).and_then(Policy::parse) {
                Some(policy) => self.policies.register(policy),
                None => Status::INVALID_PARAMETER,
            },
            // DUMP: no policy is handed back; the dump says there are none.
            4 => {
                let none = [0u8; 13];
                put(msg, POLICY_HEADER, &none).map_err(|_| MmError::Malformed)?;
                Status::SUCCESS
            }
            // LOCK
            5 => {
                self.policies.lock();
                Status::SUCCESS
            }
            _ => Status::UNSUPPORTED,
        };
        put(msg, 16, &status.0.to_le_bytes()).map_err(|_| MmError::Malformed)?;
        Ok(())
    }

    /// GetVariable: status, attributes (also on BUFFER_TOO_SMALL) and data (its full size
    /// tells the caller how much room it needs).
    fn get_variable(
        &self,
        guid: &Guid,
        name: &[u16],
        room: usize,
    ) -> (Status, Option<u32>, Option<Vec<u8>>) {
        if name.is_empty() {
            return (Status::NOT_FOUND, None, None);
        }
        let Some(var) = self.store.find(guid, name).filter(|v| self.visible(v)) else {
            return (Status::NOT_FOUND, None, None);
        };
        let status = if var.data.len() > room {
            Status::BUFFER_TOO_SMALL
        } else {
            Status::SUCCESS
        };
        (status, Some(var.attributes), Some(var.data.clone()))
    }

    /// GetNextVariableName: the visible variable after `name` in `guid` (the first one when
    /// `name` is empty).
    fn next_variable(&self, guid: &Guid, name: &[u16]) -> Result<&Variable, Status> {
        let start = if name.is_empty() {
            0
        } else {
            match self.store.position(guid, name) {
                Some(i) if self.store.get(i).is_some_and(|v| self.visible(v)) => {
                    i.checked_add(1).ok_or(Status::NOT_FOUND)?
                }
                _ => return Err(Status::INVALID_PARAMETER),
            }
        };
        (start..self.store.len())
            .filter_map(|i| self.store.get(i))
            .find(|v| self.visible(v))
            .ok_or(Status::NOT_FOUND)
    }

    /// Whether the guest sees `var` now: after ExitBootServices, only runtime variables.
    fn visible(&self, var: &Variable) -> bool {
        !self.runtime || var.attributes & RUNTIME_ACCESS != 0
    }

    /// QueryVariableInfo: (maximum storage, remaining storage, maximum variable size).
    fn query(&self, attributes: u32) -> Result<(u64, u64, u64), Status> {
        let known = NON_VOLATILE
            | BOOTSERVICE_ACCESS
            | RUNTIME_ACCESS
            | HARDWARE_ERROR_RECORD
            | AUTHENTICATED_WRITE_ACCESS
            | TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
        if attributes & known == 0
            || attributes & (RUNTIME_ACCESS | BOOTSERVICE_ACCESS) == RUNTIME_ACCESS
            || (self.runtime && attributes & RUNTIME_ACCESS == 0)
        {
            return Err(Status::INVALID_PARAMETER);
        }
        if attributes & HARDWARE_ERROR_RECORD != 0 || attributes & AUTHENTICATED_WRITE_ACCESS != 0 {
            return Err(Status::UNSUPPORTED);
        }
        let nv = attributes & NON_VOLATILE != 0;
        let max = if nv {
            NV_STORAGE_SIZE.min(self.image.capacity())
        } else {
            VOLATILE_STORAGE_SIZE
        };
        let remaining = max.saturating_sub(self.store.used(nv));
        Ok((max as u64, remaining as u64, MAX_VARIABLE_SIZE as u64))
    }

    /// SetVariable, as edk2's VariableServiceSetVariable checks and applies it.
    pub fn set_variable(
        &mut self,
        guid: &Guid,
        name: &[u16],
        attributes: u32,
        data: &[u8],
    ) -> Status {
        if name.is_empty() {
            return Status::INVALID_PARAMETER;
        }
        let mask = STORED_ATTRIBUTES | APPEND_WRITE;
        if attributes & !(mask | AUTHENTICATED_WRITE_ACCESS) != 0 {
            return Status::INVALID_PARAMETER;
        }
        if attributes & AUTHENTICATED_WRITE_ACCESS != 0 {
            return Status::UNSUPPORTED; // count-based authentication, deprecated
        }
        let stored = attributes & STORED_ATTRIBUTES;
        if attributes & (RUNTIME_ACCESS | BOOTSERVICE_ACCESS) == RUNTIME_ACCESS
            || stored & !TIME_BASED_AUTHENTICATED_WRITE_ACCESS == NON_VOLATILE
            || attributes & HARDWARE_ERROR_RECORD != 0
        {
            return Status::INVALID_PARAMETER;
        }
        let time_based = attributes & TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0;
        let append = attributes & APPEND_WRITE != 0;
        let authenticated = if time_based {
            match auth::split(data) {
                Ok(a) => Some(a),
                Err(status) => return status,
            }
        } else {
            None
        };
        let payload = authenticated.as_ref().map_or(data, |a| a.payload);
        let name_size = name.len().saturating_add(1).saturating_mul(2);
        if name_size.saturating_add(payload.len()) > MAX_VARIABLE_SIZE {
            return Status::INVALID_PARAMETER;
        }
        let index = self.store.position(guid, name);
        let existing = index.and_then(|i| self.store.get(i)).cloned();
        if let Some(var) = &existing {
            if self.runtime && (var.attributes & RUNTIME_ACCESS == 0 || !var.non_volatile()) {
                return Status::WRITE_PROTECTED;
            }
            if attributes != 0 && stored != var.attributes {
                return Status::INVALID_PARAMETER;
            }
        } else if self.runtime
            && attributes != 0
            && (stored & RUNTIME_ACCESS == 0 || stored & NON_VOLATILE == 0)
        {
            return Status::INVALID_PARAMETER;
        }
        if self.read_only(guid, name) {
            return Status::WRITE_PROTECTED;
        }
        let deleting = attributes == 0 || (payload.is_empty() && !append);
        let state = |g: &Guid, n: &[u16]| self.store.find(g, n).map(|v| v.data.clone());
        let checked = self.policies.check(
            guid,
            name,
            stored,
            if deleting { 0 } else { payload.len() },
            existing.is_some(),
            state,
        );
        if checked != Status::SUCCESS {
            return checked;
        }
        let kind = auth::kind(guid, name);
        if kind.is_some() && !time_based && attributes != 0 {
            return Status::INVALID_PARAMETER;
        }
        let timestamp = match (&authenticated, kind) {
            (Some(a), Some(kind)) => {
                match self.check_secure_boot(kind, guid, name, attributes, a) {
                    Ok(()) => a.timestamp,
                    Err(status) => return status,
                }
            }
            (Some(a), None) => {
                match self.check_private(guid, name, attributes, a, existing.as_ref()) {
                    Ok(()) => a.timestamp,
                    Err(status) => return status,
                }
            }
            (None, _) => existing.as_ref().map(|v| v.timestamp).unwrap_or_default(),
        };
        if let (Some(a), Some(var)) = (&authenticated, &existing)
            && !auth::timestamp_ok(Some(var), &a.timestamp, append)
        {
            return Status::SECURITY_VIOLATION;
        }
        if deleting {
            let Some(i) = index else {
                return Status::NOT_FOUND;
            };
            if let Some(var) = self.store.remove(i) {
                self.dirty |= var.non_volatile();
            }
            if kind.is_some() {
                self.after_key_change();
            }
            return Status::SUCCESS;
        }
        let new_data = match (&existing, append) {
            (Some(var), true) if kind.is_some() => match siglist::append(&var.data, payload) {
                Some(merged) => merged,
                None => return Status::INVALID_PARAMETER,
            },
            (Some(var), true) => {
                let mut merged = var.data.clone();
                merged.extend_from_slice(payload);
                merged
            }
            _ => payload.to_vec(),
        };
        if name_size.saturating_add(new_data.len()) > MAX_VARIABLE_SIZE {
            return Status::OUT_OF_RESOURCES;
        }
        let var = Variable {
            guid: *guid,
            name: name.to_vec(),
            attributes: existing.as_ref().map_or(stored, |v| v.attributes),
            data: new_data,
            timestamp: match &existing {
                Some(old) if append && old.timestamp.later_than(&timestamp) => old.timestamp,
                _ => timestamp,
            },
        };
        let nv = var.non_volatile();
        let budget = if nv {
            NV_STORAGE_SIZE.min(self.image.capacity())
        } else {
            VOLATILE_STORAGE_SIZE
        };
        let others = self
            .store
            .used(nv)
            .saturating_sub(existing.as_ref().map_or(0, |v| v.stored_size()));
        if others.saturating_add(var.stored_size()) > budget {
            return Status::OUT_OF_RESOURCES;
        }
        self.store.put(index, var);
        self.dirty |= nv;
        if kind.is_some() {
            self.after_key_change();
        }
        Status::SUCCESS
    }

    /// Whether the guest may not write `name` in `guid` at all: the modes the service keeps,
    /// the read-only defaults, the signer records, and the variables locked at the end of DXE.
    fn read_only(&self, guid: &Guid, name: &[u16]) -> bool {
        let is = |s: &str| name.iter().copied().eq(s.encode_utf16());
        (*guid == GLOBAL_VARIABLE
            && ([
                SETUP_MODE,
                SECURE_BOOT,
                AUDIT_MODE,
                DEPLOYED_MODE,
                SIGNATURE_SUPPORT,
                VENDOR_KEYS,
            ]
            .iter()
            .any(|n| is(n))
                || DEFAULTS.iter().any(|n| is(n))))
            || *guid == CERT_DB
            || *guid == VENDOR_KEYS_NV
            || (self.end_of_dxe && self.locks.iter().any(|(g, n)| g == guid && n == name))
    }

    /// Check a write to a Secure Boot variable: in setup mode (no PK) any well-formed write
    /// goes, as edk2 without PcdRequireSelfSignedPk lets it; otherwise PK must be signed by
    /// the PK, KEK by the PK, and the databases by a KEK or the PK.
    fn check_secure_boot(
        &self,
        kind: auth::Kind,
        guid: &Guid,
        name: &[u16],
        attributes: u32,
        a: &auth::Authenticated<'_>,
    ) -> Result<(), Status> {
        let expected = NON_VOLATILE
            | BOOTSERVICE_ACCESS
            | RUNTIME_ACCESS
            | TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
        if attributes & STORED_ATTRIBUTES != expected {
            return Err(Status::INVALID_PARAMETER);
        }
        if !auth::payload_fits(kind, a.payload) {
            return Err(Status::INVALID_PARAMETER);
        }
        let pk = self.data(&GLOBAL_VARIABLE, "PK");
        let Some(pk) = pk else {
            return Ok(()); // setup mode
        };
        let content = auth::signed_content(name, guid, attributes, a);
        let kek = self.data(&GLOBAL_VARIABLE, "KEK");
        let keys: Vec<&[u8]> = match kind {
            auth::Kind::Pk | auth::Kind::Kek => vec![pk.as_slice()],
            auth::Kind::Db => kek
                .iter()
                .map(Vec::as_slice)
                .chain([pk.as_slice()])
                .collect(),
        };
        if auth::signed_by_any(a.signature, &content, &keys) {
            Ok(())
        } else {
            Err(Status::SECURITY_VIOLATION)
        }
    }

    /// Check a write to a private time-based authenticated variable: signed, and by the signer
    /// that created the variable (whose identity the service keeps once it does).
    fn check_private(
        &mut self,
        guid: &Guid,
        name: &[u16],
        attributes: u32,
        a: &auth::Authenticated<'_>,
        existing: Option<&Variable>,
    ) -> Result<(), Status> {
        let content = auth::signed_content(name, guid, attributes, a);
        let signer =
            auth::private_signer(a.signature, &content).ok_or(Status::SECURITY_VIOLATION)?;
        let mut records = self.signer_records();
        let known = records.iter().position(|(g, n, _)| g == guid && n == name);
        match (existing, known) {
            (Some(_), Some(i)) => {
                if records.get(i).is_none_or(|(_, _, s)| *s != signer) {
                    return Err(Status::SECURITY_VIOLATION);
                }
            }
            _ => {
                if let Some(i) = known {
                    records.remove(i);
                }
                records.push((*guid, name.to_vec(), signer));
                self.put_signer_records(&records);
            }
        }
        Ok(())
    }

    /// The private variables' signers: (vendor, name, signer).
    fn signer_records(&self) -> Vec<(Guid, Vec<u16>, [u8; 32])> {
        let mut out = Vec::new();
        let Some(data) = self.data(&CERT_DB, SIGNERS) else {
            return out;
        };
        let mut r = Reader::new(&data);
        while !r.rest().is_empty() {
            let record = (|| {
                let guid = r.guid()?;
                let len = usize::from(r.u16()?);
                let name = ucs2_name(r.take(len)?).ok_or(codec::Short)?;
                let mut signer = [0u8; 32];
                signer.copy_from_slice(r.take(32)?);
                Ok::<_, codec::Short>((guid, name, signer))
            })();
            match record {
                Ok(record) => out.push(record),
                Err(_) => break,
            }
        }
        out
    }

    fn put_signer_records(&mut self, records: &[(Guid, Vec<u16>, [u8; 32])]) {
        let mut data = Vec::new();
        for (guid, name, signer) in records {
            let bytes = ucs2_bytes(name);
            let Ok(len) = u16::try_from(bytes.len()) else {
                continue;
            };
            data.extend_from_slice(&guid.0);
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(&bytes);
            data.extend_from_slice(signer);
        }
        self.put_internal(CERT_DB, SIGNERS, NON_VOLATILE | BOOTSERVICE_ACCESS, data);
    }

    /// A variable's data, by namespace and name.
    fn data(&self, guid: &Guid, name: &str) -> Option<Vec<u8>> {
        self.store.find(guid, &utf16(name)).map(|v| v.data.clone())
    }

    /// Set a variable the service keeps itself, bypassing the guest's checks.
    fn put_internal(&mut self, guid: Guid, name: &str, attributes: u32, data: Vec<u8>) {
        let name = utf16(name);
        let index = self.store.position(&guid, &name);
        let var = Variable {
            guid,
            name,
            attributes,
            data,
            timestamp: EfiTime::default(),
        };
        self.dirty |= var.non_volatile();
        self.store.put(index, var);
    }

    /// Recompute SetupMode, SecureBoot and the rest after the PK, KEK or a database changed: the
    /// keys are no longer the vendor's.
    fn after_key_change(&mut self) {
        if self
            .store
            .find(&VENDOR_KEYS_NV, &utf16("VendorKeysNv"))
            .is_some()
        {
            let attributes = self
                .store
                .find(&VENDOR_KEYS_NV, &utf16("VendorKeysNv"))
                .map_or(NON_VOLATILE | BOOTSERVICE_ACCESS, |v| v.attributes);
            self.put_internal(VENDOR_KEYS_NV, "VendorKeysNv", attributes, vec![0]);
        }
        self.refresh_modes();
    }

    /// The volatile variables that describe the Secure Boot state, from the keys.
    fn refresh_modes(&mut self) {
        let rt = BOOTSERVICE_ACCESS | RUNTIME_ACCESS;
        let pk = self.store.find(&GLOBAL_VARIABLE, &utf16("PK")).is_some();
        let enabled = self
            .store
            .find(&SECURE_BOOT_ENABLE_DISABLE, &utf16("SecureBootEnable"))
            .is_none_or(|v| v.data.first() != Some(&0));
        let vendor = self
            .store
            .find(&VENDOR_KEYS_NV, &utf16("VendorKeysNv"))
            .map_or(1, |v| v.data.first().copied().unwrap_or(1));
        let mut support = Vec::new();
        for g in [
            guid::CERT_SHA1,
            guid::CERT_SHA256,
            guid::CERT_SHA384,
            guid::CERT_SHA512,
            guid::CERT_RSA2048,
            guid::CERT_X509,
        ] {
            support.extend_from_slice(&g.0);
        }
        self.put_internal(GLOBAL_VARIABLE, SETUP_MODE, rt, vec![u8::from(!pk)]);
        self.put_internal(
            GLOBAL_VARIABLE,
            SECURE_BOOT,
            rt,
            vec![u8::from(pk && enabled)],
        );
        self.put_internal(GLOBAL_VARIABLE, AUDIT_MODE, rt, vec![0]);
        self.put_internal(GLOBAL_VARIABLE, DEPLOYED_MODE, rt, vec![0]);
        self.put_internal(GLOBAL_VARIABLE, SIGNATURE_SUPPORT, rt, support);
        self.put_internal(GLOBAL_VARIABLE, VENDOR_KEYS, rt, vec![vendor]);
    }

    /// A one-line summary for the VMM's log: how many variables, and the Secure Boot state.
    pub fn summary(&self) -> String {
        let nv = self.store.iter().filter(|v| v.non_volatile()).count();
        let pk = self.store.find(&GLOBAL_VARIABLE, &utf16("PK")).is_some();
        format!(
            "{nv} non-volatile variables, {}",
            if pk {
                "Secure Boot keys enrolled"
            } else {
                "setup mode (no PK)"
            }
        )
    }

    /// A variable's name, for logs.
    pub fn describe(guid: &Guid, name: &[u16]) -> String {
        format!("{guid}:{}", display_name(name))
    }

    /// Whether `guid` is the image security database namespace (db, dbx, ...).
    pub fn is_security_database(guid: &Guid) -> bool {
        *guid == IMAGE_SECURITY_DATABASE
    }
}

/// The common head of a GET or SET access structure: (Guid, DataSize, Name), checked as edk2's
/// handler checks it: the name NUL-terminated, name and data within the payload.
fn access_header(p: &[u8]) -> Result<(Guid, usize, Vec<u16>), Status> {
    let parse = || -> Result<(Guid, u64, u64), codec::Short> {
        let mut r = Reader::new(p);
        let guid = r.guid()?;
        let data_size = r.u64()?;
        let name_size = r.u64()?;
        Ok((guid, data_size, name_size))
    };
    let (guid, data_size, name_size) = parse().map_err(|_| Status::ACCESS_DENIED)?;
    let data_size = usize::try_from(data_size).map_err(|_| Status::ACCESS_DENIED)?;
    let name_size = usize::try_from(name_size).map_err(|_| Status::ACCESS_DENIED)?;
    let info = ACCESS_NAME
        .checked_add(data_size)
        .and_then(|s| s.checked_add(name_size))
        .ok_or(Status::ACCESS_DENIED)?;
    if info > p.len() || name_size < 2 {
        return Err(Status::ACCESS_DENIED);
    }
    let name = get(p, ACCESS_NAME, name_size).map_err(|_| Status::ACCESS_DENIED)?;
    let name = ucs2_name(name).ok_or(Status::ACCESS_DENIED)?;
    Ok((guid, data_size, name))
}

/// The layout version of [`Service::save_transient`]'s bytes.
const TRANSIENT_VERSION: u8 = 1;

impl Service {
    /// What a snapshot keeps beyond the store file: the phase, the volatile variables (the
    /// firmware's BootCurrent, OsIndicationsSupported, ... which the OS reads at run time), the
    /// variable policies and the locks.
    pub fn save_transient(&self) -> Vec<u8> {
        let mut out = vec![
            TRANSIENT_VERSION,
            u8::from(self.end_of_dxe),
            u8::from(self.runtime),
        ];
        let (enabled, locked, policies) = self.policies.save();
        out.extend_from_slice(&[u8::from(enabled), u8::from(locked)]);
        let volatile: Vec<&Variable> = self.store.iter().filter(|v| !v.non_volatile()).collect();
        push_len(&mut out, volatile.len());
        for var in volatile {
            out.extend_from_slice(&var.guid.0);
            out.extend_from_slice(&var.attributes.to_le_bytes());
            push_bytes(&mut out, &ucs2_bytes(&var.name));
            push_bytes(&mut out, &var.data);
            out.extend_from_slice(&var.timestamp.0);
        }
        push_len(&mut out, policies.len());
        for entry in policies {
            push_bytes(&mut out, entry);
        }
        push_len(&mut out, self.locks.len());
        for (guid, name) in &self.locks {
            out.extend_from_slice(&guid.0);
            push_bytes(&mut out, &ucs2_bytes(name));
        }
        out
    }

    /// Put back what [`Service::save_transient`] kept, over the store file's variables.
    pub fn restore_transient(&mut self, bytes: &[u8]) -> Result<(), edk2::StoreError> {
        let bad = |_| edk2::StoreError::NotAStore("snapshot state");
        let mut r = Reader::new(bytes);
        if r.u8().map_err(bad)? != TRANSIENT_VERSION {
            return Err(edk2::StoreError::NotAStore("snapshot state version"));
        }
        let end_of_dxe = r.u8().map_err(bad)? != 0;
        let runtime = r.u8().map_err(bad)? != 0;
        let enabled = r.u8().map_err(bad)? != 0;
        let locked = r.u8().map_err(bad)? != 0;
        let mut volatile = Vec::new();
        for _ in 0..r.u32().map_err(bad)? {
            let guid = r.guid().map_err(bad)?;
            let attributes = r.u32().map_err(bad)?;
            let name = ucs2_name(take_bytes(&mut r).map_err(bad)?)
                .ok_or(edk2::StoreError::NotAStore("snapshot state name"))?;
            let data = take_bytes(&mut r).map_err(bad)?.to_vec();
            let mut ts = [0u8; 16];
            ts.copy_from_slice(r.take(16).map_err(bad)?);
            volatile.push(Variable {
                guid,
                name,
                attributes,
                data,
                timestamp: EfiTime(ts),
            });
        }
        let mut policies = Vec::new();
        for _ in 0..r.u32().map_err(bad)? {
            policies.push(take_bytes(&mut r).map_err(bad)?.to_vec());
        }
        let mut locks = Vec::new();
        for _ in 0..r.u32().map_err(bad)? {
            let guid = r.guid().map_err(bad)?;
            let name = ucs2_name(take_bytes(&mut r).map_err(bad)?)
                .ok_or(edk2::StoreError::NotAStore("snapshot state lock"))?;
            locks.push((guid, name));
        }
        let nv: Vec<Variable> = self
            .store
            .iter()
            .filter(|v| v.non_volatile())
            .cloned()
            .collect();
        self.store = Store::default();
        for var in nv.into_iter().chain(volatile) {
            let index = self.store.position(&var.guid, &var.name);
            self.store.put(index, var);
        }
        self.policies = Policies::restore(enabled, locked, &policies);
        self.locks = locks;
        self.end_of_dxe = end_of_dxe;
        self.runtime = runtime;
        Ok(())
    }
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes());
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn take_bytes<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], codec::Short> {
    let len = usize::try_from(r.u32()?).map_err(|_| codec::Short)?;
    r.take(len)
}
