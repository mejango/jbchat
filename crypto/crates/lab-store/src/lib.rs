//! Memory-only transactional workbench around the native MLS client core.
//!
//! The transaction is a copy-on-write snapshot of the *whole* lab state. It is
//! useful for exercising invariants, but it is not durable storage and has no
//! production crash or rollback guarantees.

pub mod harness;

use core::fmt;
use std::{collections::BTreeMap, sync::RwLock};

use juicebox_messaging_client_core as core_mls;
use openmls::prelude::GroupId;
use openmls_memory_storage::MemoryStorage;

pub use core_mls::Error as CoreError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failpoint {
    AfterMlsMutation,
    AfterOutboxAppend,
    AfterCommitOutboxBeforeWelcomeAttachment,
    AfterReplayRecord,
    AfterDomainRecord,
    BeforeCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireKind {
    KeyPackage,
    Commit,
    Application,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxRecord {
    pub envelope_id: String,
    pub kind: WireKind,
    pub exact_bytes: Vec<u8>,
    /// Targeted Welcome bytes attached to the one Commit transport record.
    /// A Welcome never receives a second envelope ID or log position.
    pub attached_welcome: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRecord {
    pub envelope_id: String,
    pub effect_number: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplayRecord {
    exact_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Core(CoreError),
    InvalidEnvelopeId,
    MissingGroup,
    GroupAlreadySet,
    Replay,
    IdempotencyConflict,
    OutboxEntryNotFound,
    InjectedCrash(Failpoint),
    StorageUnavailable,
}

impl Error {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Core(error) => error.code(),
            Self::InvalidEnvelopeId => "lab.invalid_envelope_id",
            Self::MissingGroup => "lab.missing_group",
            Self::GroupAlreadySet => "lab.group_already_set",
            Self::Replay => "lab.replay",
            Self::IdempotencyConflict => "lab.idempotency_conflict",
            Self::OutboxEntryNotFound => "lab.outbox_entry_not_found",
            Self::InjectedCrash(_) => "lab.injected_crash",
            Self::StorageUnavailable => "lab.storage_unavailable",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for Error {}

impl From<CoreError> for Error {
    fn from(value: CoreError) -> Self {
        Self::Core(value)
    }
}

struct StagedMetadata {
    outbox: Vec<OutboxRecord>,
    replay: BTreeMap<String, ReplayRecord>,
    domain: Vec<DomainRecord>,
    failpoint: Option<Failpoint>,
}

impl StagedMetadata {
    fn hit(&self, point: Failpoint) -> Result<(), Error> {
        if self.failpoint == Some(point) {
            Err(Error::InjectedCrash(point))
        } else {
            Ok(())
        }
    }

    fn append_outbox(
        &mut self,
        envelope_id: &str,
        kind: WireKind,
        exact_bytes: &[u8],
    ) -> Result<(), Error> {
        validate_envelope_id(envelope_id)?;
        if self
            .outbox
            .iter()
            .any(|record| record.envelope_id == envelope_id)
        {
            return Err(Error::IdempotencyConflict);
        }
        self.outbox.push(OutboxRecord {
            envelope_id: envelope_id.to_owned(),
            kind,
            exact_bytes: exact_bytes.to_vec(),
            attached_welcome: None,
        });
        Ok(())
    }

    fn append_commit_with_welcome(
        &mut self,
        envelope_id: &str,
        exact_commit: &[u8],
        exact_welcome: &[u8],
    ) -> Result<(), Error> {
        self.append_outbox(envelope_id, WireKind::Commit, exact_commit)?;
        self.hit(Failpoint::AfterCommitOutboxBeforeWelcomeAttachment)?;
        let record = self.outbox.last_mut().ok_or(Error::StorageUnavailable)?;
        record.attached_welcome = Some(exact_welcome.to_vec());
        Ok(())
    }

    fn check_replay(&self, envelope_id: &str, exact_bytes: &[u8]) -> Result<(), Error> {
        validate_envelope_id(envelope_id)?;
        match self.replay.get(envelope_id) {
            Some(record) if record.exact_bytes == exact_bytes => Err(Error::Replay),
            Some(_) => Err(Error::IdempotencyConflict),
            None => Ok(()),
        }
    }

    fn record_incoming(
        &mut self,
        envelope_id: &str,
        exact_bytes: &[u8],
        has_domain_effect: bool,
    ) -> Result<(), Error> {
        self.replay.insert(
            envelope_id.to_owned(),
            ReplayRecord {
                exact_bytes: exact_bytes.to_vec(),
            },
        );
        self.hit(Failpoint::AfterReplayRecord)?;
        if has_domain_effect {
            let effect_number = u64::try_from(self.domain.len())
                .map_err(|_| Error::StorageUnavailable)?
                .checked_add(1)
                .ok_or(Error::StorageUnavailable)?;
            self.domain.push(DomainRecord {
                envelope_id: envelope_id.to_owned(),
                effect_number,
            });
        }
        Ok(())
    }
}

/// Whole-state copy-on-write transaction owner.
#[derive(Default)]
pub struct LabStore {
    mls: MemoryStorage,
    outbox: Vec<OutboxRecord>,
    replay: BTreeMap<String, ReplayRecord>,
    domain: Vec<DomainRecord>,
    next_failpoint: Option<Failpoint>,
    revision: u64,
}

impl LabStore {
    fn transact<T>(
        &mut self,
        operation: impl FnOnce(
            &core_mls::ProfileProvider<MemoryStorage>,
            &mut StagedMetadata,
        ) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let staged_storage = clone_memory_storage(&self.mls)?;
        let provider = core_mls::ProfileProvider::new(staged_storage);
        let mut metadata = StagedMetadata {
            outbox: self.outbox.clone(),
            replay: self.replay.clone(),
            domain: self.domain.clone(),
            failpoint: self.next_failpoint.take(),
        };

        let result = operation(&provider, &mut metadata)?;
        metadata.hit(Failpoint::BeforeCommit)?;
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::StorageUnavailable)?;

        self.mls = provider.into_storage();
        self.outbox = metadata.outbox;
        self.replay = metadata.replay;
        self.domain = metadata.domain;
        self.revision = next_revision;
        Ok(result)
    }

    pub fn inject_once(&mut self, failpoint: Failpoint) {
        self.next_failpoint = Some(failpoint);
    }

    pub fn outbox(&self) -> &[OutboxRecord] {
        &self.outbox
    }

    pub fn domain_records(&self) -> &[DomainRecord] {
        &self.domain
    }

    /// Retry the complete, immutable transport unit. For an Add this returns
    /// the Commit and its attached targeted Welcome together.
    pub fn retry_delivery(&self, envelope_id: &str) -> Result<OutboxRecord, Error> {
        self.outbox
            .iter()
            .find(|record| record.envelope_id == envelope_id)
            .cloned()
            .ok_or(Error::OutboxEntryNotFound)
    }

    pub fn storage_cell_count(&self) -> Result<usize, Error> {
        self.mls
            .values
            .read()
            .map(|values| values.len())
            .map_err(|_| Error::StorageUnavailable)
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// One synthetic installation in the native lab.
pub struct LabClient {
    identity: core_mls::SyntheticIdentity,
    store: LabStore,
    group_id: Option<GroupId>,
}

/// Disposable copy of exactly the MLS state retained at one instant. It has
/// no identity object and exposes decryption only, so the test harness can ask
/// what a current-state compromise can read without granting a second writer.
pub struct CompromisedRetainedState {
    provider: core_mls::ProfileProvider<MemoryStorage>,
    group_id: GroupId,
}

impl CompromisedRetainedState {
    pub fn open(&mut self, exact_ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut group = core_mls::load_group(&self.provider, &self.group_id)?;
        core_mls::open_application(&mut group, &self.provider, exact_ciphertext).map_err(Into::into)
    }
}

impl LabClient {
    pub fn new(label: &str) -> Result<Self, Error> {
        let mut store = LabStore::default();
        let identity = store.transact(|provider, _| {
            core_mls::create_synthetic_identity(provider, label).map_err(Into::into)
        })?;
        Ok(Self {
            identity,
            store,
            group_id: None,
        })
    }

    pub fn create_group(&mut self, group_id: &[u8]) -> Result<(), Error> {
        if self.group_id.is_some() {
            return Err(Error::GroupAlreadySet);
        }
        if group_id.is_empty() || group_id.len() > 64 {
            return Err(Error::MissingGroup);
        }
        let group_id = GroupId::from_slice(group_id);
        let identity = &self.identity;
        let committed_group_id = group_id.clone();
        self.store.transact(|provider, _| {
            core_mls::create_group(provider, identity, group_id)
                .map(|_| ())
                .map_err(Into::into)
        })?;
        self.group_id = Some(committed_group_id);
        Ok(())
    }

    pub fn publish_key_package(&mut self, envelope_id: &str) -> Result<Vec<u8>, Error> {
        let identity = &self.identity;
        self.store.transact(|provider, metadata| {
            let bytes = core_mls::generate_key_package(provider, identity)?;
            metadata.hit(Failpoint::AfterMlsMutation)?;
            metadata.append_outbox(envelope_id, WireKind::KeyPackage, &bytes)?;
            metadata.hit(Failpoint::AfterOutboxAppend)?;
            Ok(bytes)
        })
    }

    pub fn add_member(
        &mut self,
        key_package_bytes: &[u8],
        commit_envelope_id: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let group_id = self.group_id.clone().ok_or(Error::MissingGroup)?;
        let identity = &self.identity;
        self.store.transact(|provider, metadata| {
            let key_package = core_mls::decode_key_package(provider, key_package_bytes)?;
            let mut group = core_mls::load_group(provider, &group_id)?;
            let (commit, welcome) =
                core_mls::add_member(&mut group, provider, identity, &key_package)?;
            metadata.hit(Failpoint::AfterMlsMutation)?;
            metadata.append_commit_with_welcome(commit_envelope_id, &commit, &welcome)?;
            metadata.hit(Failpoint::AfterOutboxAppend)?;
            Ok((commit, welcome))
        })
    }

    pub fn join(&mut self, welcome_bytes: &[u8]) -> Result<(), Error> {
        if self.group_id.is_some() {
            return Err(Error::GroupAlreadySet);
        }
        let group_id = self.store.transact(|provider, _| {
            let group = core_mls::join_from_welcome(provider, welcome_bytes)?;
            Ok(group.group_id().clone())
        })?;
        self.group_id = Some(group_id);
        Ok(())
    }

    pub fn seal(
        &mut self,
        envelope_id: &str,
        synthetic_plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let group_id = self.group_id.clone().ok_or(Error::MissingGroup)?;
        let identity = &self.identity;
        self.store.transact(|provider, metadata| {
            let mut group = core_mls::load_group(provider, &group_id)?;
            let bytes =
                core_mls::seal_application(&mut group, provider, identity, synthetic_plaintext)?;
            metadata.hit(Failpoint::AfterMlsMutation)?;
            metadata.append_outbox(envelope_id, WireKind::Application, &bytes)?;
            metadata.hit(Failpoint::AfterOutboxAppend)?;
            Ok(bytes)
        })
    }

    pub fn open(&mut self, envelope_id: &str, exact_ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let group_id = self.group_id.clone().ok_or(Error::MissingGroup)?;
        self.store.transact(|provider, metadata| {
            metadata.check_replay(envelope_id, exact_ciphertext)?;
            let mut group = core_mls::load_group(provider, &group_id)?;
            let plaintext = core_mls::open_application(&mut group, provider, exact_ciphertext)?;
            metadata.hit(Failpoint::AfterMlsMutation)?;
            metadata.record_incoming(envelope_id, exact_ciphertext, true)?;
            metadata.hit(Failpoint::AfterDomainRecord)?;
            Ok(plaintext)
        })
    }

    pub fn update(&mut self, commit_envelope_id: &str) -> Result<Vec<u8>, Error> {
        let group_id = self.group_id.clone().ok_or(Error::MissingGroup)?;
        let identity = &self.identity;
        self.store.transact(|provider, metadata| {
            let mut group = core_mls::load_group(provider, &group_id)?;
            let commit = core_mls::self_update(&mut group, provider, identity)?;
            metadata.hit(Failpoint::AfterMlsMutation)?;
            metadata.append_outbox(commit_envelope_id, WireKind::Commit, &commit)?;
            metadata.hit(Failpoint::AfterOutboxAppend)?;
            Ok(commit)
        })
    }

    pub fn remove(
        &mut self,
        synthetic_label: &str,
        commit_envelope_id: &str,
    ) -> Result<Vec<u8>, Error> {
        let group_id = self.group_id.clone().ok_or(Error::MissingGroup)?;
        let identity = &self.identity;
        self.store.transact(|provider, metadata| {
            let mut group = core_mls::load_group(provider, &group_id)?;
            let target = core_mls::find_member(
                &group,
                &core_mls::synthetic_credential_content(synthetic_label)?,
            )?;
            let commit = core_mls::remove_member(&mut group, provider, identity, target)?;
            metadata.hit(Failpoint::AfterMlsMutation)?;
            metadata.append_outbox(commit_envelope_id, WireKind::Commit, &commit)?;
            metadata.hit(Failpoint::AfterOutboxAppend)?;
            Ok(commit)
        })
    }

    pub fn process_commit(&mut self, envelope_id: &str, exact_commit: &[u8]) -> Result<(), Error> {
        let group_id = self.group_id.clone().ok_or(Error::MissingGroup)?;
        self.store.transact(|provider, metadata| {
            metadata.check_replay(envelope_id, exact_commit)?;
            let mut group = core_mls::load_group(provider, &group_id)?;
            core_mls::process_commit(&mut group, provider, exact_commit)?;
            metadata.hit(Failpoint::AfterMlsMutation)?;
            metadata.record_incoming(envelope_id, exact_commit, false)?;
            Ok(())
        })
    }

    pub fn is_active(&self) -> Result<bool, Error> {
        let group_id = self.group_id.clone().ok_or(Error::MissingGroup)?;
        let storage = clone_memory_storage(&self.store.mls)?;
        let provider = core_mls::ProfileProvider::new(storage);
        let group = core_mls::load_group(&provider, &group_id)?;
        Ok(group.is_active())
    }

    pub fn inject_once(&mut self, failpoint: Failpoint) {
        self.store.inject_once(failpoint);
    }

    pub fn retry_delivery(&self, envelope_id: &str) -> Result<OutboxRecord, Error> {
        self.store.retry_delivery(envelope_id)
    }

    pub fn outbox(&self) -> &[OutboxRecord] {
        self.store.outbox()
    }

    pub fn domain_records(&self) -> &[DomainRecord] {
        self.store.domain_records()
    }

    pub fn storage_cell_count(&self) -> Result<usize, Error> {
        self.store.storage_cell_count()
    }

    pub const fn revision(&self) -> u64 {
        self.store.revision()
    }

    pub fn compromise_current_retained_state(&self) -> Result<CompromisedRetainedState, Error> {
        let group_id = self.group_id.clone().ok_or(Error::MissingGroup)?;
        let storage = clone_memory_storage(&self.store.mls)?;
        Ok(CompromisedRetainedState {
            provider: core_mls::ProfileProvider::new(storage),
            group_id,
        })
    }
}

fn clone_memory_storage(source: &MemoryStorage) -> Result<MemoryStorage, Error> {
    let values = source
        .values
        .read()
        .map_err(|_| Error::StorageUnavailable)?
        .clone();
    Ok(MemoryStorage {
        values: RwLock::new(values),
    })
}

fn validate_envelope_id(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Err(Error::InvalidEnvelopeId)
    } else {
        Ok(())
    }
}
