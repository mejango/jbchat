//! Provider-neutral G1 lab harness (launch-gates.md section 3.1).
//!
//! `CandidateLabClient` is the common domain API both protocol candidates
//! must implement; the [`scenarios`] module holds the shared synthetic
//! scenarios written only against that trait, so Candidate A (the native
//! OpenMLS lab) and any Candidate B adapter run byte-for-byte identical
//! assertions. Adversarial input construction that requires provider
//! tooling (off-profile key packages, wire-format probes) stays in each
//! candidate's own test crate; the behavior asserted here — atomicity,
//! replay identity, idempotency, forward secrecy of retained state, and the
//! closed one-group lifecycle — is the frozen profile itself. Diagnostic
//! code equality is intentional: stable non-secret codes are part of the
//! profile (verification.md CRY-14), so a candidate that cannot emit them
//! fails rather than adapting the profile.

use crate::{DomainRecord, Error, Failpoint, OutboxRecord};

/// A read-only capture of exactly the retained state at one instant.
pub trait CandidateCompromisedState {
    fn open(&mut self, exact_ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}

/// The provider-neutral domain surface of one synthetic installation.
pub trait CandidateLabClient: Sized {
    type Compromise: CandidateCompromisedState;

    fn new(label: &str) -> Result<Self, Error>;
    fn create_group(&mut self, group_id: &[u8]) -> Result<(), Error>;
    fn publish_key_package(&mut self, envelope_id: &str) -> Result<Vec<u8>, Error>;
    fn add_member(
        &mut self,
        key_package_bytes: &[u8],
        commit_envelope_id: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), Error>;
    fn join(&mut self, welcome_bytes: &[u8]) -> Result<(), Error>;
    fn seal(&mut self, envelope_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    fn open(&mut self, envelope_id: &str, exact_ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
    fn update(&mut self, commit_envelope_id: &str) -> Result<Vec<u8>, Error>;
    fn remove(&mut self, label: &str, commit_envelope_id: &str) -> Result<Vec<u8>, Error>;
    fn process_commit(&mut self, envelope_id: &str, exact_commit: &[u8]) -> Result<(), Error>;
    fn is_active(&self) -> Result<bool, Error>;
    fn inject_once(&mut self, failpoint: Failpoint);
    fn retry_delivery(&self, envelope_id: &str) -> Result<OutboxRecord, Error>;
    fn outbox(&self) -> &[OutboxRecord];
    fn domain_records(&self) -> &[DomainRecord];
    fn revision(&self) -> u64;
    fn storage_cell_count(&self) -> Result<usize, Error>;
    fn compromise_current_retained_state(&self) -> Result<Self::Compromise, Error>;
}

impl CandidateCompromisedState for crate::CompromisedRetainedState {
    fn open(&mut self, exact_ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        Self::open(self, exact_ciphertext)
    }
}

impl CandidateLabClient for crate::LabClient {
    type Compromise = crate::CompromisedRetainedState;

    fn new(label: &str) -> Result<Self, Error> {
        Self::new(label)
    }
    fn create_group(&mut self, group_id: &[u8]) -> Result<(), Error> {
        Self::create_group(self, group_id)
    }
    fn publish_key_package(&mut self, envelope_id: &str) -> Result<Vec<u8>, Error> {
        Self::publish_key_package(self, envelope_id)
    }
    fn add_member(
        &mut self,
        key_package_bytes: &[u8],
        commit_envelope_id: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        Self::add_member(self, key_package_bytes, commit_envelope_id)
    }
    fn join(&mut self, welcome_bytes: &[u8]) -> Result<(), Error> {
        Self::join(self, welcome_bytes)
    }
    fn seal(&mut self, envelope_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        Self::seal(self, envelope_id, plaintext)
    }
    fn open(&mut self, envelope_id: &str, exact_ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        Self::open(self, envelope_id, exact_ciphertext)
    }
    fn update(&mut self, commit_envelope_id: &str) -> Result<Vec<u8>, Error> {
        Self::update(self, commit_envelope_id)
    }
    fn remove(&mut self, label: &str, commit_envelope_id: &str) -> Result<Vec<u8>, Error> {
        Self::remove(self, label, commit_envelope_id)
    }
    fn process_commit(&mut self, envelope_id: &str, exact_commit: &[u8]) -> Result<(), Error> {
        Self::process_commit(self, envelope_id, exact_commit)
    }
    fn is_active(&self) -> Result<bool, Error> {
        Self::is_active(self)
    }
    fn inject_once(&mut self, failpoint: Failpoint) {
        Self::inject_once(self, failpoint);
    }
    fn retry_delivery(&self, envelope_id: &str) -> Result<OutboxRecord, Error> {
        Self::retry_delivery(self, envelope_id)
    }
    fn outbox(&self) -> &[OutboxRecord] {
        Self::outbox(self)
    }
    fn domain_records(&self) -> &[DomainRecord] {
        Self::domain_records(self)
    }
    fn revision(&self) -> u64 {
        Self::revision(self)
    }
    fn storage_cell_count(&self) -> Result<usize, Error> {
        Self::storage_cell_count(self)
    }
    fn compromise_current_retained_state(&self) -> Result<Self::Compromise, Error> {
        Self::compromise_current_retained_state(self)
    }
}

/// The common synthetic scenarios. Every function panics on violation so a
/// candidate binds each one into a plain `#[test]`.
pub mod scenarios {
    use super::{CandidateCompromisedState, CandidateLabClient};
    use crate::{Error, Failpoint, WireKind};

    const SEND_FAILPOINTS: [Failpoint; 3] = [
        Failpoint::AfterMlsMutation,
        Failpoint::AfterOutboxAppend,
        Failpoint::BeforeCommit,
    ];
    fn must<T>(result: Result<T, Error>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("harness scenario operation failed: {error}"),
        }
    }

    /// Reads a scale knob so `check` stays fast while an evidence run can be
    /// executed at the spec-mandated count with one environment variable.
    fn scale(variable: &str, default: usize) -> usize {
        std::env::var(variable)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    pub fn joined_pair<C: CandidateLabClient>() -> (C, C, Vec<u8>) {
        let mut alice = must(C::new("alice"));
        let mut bob = must(C::new("bob"));
        must(alice.create_group(b"deterministic-lab-group"));
        let pre_join = must(alice.seal("application:alice:prejoin", b"pre-join history"));
        let key_package = must(bob.publish_key_package("key-package:bob:1"));
        let (_commit, welcome) = must(alice.add_member(&key_package, "commit:add:bob:1"));
        must(bob.join(&welcome));
        (alice, bob, pre_join)
    }

    pub fn lifecycle_and_history_boundaries<C: CandidateLabClient>() {
        let (mut alice, mut bob, pre_join) = joined_pair::<C>();
        assert!(bob.open("incoming:prejoin", &pre_join).is_err());

        let alice_message = must(alice.seal("application:alice:1", b"hello from alice"));
        assert_eq!(
            must(bob.open("incoming:alice:1", &alice_message)),
            b"hello from alice"
        );
        let bob_message = must(bob.seal("application:bob:1", b"hello from bob"));
        assert_eq!(
            must(alice.open("incoming:bob:1", &bob_message)),
            b"hello from bob"
        );

        let update = must(bob.update("commit:update:bob:1"));
        must(alice.process_commit("incoming:commit:update:bob:1", &update));
        let after_update = must(alice.seal("application:alice:2", b"after update"));
        assert_eq!(
            must(bob.open("incoming:alice:2", &after_update)),
            b"after update"
        );

        let remove = must(alice.remove("bob", "commit:remove:bob:1"));
        must(bob.process_commit("incoming:commit:remove:bob:1", &remove));
        assert!(!must(bob.is_active()));

        let after_remove = must(alice.seal("application:alice:3", b"after removal"));
        assert!(bob.open("incoming:alice:3", &after_remove).is_err());
        let removed_send = bob.seal("application:bob:removed", b"must not send");
        assert_eq!(
            removed_send.err().map(|error| error.code()),
            Some("mls.inactive_group")
        );
    }

    pub fn add_is_one_commit_record_with_attached_welcome<C: CandidateLabClient>() {
        let (alice, _bob, _pre_join) = joined_pair::<C>();
        let add_record = alice
            .outbox()
            .iter()
            .find(|record| record.envelope_id == "commit:add:bob:1")
            .cloned()
            .unwrap_or_else(|| panic!("missing Add Commit outbox record"));
        assert_eq!(add_record.kind, WireKind::Commit);
        assert!(add_record.attached_welcome.is_some());
        assert_eq!(must(alice.retry_delivery("commit:add:bob:1")), add_record);
        assert_eq!(
            alice
                .outbox()
                .iter()
                .filter(|record| record.envelope_id == "commit:add:bob:1")
                .count(),
            1
        );
    }

    pub fn replay_and_conflict_have_no_second_domain_effect<C: CandidateLabClient>() {
        let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
        let ciphertext = must(alice.seal("application:alice:replay", b"apply once"));
        assert_eq!(
            must(bob.open("incoming:replay:1", &ciphertext)),
            b"apply once"
        );
        let effects = bob.domain_records().len();

        assert_eq!(
            bob.open("incoming:replay:1", &ciphertext),
            Err(Error::Replay)
        );
        assert!(bob.open("incoming:replay:2", &ciphertext).is_err());
        let mut conflicting = ciphertext.clone();
        conflicting.push(0);
        assert_eq!(
            bob.open("incoming:replay:1", &conflicting),
            Err(Error::IdempotencyConflict)
        );
        assert_eq!(bob.domain_records().len(), effects);
    }

    pub fn trailing_bytes_are_rejected_without_consuming_state<C: CandidateLabClient>() {
        let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
        let ciphertext = must(alice.seal("application:alice:trailing", b"strict decode"));
        let mut malformed = ciphertext.clone();
        malformed.push(0x42);
        assert!(bob.open("incoming:trailing:bad", &malformed).is_err());
        assert_eq!(
            must(bob.open("incoming:trailing:good", &ciphertext)),
            b"strict decode"
        );
    }

    pub fn retry_uses_the_exact_committed_ciphertext<C: CandidateLabClient>() {
        let (mut alice, _bob, _pre_join) = joined_pair::<C>();
        let ciphertext = must(alice.seal("application:alice:retry", b"exact retry"));
        assert_eq!(
            must(alice.retry_delivery("application:alice:retry")).exact_bytes,
            ciphertext
        );
    }

    pub fn retained_state_cannot_open_old_epoch_ciphertext<C: CandidateLabClient>() {
        let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
        let old_epoch = must(alice.seal("application:alice:old-epoch", b"old epoch secret"));

        let update = must(bob.update("commit:update:bob:forward-secrecy"));
        must(alice.process_commit("incoming:commit:update:bob:forward-secrecy", &update));
        let mut compromised = must(bob.compromise_current_retained_state());
        assert!(compromised.open(&old_epoch).is_err());

        let current_epoch =
            must(alice.seal("application:alice:current-epoch", b"current epoch works"));
        assert_eq!(
            must(bob.open("incoming:alice:current-epoch", &current_epoch)),
            b"current epoch works"
        );
    }

    pub fn send_failpoints_roll_back_whole_state_and_outbox<C: CandidateLabClient>() {
        for failpoint in SEND_FAILPOINTS {
            let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
            let before_revision = alice.revision();
            let before_outbox = alice.outbox().len();
            alice.inject_once(failpoint);

            assert_eq!(
                alice.seal("application:alice:crash", b"rollback then retry"),
                Err(Error::InjectedCrash(failpoint))
            );
            assert_eq!(alice.revision(), before_revision);
            assert_eq!(alice.outbox().len(), before_outbox);
            assert_eq!(
                alice.retry_delivery("application:alice:crash"),
                Err(Error::OutboxEntryNotFound)
            );

            let retry = must(alice.seal("application:alice:crash", b"rollback then retry"));
            assert_eq!(
                must(bob.open("incoming:alice:crash", &retry)),
                b"rollback then retry"
            );
        }
    }

    pub fn add_crash_cannot_commit_without_its_targeted_welcome<C: CandidateLabClient>() {
        for failpoint in [
            Failpoint::AfterMlsMutation,
            Failpoint::AfterCommitOutboxBeforeWelcomeAttachment,
            Failpoint::AfterOutboxAppend,
            Failpoint::BeforeCommit,
        ] {
            let mut alice = must(C::new("alice"));
            let mut bob = must(C::new("bob"));
            must(alice.create_group(b"add-crash-group"));
            let key_package = must(bob.publish_key_package("key-package:bob:add-crash"));
            let before_revision = alice.revision();
            let before_outbox = alice.outbox().len();
            alice.inject_once(failpoint);

            assert_eq!(
                alice.add_member(&key_package, "commit:add:bob:crash"),
                Err(Error::InjectedCrash(failpoint))
            );
            assert_eq!(alice.revision(), before_revision);
            assert_eq!(alice.outbox().len(), before_outbox);
            assert_eq!(
                alice.retry_delivery("commit:add:bob:crash"),
                Err(Error::OutboxEntryNotFound)
            );

            let (_commit, welcome) = must(alice.add_member(&key_package, "commit:add:bob:crash"));
            must(bob.join(&welcome));
            let message = must(alice.seal("application:alice:add-crash", b"joined atomically"));
            assert_eq!(
                must(bob.open("incoming:alice:add-crash", &message)),
                b"joined atomically"
            );
        }
    }

    pub fn receive_failpoints_roll_back_mls_replay_and_domain_effect<C: CandidateLabClient>() {
        let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
        let ciphertext = must(alice.seal("application:alice:receive-crash", b"one effect"));
        let before_revision = bob.revision();
        let before_effects = bob.domain_records().len();
        for failpoint in [
            Failpoint::AfterMlsMutation,
            Failpoint::AfterReplayRecord,
            Failpoint::AfterDomainRecord,
            Failpoint::BeforeCommit,
        ] {
            bob.inject_once(failpoint);
            assert_eq!(
                bob.open("incoming:receive-crash", &ciphertext),
                Err(Error::InjectedCrash(failpoint))
            );
            assert_eq!(bob.revision(), before_revision);
            assert_eq!(bob.domain_records().len(), before_effects);
        }

        assert_eq!(
            must(bob.open("incoming:receive-crash", &ciphertext)),
            b"one effect"
        );
        assert_eq!(bob.domain_records().len(), before_effects + 1);
    }

    pub fn key_package_publication_and_join_roll_back_for_exact_retry<C: CandidateLabClient>() {
        for failpoint in SEND_FAILPOINTS {
            let mut bob = must(C::new("bob"));
            let before_revision = bob.revision();
            let before_cells = must(bob.storage_cell_count());
            bob.inject_once(failpoint);
            assert_eq!(
                bob.publish_key_package("key-package:bob:publication-crash"),
                Err(Error::InjectedCrash(failpoint))
            );
            assert_eq!(bob.revision(), before_revision);
            assert_eq!(must(bob.storage_cell_count()), before_cells);
            assert_eq!(
                bob.retry_delivery("key-package:bob:publication-crash"),
                Err(Error::OutboxEntryNotFound)
            );
            let key_package = must(bob.publish_key_package("key-package:bob:publication-crash"));
            assert_eq!(
                must(bob.retry_delivery("key-package:bob:publication-crash")).exact_bytes,
                key_package
            );
        }

        let mut alice = must(C::new("alice"));
        let mut bob = must(C::new("bob"));
        must(alice.create_group(b"welcome-join-crash"));
        let key_package = must(bob.publish_key_package("key-package:bob:welcome-crash"));
        let (_commit, welcome) =
            must(alice.add_member(&key_package, "commit:add:bob:welcome-crash"));
        let before_revision = bob.revision();
        let before_cells = must(bob.storage_cell_count());
        bob.inject_once(Failpoint::BeforeCommit);
        assert_eq!(
            bob.join(&welcome),
            Err(Error::InjectedCrash(Failpoint::BeforeCommit))
        );
        assert_eq!(bob.revision(), before_revision);
        assert_eq!(must(bob.storage_cell_count()), before_cells);
        assert_eq!(bob.is_active(), Err(Error::MissingGroup));

        must(bob.join(&welcome));
        let message = must(alice.seal("application:alice:welcome-retry", b"welcome retry"));
        assert_eq!(
            must(bob.open("incoming:alice:welcome-retry", &message)),
            b"welcome retry"
        );
    }

    pub fn incoming_commit_failpoints_roll_back_epoch_and_replay_state<C: CandidateLabClient>() {
        for failpoint in [
            Failpoint::AfterMlsMutation,
            Failpoint::AfterReplayRecord,
            Failpoint::BeforeCommit,
        ] {
            let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
            let update = must(bob.update("commit:update:bob:incoming-crash"));
            let before_revision = alice.revision();
            let before_effects = alice.domain_records().len();
            alice.inject_once(failpoint);
            assert_eq!(
                alice.process_commit("incoming:commit:update:bob:incoming-crash", &update),
                Err(Error::InjectedCrash(failpoint))
            );
            assert_eq!(alice.revision(), before_revision);
            assert_eq!(alice.domain_records().len(), before_effects);

            must(alice.process_commit("incoming:commit:update:bob:incoming-crash", &update));
            let current = must(bob.seal("application:bob:after-commit-retry", b"same epoch"));
            assert_eq!(
                must(alice.open("incoming:bob:after-commit-retry", &current)),
                b"same epoch"
            );
        }
    }

    pub fn update_and_remove_failpoints_roll_back_epoch_and_membership<C: CandidateLabClient>() {
        for failpoint in SEND_FAILPOINTS {
            let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
            let before_revision = bob.revision();
            let before_outbox = bob.outbox().len();
            bob.inject_once(failpoint);
            assert_eq!(
                bob.update("commit:update:bob:outgoing-crash"),
                Err(Error::InjectedCrash(failpoint))
            );
            assert_eq!(bob.revision(), before_revision);
            assert_eq!(bob.outbox().len(), before_outbox);
            let update = must(bob.update("commit:update:bob:outgoing-crash"));
            must(alice.process_commit("incoming:commit:update:bob:outgoing-crash", &update));

            let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
            let before_revision = alice.revision();
            let before_outbox = alice.outbox().len();
            alice.inject_once(failpoint);
            assert_eq!(
                alice.remove("bob", "commit:remove:bob:outgoing-crash"),
                Err(Error::InjectedCrash(failpoint))
            );
            assert_eq!(alice.revision(), before_revision);
            assert_eq!(alice.outbox().len(), before_outbox);
            assert!(must(bob.is_active()));
            let remove = must(alice.remove("bob", "commit:remove:bob:outgoing-crash"));
            must(bob.process_commit("incoming:commit:remove:bob:outgoing-crash", &remove));
            assert!(!must(bob.is_active()));
        }
    }

    pub fn outgoing_envelope_conflict_rolls_back_sender_state<C: CandidateLabClient>() {
        let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
        let first = must(alice.seal("application:alice:conflict", b"first"));
        let before_revision = alice.revision();
        let before_outbox = alice.outbox().len();
        assert_eq!(
            alice.seal("application:alice:conflict", b"must roll back"),
            Err(Error::IdempotencyConflict)
        );
        assert_eq!(alice.revision(), before_revision);
        assert_eq!(alice.outbox().len(), before_outbox);
        assert_eq!(
            must(bob.open("incoming:alice:conflict:first", &first)),
            b"first"
        );

        let next = must(alice.seal("application:alice:after-conflict", b"next generation"));
        assert_eq!(
            must(bob.open("incoming:alice:after-conflict", &next)),
            b"next generation"
        );
    }

    pub fn one_group_client_rejects_silent_group_repointing<C: CandidateLabClient>() {
        let mut alice = must(C::new("alice"));
        must(alice.create_group(b"one-group-only"));
        let before_revision = alice.revision();
        assert_eq!(
            alice.create_group(b"must-not-repoint"),
            Err(Error::GroupAlreadySet)
        );
        assert_eq!(alice.revision(), before_revision);
    }

    /// PRO-07-shaped replay storm. `JBM_G1_REPLAY_COUNT` scales the count;
    /// the evidence run uses the spec's 100,000, `check` defaults to 1,000.
    /// Every envelope produces exactly one transcript entry and one domain
    /// effect, and every replay and conflicting reuse produces zero.
    pub fn replay_storm_has_exactly_one_effect_per_envelope<C: CandidateLabClient>() {
        let count = scale("JBM_G1_REPLAY_COUNT", 1_000);
        let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
        let before_effects = bob.domain_records().len();
        let mut envelopes = Vec::with_capacity(count);
        for index in 0..count {
            let ciphertext = must(alice.seal(
                &format!("application:alice:storm:{index}"),
                format!("storm payload {index}").as_bytes(),
            ));
            assert_eq!(
                must(bob.open(&format!("incoming:storm:{index}"), &ciphertext)),
                format!("storm payload {index}").as_bytes()
            );
            envelopes.push(ciphertext);
        }
        assert_eq!(bob.domain_records().len(), before_effects + count);

        for (index, ciphertext) in envelopes.iter().enumerate() {
            assert_eq!(
                bob.open(&format!("incoming:storm:{index}"), ciphertext),
                Err(Error::Replay)
            );
            let mut conflicting = ciphertext.clone();
            conflicting.push(0);
            assert_eq!(
                bob.open(&format!("incoming:storm:{index}"), &conflicting),
                Err(Error::IdempotencyConflict)
            );
        }
        assert_eq!(bob.domain_records().len(), before_effects + count);
    }

    /// PRO-10-shaped kill loop. `JBM_G1_KILLS_PER_FAILPOINT` scales toward
    /// the spec's 1,000 kills per point; `check` defaults to 100. Each
    /// failpoint is killed repeatedly on the operation path where it fires,
    /// the state must roll back whole every time, and the exact operation
    /// must then succeed once.
    pub fn failpoint_kill_loop_never_leaks_partial_state<C: CandidateLabClient>() {
        let kills = scale("JBM_G1_KILLS_PER_FAILPOINT", 100);

        // Send path: repeated kills of the same seal, then one clean retry.
        for failpoint in SEND_FAILPOINTS {
            let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
            let before_revision = alice.revision();
            let before_outbox = alice.outbox().len();
            for _ in 0..kills {
                alice.inject_once(failpoint);
                assert_eq!(
                    alice.seal("application:alice:kill", b"kill loop payload"),
                    Err(Error::InjectedCrash(failpoint))
                );
                assert_eq!(alice.revision(), before_revision);
                assert_eq!(alice.outbox().len(), before_outbox);
            }
            let retried = must(alice.seal("application:alice:kill", b"kill loop payload"));
            assert_eq!(
                must(bob.open("incoming:kill", &retried)),
                b"kill loop payload"
            );
        }

        // Welcome-attachment path: repeated kills of the same Add.
        {
            let failpoint = Failpoint::AfterCommitOutboxBeforeWelcomeAttachment;
            let mut alice = must(C::new("alice"));
            let mut bob = must(C::new("bob"));
            must(alice.create_group(b"kill-loop-add-group"));
            let key_package = must(bob.publish_key_package("key-package:bob:kill"));
            let before_revision = alice.revision();
            let before_outbox = alice.outbox().len();
            for _ in 0..kills {
                alice.inject_once(failpoint);
                assert_eq!(
                    alice.add_member(&key_package, "commit:add:bob:kill"),
                    Err(Error::InjectedCrash(failpoint))
                );
                assert_eq!(alice.revision(), before_revision);
                assert_eq!(alice.outbox().len(), before_outbox);
            }
            let (_commit, welcome) = must(alice.add_member(&key_package, "commit:add:bob:kill"));
            must(bob.join(&welcome));
        }

        // Receive path: repeated kills of the same open, then one effect.
        for failpoint in [Failpoint::AfterReplayRecord, Failpoint::AfterDomainRecord] {
            let (mut alice, mut bob, _pre_join) = joined_pair::<C>();
            let ciphertext = must(alice.seal("application:alice:receive-kill", b"one effect"));
            let before_revision = bob.revision();
            let before_effects = bob.domain_records().len();
            for _ in 0..kills {
                bob.inject_once(failpoint);
                assert_eq!(
                    bob.open("incoming:receive-kill", &ciphertext),
                    Err(Error::InjectedCrash(failpoint))
                );
                assert_eq!(bob.revision(), before_revision);
                assert_eq!(bob.domain_records().len(), before_effects);
            }
            assert_eq!(
                must(bob.open("incoming:receive-kill", &ciphertext)),
                b"one effect"
            );
            assert_eq!(bob.domain_records().len(), before_effects + 1);
        }
    }
}
