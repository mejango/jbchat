use juicebox_messaging_client_core as core_mls;
use juicebox_messaging_mls_lab_store::{Error, Failpoint, LabClient, WireKind};
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialType, CredentialWithKey, ExtensionType, Extensions,
    GroupId, KeyPackage, Lifetime, MlsGroupJoinConfig, MlsMessageBodyIn, PastEpochDeletionPolicy,
    ProtocolVersion, WireFormat, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};

fn must<T>(result: Result<T, Error>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("sanitized pre-G1 lab operation failed"),
    }
}

fn joined_pair() -> (LabClient, LabClient, Vec<u8>) {
    let mut alice = must(LabClient::new("alice"));
    let mut bob = must(LabClient::new("bob"));
    must(alice.create_group(b"deterministic-lab-group"));

    // This ciphertext is intentionally created before Bob's join boundary.
    let pre_join = must(alice.seal("application:alice:prejoin", b"pre-join history"));
    let key_package = must(bob.publish_key_package("key-package:bob:1"));
    let (_commit, welcome) = must(alice.add_member(&key_package, "commit:add:bob:1"));
    must(bob.join(&welcome));
    (alice, bob, pre_join)
}

#[test]
fn create_add_welcome_bidirectional_update_remove_and_history_boundaries() {
    let (mut alice, mut bob, pre_join) = joined_pair();

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
    assert_eq!(
        must(core_mls::decode_exact(&update).map_err(Error::Core)).wire_format(),
        WireFormat::PublicMessage
    );
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
    assert_eq!(
        bob.seal("application:bob:removed", b"must not send"),
        Err(Error::Core(core_mls::Error::InactiveGroup))
    );
}

#[test]
fn application_is_private_and_add_is_one_commit_record_with_attached_welcome() {
    let (mut alice, _bob, _pre_join) = joined_pair();
    let add_record = match alice
        .outbox()
        .iter()
        .find(|record| record.envelope_id == "commit:add:bob:1")
        .cloned()
    {
        Some(record) => record,
        None => panic!("missing Add Commit outbox record"),
    };
    assert_eq!(add_record.kind, WireKind::Commit);
    assert_eq!(
        must(core_mls::decode_exact(&add_record.exact_bytes).map_err(Error::Core)).wire_format(),
        WireFormat::PublicMessage
    );
    let welcome = match add_record.attached_welcome.as_ref() {
        Some(welcome) => welcome,
        None => panic!("missing targeted Welcome on Add Commit"),
    };
    assert!(matches!(
        must(core_mls::decode_exact(welcome).map_err(Error::Core)).extract(),
        MlsMessageBodyIn::Welcome(_)
    ));
    assert_eq!(must(alice.retry_delivery("commit:add:bob:1")), add_record);
    assert_eq!(
        alice
            .outbox()
            .iter()
            .filter(|record| record.envelope_id == "commit:add:bob:1")
            .count(),
        1
    );

    let application = must(alice.seal("application:alice:wire", b"private wire"));
    assert_eq!(
        must(core_mls::decode_exact(&application).map_err(Error::Core)).wire_format(),
        WireFormat::PrivateMessage
    );
}

#[test]
fn replay_and_conflicting_reuse_have_no_second_domain_effect() {
    let (mut alice, mut bob, _pre_join) = joined_pair();
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

#[test]
fn exact_decoder_rejects_trailing_bytes_without_consuming_message_state() {
    let (mut alice, mut bob, _pre_join) = joined_pair();
    let ciphertext = must(alice.seal("application:alice:trailing", b"strict decode"));
    let mut malformed = ciphertext.clone();
    malformed.push(0x42);

    assert_eq!(
        bob.open("incoming:trailing:bad", &malformed),
        Err(Error::Core(core_mls::Error::InvalidWireEncoding))
    );
    assert_eq!(
        must(bob.open("incoming:trailing:good", &ciphertext)),
        b"strict decode"
    );
}

#[test]
fn every_ingress_rejects_trailing_bytes_without_consuming_state() {
    let mut alice = must(LabClient::new("alice"));
    let mut bob = must(LabClient::new("bob"));
    must(alice.create_group(b"all-strict-decoders"));

    let key_package = must(bob.publish_key_package("key-package:bob:strict"));
    let mut malformed_key_package = key_package.clone();
    malformed_key_package.push(0x11);
    assert_eq!(
        alice.add_member(&malformed_key_package, "commit:add:bob:malformed"),
        Err(Error::Core(core_mls::Error::InvalidWireEncoding))
    );

    let (_add, welcome) = must(alice.add_member(&key_package, "commit:add:bob:strict"));
    let mut malformed_welcome = welcome.clone();
    malformed_welcome.push(0x22);
    assert_eq!(
        bob.join(&malformed_welcome),
        Err(Error::Core(core_mls::Error::InvalidWireEncoding))
    );
    must(bob.join(&welcome));

    let update = must(bob.update("commit:update:bob:strict"));
    let mut malformed_commit = update.clone();
    malformed_commit.push(0x33);
    assert_eq!(
        alice.process_commit("incoming:commit:update:bob:malformed", &malformed_commit),
        Err(Error::Core(core_mls::Error::InvalidWireEncoding))
    );
    must(alice.process_commit("incoming:commit:update:bob:strict", &update));

    let current = must(bob.seal("application:bob:strict-current", b"state was not consumed"));
    assert_eq!(
        must(alice.open("incoming:bob:strict-current", &current)),
        b"state was not consumed"
    );
}

#[test]
fn every_ingress_has_its_frozen_predecode_size_ceiling() {
    let oversized = vec![0_u8; core_mls::MAX_COMMIT_WIRE_BYTES + 1];
    assert_eq!(
        core_mls::decode_exact(&oversized),
        Err(core_mls::Error::WireSizeExceeded)
    );
    assert_eq!(
        core_mls::decode_exact(&[]),
        Err(core_mls::Error::WireSizeExceeded)
    );

    let provider = core_mls::ProfileProvider::new(MemoryStorage::default());
    assert_eq!(
        core_mls::decode_key_package(
            &provider,
            &vec![0_u8; core_mls::MAX_KEY_PACKAGE_WIRE_BYTES + 1],
        ),
        Err(core_mls::Error::WireSizeExceeded)
    );
    assert!(matches!(
        core_mls::join_from_welcome(&provider, &vec![0_u8; core_mls::MAX_WELCOME_WIRE_BYTES + 1],),
        Err(core_mls::Error::WireSizeExceeded)
    ));

    let (mut alice, mut bob, _pre_join) = joined_pair();
    assert_eq!(
        bob.open(
            "incoming:oversized:application",
            &vec![0_u8; core_mls::MAX_APPLICATION_WIRE_BYTES + 1],
        ),
        Err(Error::Core(core_mls::Error::WireSizeExceeded))
    );
    assert_eq!(
        alice.process_commit(
            "incoming:oversized:commit",
            &vec![0_u8; core_mls::MAX_COMMIT_WIRE_BYTES + 1],
        ),
        Err(Error::Core(core_mls::Error::WireSizeExceeded))
    );
}

#[test]
fn unsupported_suite_and_capability_are_rejected_without_fallback() {
    assert_eq!(
        core_mls::ensure_profile_ciphersuite(
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ),
        Err(core_mls::Error::UnsupportedCiphersuite)
    );

    let wrong_suite = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    assert_eq!(
        core_mls::validate_capabilities(&wrong_suite),
        Err(core_mls::Error::UnsupportedCiphersuite)
    );

    let unknown_extension = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[core_mls::PROFILE_CIPHERSUITE]),
        Some(&[ExtensionType::Unknown(0xf100)]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    assert_eq!(
        core_mls::validate_capabilities(&unknown_extension),
        Err(core_mls::Error::UnsupportedCapability)
    );
}

#[test]
fn off_profile_and_last_resort_key_packages_are_rejected() {
    let provider = core_mls::ProfileProvider::new(MemoryStorage::default());
    let identity = match core_mls::create_synthetic_identity(&provider, "mallory") {
        Ok(identity) => identity,
        Err(_) => panic!("synthetic identity setup failed"),
    };

    let off_profile_suite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let off_profile_capabilities = Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[off_profile_suite]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    );
    let off_profile = match KeyPackage::builder()
        .key_package_extensions(Extensions::default())
        .leaf_node_capabilities(off_profile_capabilities)
        .leaf_node_extensions(Extensions::default())
        .build(
            off_profile_suite,
            &provider,
            identity.signer(),
            identity.credential().clone(),
        ) {
        Ok(bundle) => bundle,
        Err(_) => panic!("off-profile KeyPackage fixture setup failed"),
    };
    assert_eq!(
        core_mls::validate_key_package(off_profile.key_package()),
        Err(core_mls::Error::UnsupportedCiphersuite)
    );

    let last_resort = match KeyPackage::builder()
        .key_package_extensions(Extensions::default())
        .leaf_node_capabilities(core_mls::profile_capabilities())
        .leaf_node_extensions(Extensions::default())
        .mark_as_last_resort()
        .build(
            core_mls::PROFILE_CIPHERSUITE,
            &provider,
            identity.signer(),
            identity.credential().clone(),
        ) {
        Ok(bundle) => bundle,
        Err(_) => panic!("last-resort KeyPackage fixture setup failed"),
    };
    assert_eq!(
        core_mls::validate_key_package(last_resort.key_package()),
        Err(core_mls::Error::LastResortKeyPackage)
    );

    let overlong = match KeyPackage::builder()
        .key_package_lifetime(Lifetime::new(core_mls::KEY_PACKAGE_LIFETIME_SECONDS + 1))
        .key_package_extensions(Extensions::default())
        .leaf_node_capabilities(core_mls::profile_capabilities())
        .leaf_node_extensions(Extensions::default())
        .build(
            core_mls::PROFILE_CIPHERSUITE,
            &provider,
            identity.signer(),
            identity.credential().clone(),
        ) {
        Ok(bundle) => bundle,
        Err(_) => panic!("overlong KeyPackage fixture setup failed"),
    };
    assert_eq!(
        core_mls::validate_key_package(overlong.key_package()),
        Err(core_mls::Error::InvalidKeyPackageLifetime)
    );

    for invalid_lifetime in [Lifetime::init(0, 1), Lifetime::init(u64::MAX - 1, u64::MAX)] {
        let key_package = match KeyPackage::builder()
            .key_package_lifetime(invalid_lifetime)
            .key_package_extensions(Extensions::default())
            .leaf_node_capabilities(core_mls::profile_capabilities())
            .leaf_node_extensions(Extensions::default())
            .build(
                core_mls::PROFILE_CIPHERSUITE,
                &provider,
                identity.signer(),
                identity.credential().clone(),
            ) {
            Ok(bundle) => bundle,
            Err(_) => panic!("invalid-time KeyPackage fixture setup failed"),
        };
        assert_eq!(
            core_mls::validate_key_package(key_package.key_package()),
            Err(core_mls::Error::InvalidKeyPackageLifetime)
        );
    }

    let non_synthetic_credential = CredentialWithKey {
        credential: BasicCredential::new(b"non-synthetic-fixture".to_vec()).into(),
        signature_key: identity.credential().signature_key.clone(),
    };
    let non_synthetic = match KeyPackage::builder()
        .key_package_lifetime(Lifetime::new(core_mls::KEY_PACKAGE_LIFETIME_SECONDS))
        .key_package_extensions(Extensions::default())
        .leaf_node_capabilities(core_mls::profile_capabilities())
        .leaf_node_extensions(Extensions::default())
        .build(
            core_mls::PROFILE_CIPHERSUITE,
            &provider,
            identity.signer(),
            non_synthetic_credential,
        ) {
        Ok(bundle) => bundle,
        Err(_) => panic!("non-synthetic KeyPackage fixture setup failed"),
    };
    assert_eq!(
        core_mls::validate_key_package(non_synthetic.key_package()),
        Err(core_mls::Error::InvalidSyntheticIdentity)
    );
}

#[test]
fn loaded_group_configuration_cannot_silently_drift() {
    let provider = core_mls::ProfileProvider::new(MemoryStorage::default());
    let identity = match core_mls::create_synthetic_identity(&provider, "alice") {
        Ok(identity) => identity,
        Err(_) => panic!("synthetic identity setup failed"),
    };
    let group_id = GroupId::from_slice(b"off-profile-config");
    let mut group = match core_mls::create_group(&provider, &identity, group_id.clone()) {
        Ok(group) => group,
        Err(_) => panic!("group fixture setup failed"),
    };
    let off_profile = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(1))
        .use_ratchet_tree_extension(true)
        .build();
    if group
        .set_configuration(provider.storage(), &off_profile)
        .is_err()
    {
        panic!("off-profile persisted configuration fixture setup failed");
    }
    assert!(matches!(
        core_mls::load_group(&provider, &group_id),
        Err(core_mls::Error::UnsupportedCapability)
    ));
}

#[test]
fn outgoing_wrapper_rejects_pending_proposal_contamination() {
    let alice_provider = core_mls::ProfileProvider::new(MemoryStorage::default());
    let alice_identity = match core_mls::create_synthetic_identity(&alice_provider, "alice") {
        Ok(identity) => identity,
        Err(_) => panic!("Alice identity fixture setup failed"),
    };
    let mut alice_group = match core_mls::create_group(
        &alice_provider,
        &alice_identity,
        GroupId::from_slice(b"pending-proposal-contamination"),
    ) {
        Ok(group) => group,
        Err(_) => panic!("Alice group fixture setup failed"),
    };

    let bob_provider = core_mls::ProfileProvider::new(MemoryStorage::default());
    let bob_identity = match core_mls::create_synthetic_identity(&bob_provider, "bob") {
        Ok(identity) => identity,
        Err(_) => panic!("Bob identity fixture setup failed"),
    };
    let key_package_bytes = match core_mls::generate_key_package(&bob_provider, &bob_identity) {
        Ok(bytes) => bytes,
        Err(_) => panic!("Bob KeyPackage fixture setup failed"),
    };
    let key_package = match core_mls::decode_key_package(&alice_provider, &key_package_bytes) {
        Ok(key_package) => key_package,
        Err(_) => panic!("Bob KeyPackage decode fixture failed"),
    };
    if alice_group
        .propose_add_member(&alice_provider, alice_identity.signer(), &key_package)
        .is_err()
    {
        panic!("pending Add proposal fixture setup failed");
    }

    assert_eq!(
        core_mls::self_update(&mut alice_group, &alice_provider, &alice_identity),
        Err(core_mls::Error::UnsupportedCapability)
    );
}

#[test]
fn retry_uses_the_exact_committed_ciphertext() {
    let (mut alice, _bob, _pre_join) = joined_pair();
    let ciphertext = must(alice.seal("application:alice:retry", b"exact retry"));
    assert_eq!(
        must(alice.retry_delivery("application:alice:retry")).exact_bytes,
        ciphertext
    );
}

#[test]
fn current_retained_state_after_update_cannot_open_old_epoch_ciphertext() {
    let (mut alice, mut bob, _pre_join) = joined_pair();
    let old_epoch = must(alice.seal("application:alice:old-epoch", b"old epoch secret"));

    // Bob intentionally does not open `old_epoch` before advancing. The
    // profile's explicit MaxEpochs(0) policy deletes prior-epoch message
    // secrets when this Update is merged.
    let update = must(bob.update("commit:update:bob:forward-secrecy"));
    must(alice.process_commit("incoming:commit:update:bob:forward-secrecy", &update));
    let mut compromised = must(bob.compromise_current_retained_state());
    assert!(compromised.open(&old_epoch).is_err());

    let current_epoch = must(alice.seal("application:alice:current-epoch", b"current epoch works"));
    assert_eq!(
        must(bob.open("incoming:alice:current-epoch", &current_epoch)),
        b"current epoch works"
    );
}

#[test]
fn send_failpoints_roll_back_whole_state_and_outbox() {
    for failpoint in [
        Failpoint::AfterMlsMutation,
        Failpoint::AfterOutboxAppend,
        Failpoint::BeforeCommit,
    ] {
        let (mut alice, mut bob, _pre_join) = joined_pair();
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

#[test]
fn add_crash_cannot_commit_without_its_targeted_welcome() {
    for failpoint in [
        Failpoint::AfterMlsMutation,
        Failpoint::AfterCommitOutboxBeforeWelcomeAttachment,
        Failpoint::AfterOutboxAppend,
        Failpoint::BeforeCommit,
    ] {
        let mut alice = must(LabClient::new("alice"));
        let mut bob = must(LabClient::new("bob"));
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

#[test]
fn receive_failpoints_roll_back_mls_replay_and_domain_effect() {
    let (mut alice, mut bob, _pre_join) = joined_pair();
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

#[test]
fn key_package_publication_and_welcome_join_roll_back_for_exact_retry() {
    for failpoint in [
        Failpoint::AfterMlsMutation,
        Failpoint::AfterOutboxAppend,
        Failpoint::BeforeCommit,
    ] {
        let mut bob = must(LabClient::new("bob"));
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

    let mut alice = must(LabClient::new("alice"));
    let mut bob = must(LabClient::new("bob"));
    must(alice.create_group(b"welcome-join-crash"));
    let key_package = must(bob.publish_key_package("key-package:bob:welcome-crash"));
    let (_commit, welcome) = must(alice.add_member(&key_package, "commit:add:bob:welcome-crash"));
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

#[test]
fn incoming_commit_failpoints_roll_back_epoch_and_replay_state() {
    for failpoint in [
        Failpoint::AfterMlsMutation,
        Failpoint::AfterReplayRecord,
        Failpoint::BeforeCommit,
    ] {
        let (mut alice, mut bob, _pre_join) = joined_pair();
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

#[test]
fn update_and_remove_failpoints_roll_back_epoch_and_membership() {
    for failpoint in [
        Failpoint::AfterMlsMutation,
        Failpoint::AfterOutboxAppend,
        Failpoint::BeforeCommit,
    ] {
        let (mut alice, mut bob, _pre_join) = joined_pair();
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

        let (mut alice, mut bob, _pre_join) = joined_pair();
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

#[test]
fn outgoing_envelope_conflict_rolls_back_mls_sender_state() {
    let (mut alice, mut bob, _pre_join) = joined_pair();
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

#[test]
fn one_group_lab_client_rejects_silent_group_repointing() {
    let mut alice = must(LabClient::new("alice"));
    must(alice.create_group(b"one-group-only"));
    let before_revision = alice.revision();
    assert_eq!(
        alice.create_group(b"must-not-repoint"),
        Err(Error::GroupAlreadySet)
    );
    assert_eq!(alice.revision(), before_revision);
}
