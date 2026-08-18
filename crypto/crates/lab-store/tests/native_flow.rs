use juicebox_messaging_client_core as core_mls;
use juicebox_messaging_mls_lab_store::harness::scenarios;
use juicebox_messaging_mls_lab_store::{Error, LabClient};
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
    scenarios::joined_pair::<LabClient>()
}

// ---------------------------------------------------------------------------
// Provider-neutral scenarios, bound to the native OpenMLS candidate. The
// bodies live in the harness module so a Candidate B adapter runs the exact
// same assertions.
// ---------------------------------------------------------------------------

#[test]
fn create_add_welcome_bidirectional_update_remove_and_history_boundaries() {
    scenarios::lifecycle_and_history_boundaries::<LabClient>();
}

#[test]
fn add_is_one_commit_record_with_attached_welcome() {
    scenarios::add_is_one_commit_record_with_attached_welcome::<LabClient>();
}

#[test]
fn replay_and_conflicting_reuse_have_no_second_domain_effect() {
    scenarios::replay_and_conflict_have_no_second_domain_effect::<LabClient>();
}

#[test]
fn trailing_bytes_are_rejected_without_consuming_state() {
    scenarios::trailing_bytes_are_rejected_without_consuming_state::<LabClient>();
}

#[test]
fn retry_uses_the_exact_committed_ciphertext() {
    scenarios::retry_uses_the_exact_committed_ciphertext::<LabClient>();
}

#[test]
fn current_retained_state_after_update_cannot_open_old_epoch_ciphertext() {
    scenarios::retained_state_cannot_open_old_epoch_ciphertext::<LabClient>();
}

#[test]
fn send_failpoints_roll_back_whole_state_and_outbox() {
    scenarios::send_failpoints_roll_back_whole_state_and_outbox::<LabClient>();
}

#[test]
fn add_crash_cannot_commit_without_its_targeted_welcome() {
    scenarios::add_crash_cannot_commit_without_its_targeted_welcome::<LabClient>();
}

#[test]
fn receive_failpoints_roll_back_mls_replay_and_domain_effect() {
    scenarios::receive_failpoints_roll_back_mls_replay_and_domain_effect::<LabClient>();
}

#[test]
fn key_package_publication_and_welcome_join_roll_back_for_exact_retry() {
    scenarios::key_package_publication_and_join_roll_back_for_exact_retry::<LabClient>();
}

#[test]
fn incoming_commit_failpoints_roll_back_epoch_and_replay_state() {
    scenarios::incoming_commit_failpoints_roll_back_epoch_and_replay_state::<LabClient>();
}

#[test]
fn update_and_remove_failpoints_roll_back_epoch_and_membership() {
    scenarios::update_and_remove_failpoints_roll_back_epoch_and_membership::<LabClient>();
}

#[test]
fn outgoing_envelope_conflict_rolls_back_mls_sender_state() {
    scenarios::outgoing_envelope_conflict_rolls_back_sender_state::<LabClient>();
}

#[test]
fn one_group_lab_client_rejects_silent_group_repointing() {
    scenarios::one_group_client_rejects_silent_group_repointing::<LabClient>();
}

#[test]
fn replay_storm_has_exactly_one_effect_per_envelope() {
    scenarios::replay_storm_has_exactly_one_effect_per_envelope::<LabClient>();
}

#[test]
fn failpoint_kill_loop_never_leaks_partial_state() {
    scenarios::failpoint_kill_loop_never_leaks_partial_state::<LabClient>();
}

// ---------------------------------------------------------------------------
// Native-candidate wire-format probes: these assert OpenMLS-specific frozen
// profile facts a neutral scenario cannot express.
// ---------------------------------------------------------------------------

#[test]
fn frozen_wire_formats_public_commit_private_application_welcome_body() {
    let (mut alice, mut bob, _pre_join) = joined_pair();
    let add_record = match alice
        .outbox()
        .iter()
        .find(|record| record.envelope_id == "commit:add:bob:1")
        .cloned()
    {
        Some(record) => record,
        None => panic!("missing Add Commit outbox record"),
    };
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

    let update = must(bob.update("commit:update:bob:wire"));
    assert_eq!(
        must(core_mls::decode_exact(&update).map_err(Error::Core)).wire_format(),
        WireFormat::PublicMessage
    );
    must(alice.process_commit("incoming:commit:update:bob:wire", &update));

    let application = must(alice.seal("application:alice:wire", b"private wire"));
    assert_eq!(
        must(core_mls::decode_exact(&application).map_err(Error::Core)).wire_format(),
        WireFormat::PrivateMessage
    );
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
