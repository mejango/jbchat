//! Narrow, native-only OpenMLS profile for the pre-G1 workbench.
//!
//! This crate deliberately contains no wallet, chain, browser, transport, or
//! production persistence integration. Its public errors are closed and do not
//! expose dependency diagnostics or secret-bearing values.

use core::fmt;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{
    storage::{StorageProvider, CURRENT_VERSION},
    OpenMlsProvider,
};
use tls_codec::Deserialize as _;

/// The only ciphersuite accepted by the version-one profile.
pub const PROFILE_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const MAX_APPLICATION_WIRE_BYTES: usize = 64 * 1024;
pub const MAX_KEY_PACKAGE_WIRE_BYTES: usize = 64 * 1024;
pub const MAX_WELCOME_WIRE_BYTES: usize = 256 * 1024;
pub const MAX_COMMIT_WIRE_BYTES: usize = 512 * 1024;
pub const KEY_PACKAGE_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
const KEY_PACKAGE_CLOCK_SKEW_SECONDS: u64 = 60 * 60;
const SYNTHETIC_IDENTITY_PREFIX: &[u8] = b"jbm-pre-g1-synthetic:v1:";

/// Stable, non-secret error codes exposed by this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidSyntheticIdentity,
    UnsupportedProtocolVersion,
    UnsupportedCiphersuite,
    UnsupportedCredential,
    UnsupportedCapability,
    UnsupportedExtension,
    LastResortKeyPackage,
    InvalidKeyPackageLifetime,
    WireSizeExceeded,
    InvalidWireEncoding,
    UnexpectedWireFormat,
    UnexpectedMessageContent,
    GroupNotFound,
    InactiveGroup,
    CryptoOperationFailed,
    StorageOperationFailed,
}

impl Error {
    /// Stable machine-readable code. It never incorporates an upstream error.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSyntheticIdentity => "mls.invalid_synthetic_identity",
            Self::UnsupportedProtocolVersion => "mls.unsupported_protocol_version",
            Self::UnsupportedCiphersuite => "mls.unsupported_ciphersuite",
            Self::UnsupportedCredential => "mls.unsupported_credential",
            Self::UnsupportedCapability => "mls.unsupported_capability",
            Self::UnsupportedExtension => "mls.unsupported_extension",
            Self::LastResortKeyPackage => "mls.last_resort_key_package",
            Self::InvalidKeyPackageLifetime => "mls.invalid_key_package_lifetime",
            Self::WireSizeExceeded => "mls.wire_size_exceeded",
            Self::InvalidWireEncoding => "mls.invalid_wire_encoding",
            Self::UnexpectedWireFormat => "mls.unexpected_wire_format",
            Self::UnexpectedMessageContent => "mls.unexpected_message_content",
            Self::GroupNotFound => "mls.group_not_found",
            Self::InactiveGroup => "mls.inactive_group",
            Self::CryptoOperationFailed => "mls.crypto_operation_failed",
            Self::StorageOperationFailed => "mls.storage_operation_failed",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for Error {}

/// An owned provider boundary. The RustCrypto primitive/RNG implementation is
/// composed with caller-owned storage; `OpenMlsRustCrypto` and its bundled
/// memory store are intentionally not instantiated here.
pub struct ProfileProvider<S> {
    crypto: RustCrypto,
    storage: S,
}

impl<S> ProfileProvider<S> {
    pub fn new(storage: S) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }

    pub fn into_storage(self) -> S {
        self.storage
    }
}

impl<S> OpenMlsProvider for ProfileProvider<S>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = S;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// Synthetic lab identity and its Basic/Ed25519 signing material.
pub struct SyntheticIdentity {
    credential: CredentialWithKey,
    signer: SignatureKeyPair,
}

impl SyntheticIdentity {
    pub fn credential(&self) -> &CredentialWithKey {
        &self.credential
    }

    pub fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }
}

/// Create a visibly synthetic Basic credential. Labels are bounded lowercase
/// ASCII identifiers, never wallet addresses, phone numbers, or user PII.
pub fn create_synthetic_identity<S>(
    provider: &ProfileProvider<S>,
    label: &str,
) -> Result<SyntheticIdentity, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    validate_synthetic_label(label.as_bytes())?;

    let identity = synthetic_credential_content(label)?;
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
        .map_err(|_| Error::CryptoOperationFailed)?;
    signer
        .store(provider.storage())
        .map_err(|_| Error::StorageOperationFailed)?;

    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity).into(),
        signature_key: signer.to_public_vec().into(),
    };

    Ok(SyntheticIdentity { credential, signer })
}

/// Load a previously stored synthetic identity back from the provider's
/// storage. The caller supplies the label and the Ed25519 public key it
/// recorded at creation time; the private half never leaves storage.
pub fn load_synthetic_identity<S>(
    provider: &ProfileProvider<S>,
    label: &str,
    signature_public_key: &[u8],
) -> Result<SyntheticIdentity, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    let identity = synthetic_credential_content(label)?;
    let signer = SignatureKeyPair::read(
        provider.storage(),
        signature_public_key,
        SignatureScheme::ED25519,
    )
    .ok_or(Error::StorageOperationFailed)?;
    if signer.public() != signature_public_key {
        return Err(Error::CryptoOperationFailed);
    }
    let credential = CredentialWithKey {
        credential: BasicCredential::new(identity).into(),
        signature_key: signer.to_public_vec().into(),
    };
    Ok(SyntheticIdentity { credential, signer })
}

/// Capabilities emitted by every lab leaf and KeyPackage. Nothing is inferred
/// from provider defaults.
pub fn profile_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[PROFILE_CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

/// Reject every capability set that is not the exact version-one profile.
pub fn validate_capabilities(capabilities: &Capabilities) -> Result<(), Error> {
    if capabilities.versions() != [ProtocolVersion::Mls10] {
        return Err(Error::UnsupportedProtocolVersion);
    }
    if capabilities.ciphersuites().len() != 1
        || capabilities.ciphersuites()[0].value() != PROFILE_CIPHERSUITE as u16
    {
        return Err(Error::UnsupportedCiphersuite);
    }
    if !capabilities.extensions().is_empty() || !capabilities.proposals().is_empty() {
        return Err(Error::UnsupportedCapability);
    }
    if capabilities.credentials() != [CredentialType::Basic] {
        return Err(Error::UnsupportedCredential);
    }
    Ok(())
}

pub fn ensure_profile_ciphersuite(ciphersuite: Ciphersuite) -> Result<(), Error> {
    if ciphersuite == PROFILE_CIPHERSUITE {
        Ok(())
    } else {
        Err(Error::UnsupportedCiphersuite)
    }
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(PROFILE_CIPHERSUITE)
        .capabilities(profile_capabilities())
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(0))
        .use_ratchet_tree_extension(true)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(0))
        .use_ratchet_tree_extension(true)
        .build()
}

pub fn create_group<S>(
    provider: &ProfileProvider<S>,
    identity: &SyntheticIdentity,
    group_id: GroupId,
) -> Result<MlsGroup, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    let group = MlsGroup::new_with_group_id(
        provider,
        identity.signer(),
        &create_config(),
        group_id,
        identity.credential().clone(),
    )
    .map_err(|_| Error::CryptoOperationFailed)?;
    validate_group_profile(&group)?;
    Ok(group)
}

pub fn load_group<S>(provider: &ProfileProvider<S>, group_id: &GroupId) -> Result<MlsGroup, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    let group = MlsGroup::load(provider.storage(), group_id)
        .map_err(|_| Error::StorageOperationFailed)?
        .ok_or(Error::GroupNotFound)?;
    validate_group_profile(&group)?;
    Ok(group)
}

pub fn generate_key_package<S>(
    provider: &ProfileProvider<S>,
    identity: &SyntheticIdentity,
) -> Result<Vec<u8>, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    let bundle = KeyPackage::builder()
        .key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME_SECONDS))
        .key_package_extensions(Extensions::default())
        .leaf_node_capabilities(profile_capabilities())
        .leaf_node_extensions(Extensions::default())
        .build(
            PROFILE_CIPHERSUITE,
            provider,
            identity.signer(),
            identity.credential().clone(),
        )
        .map_err(|_| Error::CryptoOperationFailed)?;
    validate_key_package(bundle.key_package())?;
    serialize_output(
        &MlsMessageOut::from(bundle.into_key_package()),
        WireFormat::KeyPackage,
    )
}

pub fn decode_key_package<S>(
    provider: &ProfileProvider<S>,
    bytes: &[u8],
) -> Result<KeyPackage, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    ensure_wire_size(bytes, MAX_KEY_PACKAGE_WIRE_BYTES)?;
    let message = decode_exact(bytes)?;
    if message.wire_format() != WireFormat::KeyPackage {
        return Err(Error::UnexpectedWireFormat);
    }
    let incoming = match message.extract() {
        MlsMessageBodyIn::KeyPackage(incoming) => incoming,
        _ => return Err(Error::UnexpectedWireFormat),
    };
    let key_package = incoming
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| Error::CryptoOperationFailed)?;
    validate_key_package(&key_package)?;
    Ok(key_package)
}

pub fn validate_key_package(key_package: &KeyPackage) -> Result<(), Error> {
    ensure_profile_ciphersuite(key_package.ciphersuite())?;
    if key_package.last_resort() {
        return Err(Error::LastResortKeyPackage);
    }
    let lifetime = key_package.life_time();
    lifetime
        .validate()
        .map_err(|_| Error::InvalidKeyPackageLifetime)?;
    let range = lifetime
        .not_after()
        .checked_sub(lifetime.not_before())
        .ok_or(Error::InvalidKeyPackageLifetime)?;
    if range > KEY_PACKAGE_LIFETIME_SECONDS + KEY_PACKAGE_CLOCK_SKEW_SECONDS {
        return Err(Error::InvalidKeyPackageLifetime);
    }
    if key_package.extensions().iter().next().is_some()
        || key_package.leaf_node().extensions().iter().next().is_some()
    {
        return Err(Error::UnsupportedExtension);
    }
    validate_leaf_profile(key_package.leaf_node())
}

/// Create and locally merge an Add Commit. Handshakes are serialized only as
/// public MLS messages; the Welcome is returned separately.
pub fn add_member<S>(
    group: &mut MlsGroup,
    provider: &ProfileProvider<S>,
    identity: &SyntheticIdentity,
    key_package: &KeyPackage,
) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    add_members(
        group,
        provider,
        identity,
        core::slice::from_ref(key_package),
    )
}

/// Create and locally merge one Add Commit covering every KeyPackage.
/// A single Welcome message serves all invitees.
pub fn add_members<S>(
    group: &mut MlsGroup,
    provider: &ProfileProvider<S>,
    identity: &SyntheticIdentity,
    key_packages: &[KeyPackage],
) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    if key_packages.is_empty() {
        return Err(Error::UnsupportedCapability);
    }
    validate_group_profile(group)?;
    ensure_no_pending_proposals(group)?;
    for key_package in key_packages {
        validate_key_package(key_package)?;
    }
    let (commit, welcome, _) = group
        .add_members(provider, identity.signer(), key_packages)
        .map_err(|_| Error::CryptoOperationFailed)?;
    let commit_bytes = serialize_output(&commit, WireFormat::PublicMessage)?;
    let welcome_bytes = serialize_output(&welcome, WireFormat::Welcome)?;
    group
        .merge_pending_commit(provider)
        .map_err(|_| Error::CryptoOperationFailed)?;
    validate_group_profile(group)?;
    Ok((commit_bytes, welcome_bytes))
}

pub fn join_from_welcome<S>(provider: &ProfileProvider<S>, bytes: &[u8]) -> Result<MlsGroup, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    ensure_wire_size(bytes, MAX_WELCOME_WIRE_BYTES)?;
    let message = decode_exact(bytes)?;
    if message.wire_format() != WireFormat::Welcome {
        return Err(Error::UnexpectedWireFormat);
    }
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err(Error::UnexpectedWireFormat),
    };
    let builder = StagedWelcome::build_from_welcome(provider, &join_config(), welcome)
        .map_err(|_| Error::CryptoOperationFailed)?;
    {
        let processed = builder.processed_welcome();
        validate_group_context(processed.unverified_group_info().group_context())?;
        let mut group_info_extensions = processed.unverified_group_info().extensions().iter();
        if !matches!(
            group_info_extensions.next(),
            Some(Extension::RatchetTree(_))
        ) || group_info_extensions.next().is_some()
        {
            return Err(Error::UnsupportedExtension);
        }
        if !processed.psks().is_empty() {
            return Err(Error::UnsupportedCapability);
        }
    }
    let staged = builder.build().map_err(|_| Error::CryptoOperationFailed)?;
    validate_group_context(staged.group_context())?;
    validate_leaf_profile(staged.own_leaf_node().ok_or(Error::CryptoOperationFailed)?)?;
    validate_leaf_profile(
        staged
            .welcome_sender()
            .map_err(|_| Error::CryptoOperationFailed)?,
    )?;
    let group = staged
        .into_group(provider)
        .map_err(|_| Error::CryptoOperationFailed)?;
    validate_group_profile(&group)?;
    Ok(group)
}

pub fn seal_application<S>(
    group: &mut MlsGroup,
    provider: &ProfileProvider<S>,
    identity: &SyntheticIdentity,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    validate_group_profile(group)?;
    if !group.is_active() {
        return Err(Error::InactiveGroup);
    }
    let message = group
        .create_message(provider, identity.signer(), plaintext)
        .map_err(|_| Error::CryptoOperationFailed)?;
    serialize_output(&message, WireFormat::PrivateMessage)
}

pub fn open_application<S>(
    group: &mut MlsGroup,
    provider: &ProfileProvider<S>,
    bytes: &[u8],
) -> Result<Vec<u8>, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    validate_group_profile(group)?;
    let protocol = decode_protocol(bytes, WireFormat::PrivateMessage)?;
    if protocol.content_type() != ContentType::Application {
        return Err(Error::UnexpectedMessageContent);
    }
    let processed = group
        .process_message(provider, protocol)
        .map_err(|_| Error::CryptoOperationFailed)?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
        _ => Err(Error::UnexpectedMessageContent),
    }
}

pub fn self_update<S>(
    group: &mut MlsGroup,
    provider: &ProfileProvider<S>,
    identity: &SyntheticIdentity,
) -> Result<Vec<u8>, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    validate_group_profile(group)?;
    ensure_no_pending_proposals(group)?;
    let (commit, welcome, _) = group
        .self_update(provider, identity.signer(), LeafNodeParameters::default())
        .map_err(|_| Error::CryptoOperationFailed)?
        .into_contents();
    if welcome.is_some() {
        return Err(Error::UnexpectedMessageContent);
    }
    let bytes = serialize_output(&commit, WireFormat::PublicMessage)?;
    group
        .merge_pending_commit(provider)
        .map_err(|_| Error::CryptoOperationFailed)?;
    validate_group_profile(group)?;
    Ok(bytes)
}

pub fn remove_member<S>(
    group: &mut MlsGroup,
    provider: &ProfileProvider<S>,
    identity: &SyntheticIdentity,
    leaf_index: LeafNodeIndex,
) -> Result<Vec<u8>, Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    validate_group_profile(group)?;
    ensure_no_pending_proposals(group)?;
    let (commit, welcome, _) = group
        .remove_members(provider, identity.signer(), &[leaf_index])
        .map_err(|_| Error::CryptoOperationFailed)?;
    if welcome.is_some() {
        return Err(Error::UnexpectedMessageContent);
    }
    let bytes = serialize_output(&commit, WireFormat::PublicMessage)?;
    group
        .merge_pending_commit(provider)
        .map_err(|_| Error::CryptoOperationFailed)?;
    validate_group_profile(group)?;
    Ok(bytes)
}

pub fn process_commit<S>(
    group: &mut MlsGroup,
    provider: &ProfileProvider<S>,
    bytes: &[u8],
) -> Result<(), Error>
where
    S: StorageProvider<CURRENT_VERSION>,
{
    validate_group_profile(group)?;
    let protocol = decode_protocol(bytes, WireFormat::PublicMessage)?;
    if protocol.content_type() != ContentType::Commit {
        return Err(Error::UnexpectedMessageContent);
    }
    let processed = group
        .process_message(provider, protocol)
        .map_err(|_| Error::CryptoOperationFailed)?;
    let commit = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => commit,
        _ => return Err(Error::UnexpectedMessageContent),
    };
    validate_staged_commit_profile(&commit)?;
    group
        .merge_staged_commit(provider, *commit)
        .map_err(|_| Error::CryptoOperationFailed)?;
    validate_group_profile(group)
}

pub fn find_member(group: &MlsGroup, credential_content: &[u8]) -> Result<LeafNodeIndex, Error> {
    validate_synthetic_credential_content(credential_content)?;
    group
        .members()
        .find(|member| member.credential.serialized_content() == credential_content)
        .map(|member| member.index)
        .ok_or(Error::GroupNotFound)
}

pub fn synthetic_credential_content(label: &str) -> Result<Vec<u8>, Error> {
    validate_synthetic_label(label.as_bytes())?;
    let mut content = Vec::with_capacity(SYNTHETIC_IDENTITY_PREFIX.len() + label.len());
    content.extend_from_slice(SYNTHETIC_IDENTITY_PREFIX);
    content.extend_from_slice(label.as_bytes());
    Ok(content)
}

fn validate_staged_commit_profile(commit: &StagedCommit) -> Result<(), Error> {
    validate_group_context(commit.group_context())?;
    if let Some(leaf_node) = commit.update_path_leaf_node() {
        validate_leaf_profile(leaf_node)?;
    }
    for queued in commit.queued_proposals() {
        if !matches!(queued.sender(), Sender::Member(_))
            || queued.proposal_or_ref_type() != ProposalOrRefType::Proposal
        {
            return Err(Error::UnsupportedCapability);
        }
        match queued.proposal() {
            Proposal::Add(add) => validate_key_package(add.key_package())?,
            Proposal::Update(update) => validate_leaf_profile(update.leaf_node())?,
            Proposal::Remove(_) => {}
            Proposal::PreSharedKey(_)
            | Proposal::ReInit(_)
            | Proposal::ExternalInit(_)
            | Proposal::GroupContextExtensions(_)
            | Proposal::SelfRemove
            | Proposal::Custom(_) => return Err(Error::UnsupportedCapability),
        }
    }
    Ok(())
}

fn ensure_no_pending_proposals(group: &MlsGroup) -> Result<(), Error> {
    if group.pending_proposals().next().is_some() {
        Err(Error::UnsupportedCapability)
    } else {
        Ok(())
    }
}

fn validate_group_profile(group: &MlsGroup) -> Result<(), Error> {
    validate_group_context(group.public_group().group_context())?;
    if group.configuration() != &join_config() {
        return Err(Error::UnsupportedCapability);
    }
    for member in group.members() {
        let leaf_node = group
            .public_group()
            .leaf(member.index)
            .ok_or(Error::CryptoOperationFailed)?;
        validate_leaf_profile(leaf_node)?;
    }
    Ok(())
}

fn validate_group_context(group_context: &GroupContext) -> Result<(), Error> {
    if group_context.protocol_version() != ProtocolVersion::Mls10 {
        return Err(Error::UnsupportedProtocolVersion);
    }
    ensure_profile_ciphersuite(group_context.ciphersuite())?;
    if group_context.extensions().iter().next().is_some() {
        return Err(Error::UnsupportedExtension);
    }
    Ok(())
}

fn validate_leaf_profile(leaf_node: &LeafNode) -> Result<(), Error> {
    if leaf_node.credential().credential_type() != CredentialType::Basic {
        return Err(Error::UnsupportedCredential);
    }
    if leaf_node.signature_key().as_slice().len() != 32 {
        return Err(Error::UnsupportedCredential);
    }
    validate_synthetic_credential_content(leaf_node.credential().serialized_content())?;
    if leaf_node.extensions().iter().next().is_some() {
        return Err(Error::UnsupportedExtension);
    }
    validate_capabilities(leaf_node.capabilities())
}

fn validate_synthetic_credential_content(content: &[u8]) -> Result<(), Error> {
    let label = content
        .strip_prefix(SYNTHETIC_IDENTITY_PREFIX)
        .ok_or(Error::InvalidSyntheticIdentity)?;
    validate_synthetic_label(label)
}

fn validate_synthetic_label(label: &[u8]) -> Result<(), Error> {
    if label.is_empty()
        || label.len() > 24
        || !label
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        Err(Error::InvalidSyntheticIdentity)
    } else {
        Ok(())
    }
}

pub fn decode_exact(bytes: &[u8]) -> Result<MlsMessageIn, Error> {
    ensure_wire_size(bytes, MAX_COMMIT_WIRE_BYTES)?;
    MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| Error::InvalidWireEncoding)
}

fn decode_protocol(bytes: &[u8], expected: WireFormat) -> Result<ProtocolMessage, Error> {
    let limit = match expected {
        WireFormat::PrivateMessage => MAX_APPLICATION_WIRE_BYTES,
        WireFormat::PublicMessage => MAX_COMMIT_WIRE_BYTES,
        _ => return Err(Error::UnexpectedWireFormat),
    };
    ensure_wire_size(bytes, limit)?;
    let message = decode_exact(bytes)?;
    if message.wire_format() != expected {
        return Err(Error::UnexpectedWireFormat);
    }
    message
        .try_into_protocol_message()
        .map_err(|_| Error::UnexpectedWireFormat)
}

fn serialize_output(message: &MlsMessageOut, expected: WireFormat) -> Result<Vec<u8>, Error> {
    let actual = match message.body() {
        MlsMessageBodyOut::PublicMessage(_) => WireFormat::PublicMessage,
        MlsMessageBodyOut::PrivateMessage(_) => WireFormat::PrivateMessage,
        MlsMessageBodyOut::Welcome(_) => WireFormat::Welcome,
        MlsMessageBodyOut::GroupInfo(_) => WireFormat::GroupInfo,
        MlsMessageBodyOut::KeyPackage(_) => WireFormat::KeyPackage,
    };
    if actual != expected {
        return Err(Error::UnexpectedWireFormat);
    }
    let bytes = message.to_bytes().map_err(|_| Error::InvalidWireEncoding)?;
    let limit = match actual {
        WireFormat::PrivateMessage => MAX_APPLICATION_WIRE_BYTES,
        WireFormat::PublicMessage => MAX_COMMIT_WIRE_BYTES,
        WireFormat::Welcome => MAX_WELCOME_WIRE_BYTES,
        WireFormat::KeyPackage => MAX_KEY_PACKAGE_WIRE_BYTES,
        _ => MAX_COMMIT_WIRE_BYTES,
    };
    ensure_wire_size(&bytes, limit)?;
    Ok(bytes)
}

fn ensure_wire_size(bytes: &[u8], maximum: usize) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err(Error::WireSizeExceeded)
    } else {
        Ok(())
    }
}
