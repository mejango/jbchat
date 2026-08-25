//! Native state-threading MLS client for the bridge's `client/*` verbs.
//!
//! The SAME versioned snapshot envelope as the wasm client (version 1,
//! label, signature public key, sorted hex storage entries), so a state
//! blob is interoperable across both. The bridge stays stateless: every
//! verb takes a snapshot in and hands the mutated snapshot back — group
//! secrets never live in the bridge process between requests (ADR 0004's
//! custody boundary; the caller seals the snapshot at rest).

use std::collections::HashMap;
use std::sync::RwLock;

use juicebox_messaging_client_core as core_mls;
use openmls::prelude::{GroupId, OpenMlsProvider};
use openmls_memory_storage::MemoryStorage;
use serde_json::Value;

const STATE_VERSION: u64 = 1;

pub struct NativeMlsClient {
    provider: core_mls::ProfileProvider<MemoryStorage>,
    identity: core_mls::SyntheticIdentity,
    label: String,
}

pub enum ClientError {
    Malformed,
    Crypto(&'static str),
}

impl ClientError {
    pub fn code(&self) -> &'static str {
        match self {
            ClientError::Malformed => "bridge.malformed_request",
            ClientError::Crypto(code) => code,
        }
    }
}

fn crypto_fail(error: core_mls::Error) -> ClientError {
    ClientError::Crypto(error.code())
}

impl NativeMlsClient {
    pub fn create(label: &str) -> Result<NativeMlsClient, ClientError> {
        let provider = core_mls::ProfileProvider::new(MemoryStorage::default());
        let identity =
            core_mls::create_synthetic_identity(&provider, label).map_err(crypto_fail)?;
        Ok(NativeMlsClient {
            provider,
            identity,
            label: label.to_owned(),
        })
    }

    pub fn export_state(&self) -> Result<String, ClientError> {
        let mut entries: Vec<(String, String)> = Vec::new();
        {
            let values = self
                .provider
                .storage()
                .values
                .read()
                .map_err(|_| ClientError::Crypto("bridge.crypto_operation_failed"))?;
            for (key, value) in values.iter() {
                entries.push((hex_encode(key), hex_encode(value)));
            }
        }
        entries.sort();
        let state = serde_json::json!({
            "version": STATE_VERSION,
            "label": self.label,
            "signaturePublicKey": hex_encode(self.identity.signer().public()),
            "entries": entries,
        });
        serde_json::to_string(&state)
            .map_err(|_| ClientError::Crypto("bridge.crypto_operation_failed"))
    }

    pub fn import_state(json: &str) -> Result<NativeMlsClient, ClientError> {
        let parsed: Value = serde_json::from_str(json).map_err(|_| ClientError::Malformed)?;
        if parsed.get("version").and_then(Value::as_u64) != Some(STATE_VERSION) {
            return Err(ClientError::Malformed);
        }
        let label = parsed
            .get("label")
            .and_then(Value::as_str)
            .ok_or(ClientError::Malformed)?
            .to_owned();
        let public_key = parsed
            .get("signaturePublicKey")
            .and_then(Value::as_str)
            .and_then(hex_decode)
            .ok_or(ClientError::Malformed)?;
        let entries = parsed
            .get("entries")
            .and_then(Value::as_array)
            .ok_or(ClientError::Malformed)?;
        let mut values: HashMap<Vec<u8>, Vec<u8>> = HashMap::with_capacity(entries.len());
        for entry in entries {
            let pair = entry
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or(ClientError::Malformed)?;
            let key = pair[0]
                .as_str()
                .and_then(hex_decode)
                .ok_or(ClientError::Malformed)?;
            let value = pair[1]
                .as_str()
                .and_then(hex_decode)
                .ok_or(ClientError::Malformed)?;
            values.insert(key, value);
        }
        let provider = core_mls::ProfileProvider::new(MemoryStorage {
            values: RwLock::new(values),
        });
        let identity = core_mls::load_synthetic_identity(&provider, &label, &public_key)
            .map_err(crypto_fail)?;
        Ok(NativeMlsClient {
            provider,
            identity,
            label,
        })
    }

    pub fn signature_public_key(&self) -> Vec<u8> {
        self.identity.signer().public().to_vec()
    }

    pub fn generate_key_package(&self) -> Result<Vec<u8>, ClientError> {
        core_mls::generate_key_package(&self.provider, &self.identity).map_err(crypto_fail)
    }

    pub fn join_from_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>, ClientError> {
        let group = core_mls::join_from_welcome(&self.provider, welcome).map_err(crypto_fail)?;
        Ok(group.group_id().as_slice().to_vec())
    }

    pub fn seal_application(
        &self,
        group_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let mut group = core_mls::load_group(&self.provider, &GroupId::from_slice(group_id))
            .map_err(crypto_fail)?;
        core_mls::seal_application(&mut group, &self.provider, &self.identity, plaintext)
            .map_err(crypto_fail)
    }

    pub fn open_application(
        &self,
        group_id: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let mut group = core_mls::load_group(&self.provider, &GroupId::from_slice(group_id))
            .map_err(crypto_fail)?;
        core_mls::open_application(&mut group, &self.provider, message).map_err(crypto_fail)
    }

    pub fn process_commit(&self, group_id: &[u8], commit: &[u8]) -> Result<(), ClientError> {
        let mut group = core_mls::load_group(&self.provider, &GroupId::from_slice(group_id))
            .map_err(crypto_fail)?;
        core_mls::process_commit(&mut group, &self.provider, commit).map_err(crypto_fail)
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    text
}

pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let raw = text.as_bytes();
    for pair in raw.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_nibble(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character - b'0'),
        b'a'..=b'f' => Some(character - b'a' + 10),
        _ => None,
    }
}
