//! Browser MLS client: the frozen-profile client core compiled to wasm32.
//!
//! Every operation delegates to `juicebox-messaging-client-core` - the same
//! validated core the G1 harness and the service bridge run - over an
//! in-memory OpenMLS storage provider. The host persists the client by
//! round-tripping `export_state`/`import_state` (a versioned JSON snapshot
//! of the storage map plus the identity's label and public key); private
//! key material stays inside the snapshot and never crosses in any other
//! shape.

use std::collections::HashMap;
use std::sync::RwLock;

use juicebox_messaging_client_core as core_mls;
use openmls::prelude::{GroupId, OpenMlsProvider};
use openmls_memory_storage::MemoryStorage;
use wasm_bindgen::prelude::*;

const STATE_VERSION: u64 = 1;

#[wasm_bindgen]
pub struct MlsClient {
    provider: core_mls::ProfileProvider<MemoryStorage>,
    identity: core_mls::SyntheticIdentity,
    label: String,
}

/// The artifacts an Add Commit produces: the public Commit message, the
/// Welcome for the added member, and the resulting group state markers the
/// delivery plane records.
#[wasm_bindgen(getter_with_clone)]
pub struct AddMemberOutput {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub epoch: u64,
    pub confirmed_transcript_hash: Vec<u8>,
}

fn fail(error: core_mls::Error) -> JsError {
    JsError::new(&error.to_string())
}

fn state_fail(reason: &str) -> JsError {
    JsError::new(reason)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

#[wasm_bindgen]
impl MlsClient {
    /// Create a fresh client identity under the given synthetic label
    /// (bounded lowercase ASCII; the host derives it from the installation
    /// id, never from PII).
    #[wasm_bindgen(constructor)]
    pub fn new(label: &str) -> Result<MlsClient, JsError> {
        let provider = core_mls::ProfileProvider::new(MemoryStorage::default());
        let identity = core_mls::create_synthetic_identity(&provider, label).map_err(fail)?;
        Ok(MlsClient {
            provider,
            identity,
            label: label.to_owned(),
        })
    }

    /// Serialize the whole client - storage map, label, and signature
    /// public key - as a versioned JSON snapshot for host persistence.
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Result<String, JsError> {
        let mut entries: Vec<(String, String)> = Vec::new();
        {
            let values = self
                .provider
                .storage()
                .values
                .read()
                .map_err(|_| state_fail("storage lock poisoned"))?;
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
        serde_json::to_string(&state).map_err(|_| state_fail("state serialization failed"))
    }

    /// Rebuild a client from an `export_state` snapshot.
    #[wasm_bindgen(js_name = importState)]
    pub fn import_state(json: &str) -> Result<MlsClient, JsError> {
        let parsed: serde_json::Value =
            serde_json::from_str(json).map_err(|_| state_fail("state is not valid JSON"))?;
        if parsed.get("version").and_then(serde_json::Value::as_u64) != Some(STATE_VERSION) {
            return Err(state_fail("unsupported state version"));
        }
        let label = parsed
            .get("label")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| state_fail("state label missing"))?
            .to_owned();
        let public_key = parsed
            .get("signaturePublicKey")
            .and_then(serde_json::Value::as_str)
            .and_then(hex_decode)
            .ok_or_else(|| state_fail("state public key missing"))?;
        let entries = parsed
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| state_fail("state entries missing"))?;
        let mut values: HashMap<Vec<u8>, Vec<u8>> = HashMap::with_capacity(entries.len());
        for entry in entries {
            let pair = entry
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(|| state_fail("state entry malformed"))?;
            let key = pair[0]
                .as_str()
                .and_then(hex_decode)
                .ok_or_else(|| state_fail("state entry key malformed"))?;
            let value = pair[1]
                .as_str()
                .and_then(hex_decode)
                .ok_or_else(|| state_fail("state entry value malformed"))?;
            values.insert(key, value);
        }
        let provider = core_mls::ProfileProvider::new(MemoryStorage {
            values: RwLock::new(values),
        });
        let identity =
            core_mls::load_synthetic_identity(&provider, &label, &public_key).map_err(fail)?;
        Ok(MlsClient {
            provider,
            identity,
            label,
        })
    }

    #[wasm_bindgen(js_name = credentialLabel)]
    pub fn credential_label(&self) -> String {
        self.label.clone()
    }

    /// Raw 32-byte Ed25519 signature public key of this identity.
    #[wasm_bindgen(js_name = signaturePublicKey)]
    pub fn signature_public_key(&self) -> Vec<u8> {
        self.identity.signer().public().to_vec()
    }

    /// Serialized MLS KeyPackage message (profile ciphersuite 0x0001).
    #[wasm_bindgen(js_name = generateKeyPackage)]
    pub fn generate_key_package(&self) -> Result<Vec<u8>, JsError> {
        core_mls::generate_key_package(&self.provider, &self.identity).map_err(fail)
    }

    /// Create a new group under the caller-chosen group id.
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(&self, group_id: &[u8]) -> Result<(), JsError> {
        core_mls::create_group(
            &self.provider,
            &self.identity,
            GroupId::from_slice(group_id),
        )
        .map(|_| ())
        .map_err(fail)
    }

    /// Add a member by their serialized KeyPackage: returns the public
    /// Commit, the member's Welcome, and the post-merge group markers.
    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(
        &self,
        group_id: &[u8],
        key_package: &[u8],
    ) -> Result<AddMemberOutput, JsError> {
        let mut group =
            core_mls::load_group(&self.provider, &GroupId::from_slice(group_id)).map_err(fail)?;
        let decoded = core_mls::decode_key_package(&self.provider, key_package).map_err(fail)?;
        let (commit, welcome) =
            core_mls::add_member(&mut group, &self.provider, &self.identity, &decoded)
                .map_err(fail)?;
        Ok(AddMemberOutput {
            commit,
            welcome,
            epoch: group.epoch().as_u64(),
            confirmed_transcript_hash: group
                .public_group()
                .group_context()
                .confirmed_transcript_hash()
                .to_vec(),
        })
    }

    /// Join a group from a serialized Welcome; returns the group id.
    #[wasm_bindgen(js_name = joinFromWelcome)]
    pub fn join_from_welcome(&self, welcome: &[u8]) -> Result<Vec<u8>, JsError> {
        let group = core_mls::join_from_welcome(&self.provider, welcome).map_err(fail)?;
        Ok(group.group_id().as_slice().to_vec())
    }

    #[wasm_bindgen(js_name = groupEpoch)]
    pub fn group_epoch(&self, group_id: &[u8]) -> Result<u64, JsError> {
        let group =
            core_mls::load_group(&self.provider, &GroupId::from_slice(group_id)).map_err(fail)?;
        Ok(group.epoch().as_u64())
    }

    #[wasm_bindgen(js_name = groupConfirmedTranscriptHash)]
    pub fn group_confirmed_transcript_hash(&self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        let group =
            core_mls::load_group(&self.provider, &GroupId::from_slice(group_id)).map_err(fail)?;
        Ok(group
            .public_group()
            .group_context()
            .confirmed_transcript_hash()
            .to_vec())
    }

    /// Seal an application payload into a PrivateMessage.
    #[wasm_bindgen(js_name = sealApplication)]
    pub fn seal_application(&self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut group =
            core_mls::load_group(&self.provider, &GroupId::from_slice(group_id)).map_err(fail)?;
        core_mls::seal_application(&mut group, &self.provider, &self.identity, plaintext)
            .map_err(fail)
    }

    /// Open a PrivateMessage application payload from another member.
    #[wasm_bindgen(js_name = openApplication)]
    pub fn open_application(&self, group_id: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut group =
            core_mls::load_group(&self.provider, &GroupId::from_slice(group_id)).map_err(fail)?;
        core_mls::open_application(&mut group, &self.provider, message).map_err(fail)
    }

    /// Process and merge another member's Commit.
    #[wasm_bindgen(js_name = processCommit)]
    pub fn process_commit(&self, group_id: &[u8], commit: &[u8]) -> Result<(), JsError> {
        let mut group =
            core_mls::load_group(&self.provider, &GroupId::from_slice(group_id)).map_err(fail)?;
        core_mls::process_commit(&mut group, &self.provider, commit).map_err(fail)
    }
}

#[cfg(test)]
mod tests {
    use super::MlsClient;

    #[test]
    fn full_conversation_round_trip_survives_state_export() {
        let alice = MlsClient::new("creator-1").expect("alice");
        let bob = MlsClient::new("member-2").expect("bob");
        let group_id = [0x42u8; 32];

        let bob_key_package = bob.generate_key_package().expect("key package");
        alice.create_group(&group_id).expect("create");
        let added = alice
            .add_member(&group_id, &bob_key_package)
            .expect("add member");
        assert_eq!(added.epoch, 1);
        assert_eq!(added.confirmed_transcript_hash.len(), 32);

        let joined_group_id = bob.join_from_welcome(&added.welcome).expect("join");
        assert_eq!(joined_group_id, group_id);
        assert_eq!(
            bob.group_confirmed_transcript_hash(&group_id)
                .expect("hash"),
            added.confirmed_transcript_hash,
        );

        let sealed = alice
            .seal_application(&group_id, b"hello bob")
            .expect("seal");
        assert_eq!(
            bob.open_application(&group_id, &sealed).expect("open"),
            b"hello bob",
        );

        // Persistence: bob survives an export/import cycle and can still
        // both read and write.
        let snapshot = bob.export_state().expect("export");
        drop(bob);
        let bob = MlsClient::import_state(&snapshot).expect("import");
        let sealed_two = alice
            .seal_application(&group_id, b"after restore")
            .expect("seal two");
        assert_eq!(
            bob.open_application(&group_id, &sealed_two)
                .expect("open two"),
            b"after restore",
        );
        let reply = bob
            .seal_application(&group_id, b"reply from restored state")
            .expect("reply");
        assert_eq!(
            alice
                .open_application(&group_id, &reply)
                .expect("read reply"),
            b"reply from restored state",
        );
    }
}
