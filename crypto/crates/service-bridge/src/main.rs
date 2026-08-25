//! Stdio JSONL bridge exposing the frozen-profile MLS core (ADR 0004).
//!
//! One JSON object per line on stdin; one response object per line on
//! stdout. Binary fields are lowercase hex. Responses carry only stable
//! `mls.*`/`bridge.*` codes - never dependency diagnostics, secrets, or
//! timestamps. The bridge is deterministic and stateless across requests.

use std::io::{BufRead, Write};

use juicebox_messaging_client_core as core_mls;
use openmls_memory_storage::MemoryStorage;
use serde_json::{json, Map, Value};

mod native_client;
use native_client::NativeMlsClient;

const BRIDGE_PROTOCOL: u64 = 1;
// State-threading client verbs carry a full client snapshot per request;
// a relay serving a handful of conversations stays well under this. The
// ceiling exists to bound memory, not to size-fit the snapshot.
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024 * 1024;

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_line(&line);
        if writeln!(out, "{response}").is_err() || out.flush().is_err() {
            break;
        }
    }
}

fn handle_line(line: &str) -> Value {
    if line.len() > MAX_REQUEST_LINE_BYTES {
        return error_response(Value::Null, "bridge.request_too_large");
    }
    let parsed: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => return error_response(Value::Null, "bridge.malformed_request"),
    };
    let request = match parsed.as_object() {
        Some(request) => request,
        None => return error_response(Value::Null, "bridge.malformed_request"),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if !matches!(id, Value::String(_)) {
        return error_response(Value::Null, "bridge.malformed_request");
    }
    let verb = match request.get("verb").and_then(Value::as_str) {
        Some(verb) => verb,
        None => return error_response(id, "bridge.malformed_request"),
    };
    match dispatch(verb, request) {
        Ok(result) => json!({ "id": id, "ok": true, "result": result }),
        Err(code) => error_response(id, code),
    }
}

fn dispatch(verb: &str, request: &Map<String, Value>) -> Result<Value, &'static str> {
    match verb {
        "bridge/describe" => Ok(json!({
            "bridgeProtocol": BRIDGE_PROTOCOL,
            "profile": "jb-msg-mls-v1",
            "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "maxKeyPackageWireBytes": core_mls::MAX_KEY_PACKAGE_WIRE_BYTES,
            "maxCommitWireBytes": core_mls::MAX_COMMIT_WIRE_BYTES,
            "maxWelcomeWireBytes": core_mls::MAX_WELCOME_WIRE_BYTES,
            "maxApplicationWireBytes": core_mls::MAX_APPLICATION_WIRE_BYTES,
            "keyPackageLifetimeSeconds": core_mls::KEY_PACKAGE_LIFETIME_SECONDS,
            // The relay is always the WELCOMED side; group creation and
            // Adds stay on member devices, so those verbs do not exist.
            "clientVerbs": [
                "client/create-identity",
                "client/generate-key-package",
                "client/join-welcome",
                "client/seal-application",
                "client/open-application",
                "client/process-commit",
            ],
        })),
        // State-threading client verbs (ADR 0006 phase 0). The caller
        // holds custody: a snapshot rides in, the op runs over the frozen
        // profile, and the MUTATED snapshot rides back out — MLS ratchets
        // advance on open/seal, so the returned state must always replace
        // the stored one atomically.
        "client/create-identity" => {
            let label = request
                .get("label")
                .and_then(Value::as_str)
                .ok_or("bridge.malformed_request")?;
            let client = NativeMlsClient::create(label).map_err(|error| error.code())?;
            Ok(json!({
                "state": client.export_state().map_err(|error| error.code())?,
                "signaturePublicKey": hex_encode(&client.signature_public_key()),
            }))
        }
        "client/generate-key-package" => {
            let client = client_from(request)?;
            let bytes = client
                .generate_key_package()
                .map_err(|error| error.code())?;
            Ok(json!({
                "state": client.export_state().map_err(|error| error.code())?,
                "keyPackage": hex_encode(&bytes),
            }))
        }
        "client/join-welcome" => {
            let client = client_from(request)?;
            let welcome = require_hex_field(request, "welcome")?;
            let group_id = client
                .join_from_welcome(&welcome)
                .map_err(|error| error.code())?;
            Ok(json!({
                "state": client.export_state().map_err(|error| error.code())?,
                "groupId": hex_encode(&group_id),
            }))
        }
        "client/seal-application" => {
            let client = client_from(request)?;
            let group_id = require_hex_field(request, "groupId")?;
            let plaintext = require_hex_field(request, "plaintext")?;
            let message = client
                .seal_application(&group_id, &plaintext)
                .map_err(|error| error.code())?;
            Ok(json!({
                "state": client.export_state().map_err(|error| error.code())?,
                "message": hex_encode(&message),
            }))
        }
        "client/open-application" => {
            let client = client_from(request)?;
            let group_id = require_hex_field(request, "groupId")?;
            let message = require_hex_field(request, "message")?;
            let plaintext = client
                .open_application(&group_id, &message)
                .map_err(|error| error.code())?;
            Ok(json!({
                "state": client.export_state().map_err(|error| error.code())?,
                "plaintext": hex_encode(&plaintext),
            }))
        }
        "client/process-commit" => {
            let client = client_from(request)?;
            let group_id = require_hex_field(request, "groupId")?;
            let commit = require_hex_field(request, "commit")?;
            client
                .process_commit(&group_id, &commit)
                .map_err(|error| error.code())?;
            Ok(json!({
                "state": client.export_state().map_err(|error| error.code())?,
            }))
        }
        "key-package/validate" => {
            let bytes = require_hex_field(request, "keyPackage")?;
            let provider = core_mls::ProfileProvider::new(MemoryStorage::default());
            match core_mls::decode_key_package(&provider, &bytes) {
                Ok(key_package) => {
                    let leaf = key_package.leaf_node();
                    Ok(json!({
                        "valid": true,
                        "credentialContent": hex_encode(
                            leaf.credential().serialized_content(),
                        ),
                        "signatureKey": hex_encode(leaf.signature_key().as_slice()),
                    }))
                }
                Err(error) => Ok(json!({ "valid": false, "code": error.code() })),
            }
        }
        // Lab-only: mints a KeyPackage for a visibly synthetic identity
        // (the jbm-pre-g1-synthetic:v1: label space). Production key
        // packages come from client devices, never from this verb.
        "key-package/generate-synthetic" => {
            let label = request
                .get("label")
                .and_then(Value::as_str)
                .ok_or("bridge.malformed_request")?;
            let provider = core_mls::ProfileProvider::new(MemoryStorage::default());
            let identity = core_mls::create_synthetic_identity(&provider, label)
                .map_err(|_| "bridge.malformed_request")?;
            let bytes = core_mls::generate_key_package(&provider, &identity)
                .map_err(|_| "bridge.crypto_operation_failed")?;
            Ok(json!({ "keyPackage": hex_encode(&bytes) }))
        }
        _ => Err("bridge.unknown_verb"),
    }
}

fn client_from(request: &Map<String, Value>) -> Result<NativeMlsClient, &'static str> {
    let state = request
        .get("state")
        .and_then(Value::as_str)
        .ok_or("bridge.malformed_request")?;
    NativeMlsClient::import_state(state).map_err(|error| error.code())
}

fn require_hex_field(request: &Map<String, Value>, field: &str) -> Result<Vec<u8>, &'static str> {
    let text = request
        .get(field)
        .and_then(Value::as_str)
        .ok_or("bridge.malformed_request")?;
    hex_decode(text).ok_or("bridge.malformed_request")
}

fn error_response(id: Value, code: &str) -> Value {
    json!({ "id": id, "ok": false, "error": { "code": code } })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    text
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_key_package_hex() -> String {
        let provider = core_mls::ProfileProvider::new(MemoryStorage::default());
        let identity =
            core_mls::create_synthetic_identity(&provider, "bridgetest").expect("identity");
        let bytes = core_mls::generate_key_package(&provider, &identity).expect("key package");
        hex_encode(&bytes)
    }

    #[test]
    fn describe_reports_the_frozen_profile() {
        let response = handle_line(r#"{"id":"a","verb":"bridge/describe"}"#);
        assert_eq!(response["ok"], Value::Bool(true));
        assert_eq!(response["result"]["bridgeProtocol"], json!(1));
        assert_eq!(
            response["result"]["ciphersuite"],
            json!("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"),
        );
    }

    #[test]
    fn validates_a_real_key_package_and_rejects_a_tampered_one() {
        let hex = generated_key_package_hex();
        let request = serde_json::to_string(&json!({
            "id": "b",
            "verb": "key-package/validate",
            "keyPackage": hex,
        }))
        .expect("request");
        let response = handle_line(&request);
        assert_eq!(response["ok"], Value::Bool(true));
        assert_eq!(response["result"]["valid"], Value::Bool(true));
        assert!(response["result"]["credentialContent"]
            .as_str()
            .is_some_and(|content| !content.is_empty()));

        let mut tampered = hex_decode(&hex).expect("decode");
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let request = serde_json::to_string(&json!({
            "id": "c",
            "verb": "key-package/validate",
            "keyPackage": hex_encode(&tampered),
        }))
        .expect("request");
        let response = handle_line(&request);
        assert_eq!(response["ok"], Value::Bool(true));
        assert_eq!(response["result"]["valid"], Value::Bool(false));
    }

    #[test]
    fn relay_state_threading_round_trip_over_the_verbs() {
        // The "member device" side runs the core directly (as a browser
        // would); the relay side is driven ONLY through the client/*
        // verbs, re-importing the returned snapshot at every step — which
        // is exactly the DB-custody model the service uses.
        let member = core_mls::ProfileProvider::new(MemoryStorage::default());
        let member_id =
            core_mls::create_synthetic_identity(&member, "member-device-1").expect("member");

        let created = handle_line(
            &serde_json::to_string(&json!({
                "id": "1", "verb": "client/create-identity", "label": "relay-tg-000001",
            }))
            .expect("request"),
        );
        assert_eq!(created["ok"], Value::Bool(true));
        let state_one = created["result"]["state"]
            .as_str()
            .expect("state")
            .to_owned();

        let generated = handle_line(
            &serde_json::to_string(&json!({
                "id": "2", "verb": "client/generate-key-package", "state": state_one,
            }))
            .expect("request"),
        );
        assert_eq!(generated["ok"], Value::Bool(true));
        let state_two = generated["result"]["state"]
            .as_str()
            .expect("state")
            .to_owned();
        let relay_key_package =
            hex_decode(generated["result"]["keyPackage"].as_str().expect("kp")).expect("kp hex");

        // Member creates the group and Adds the relay.
        let group_id = [0x77u8; 32];
        let mut group = core_mls::create_group(
            &member,
            &member_id,
            openmls::prelude::GroupId::from_slice(&group_id),
        )
        .expect("group");
        let decoded = core_mls::decode_key_package(&member, &relay_key_package).expect("decode");
        let (_commit, welcome) =
            core_mls::add_member(&mut group, &member, &member_id, &decoded).expect("add");

        let joined = handle_line(
            &serde_json::to_string(&json!({
                "id": "3", "verb": "client/join-welcome",
                "state": state_two, "welcome": hex_encode(&welcome),
            }))
            .expect("request"),
        );
        assert_eq!(joined["ok"], Value::Bool(true));
        assert_eq!(
            joined["result"]["groupId"].as_str().expect("group id"),
            hex_encode(&group_id),
        );
        let state_three = joined["result"]["state"]
            .as_str()
            .expect("state")
            .to_owned();

        // Member -> relay: the relay opens through the verbs.
        let sealed =
            core_mls::seal_application(&mut group, &member, &member_id, b"order #4 shipped")
                .expect("seal");
        let opened = handle_line(
            &serde_json::to_string(&json!({
                "id": "4", "verb": "client/open-application",
                "state": state_three, "groupId": hex_encode(&group_id),
                "message": hex_encode(&sealed),
            }))
            .expect("request"),
        );
        assert_eq!(opened["ok"], Value::Bool(true));
        assert_eq!(
            hex_decode(opened["result"]["plaintext"].as_str().expect("plaintext")).expect("hex"),
            b"order #4 shipped".to_vec(),
        );
        let state_four = opened["result"]["state"]
            .as_str()
            .expect("state")
            .to_owned();

        // Relay -> member: sealed through the verbs, opened by the member.
        let replied = handle_line(
            &serde_json::to_string(&json!({
                "id": "5", "verb": "client/seal-application",
                "state": state_four, "groupId": hex_encode(&group_id),
                "plaintext": hex_encode(b"thanks, got it"),
            }))
            .expect("request"),
        );
        assert_eq!(replied["ok"], Value::Bool(true));
        let reply_bytes =
            hex_decode(replied["result"]["message"].as_str().expect("message")).expect("hex");
        assert_eq!(
            core_mls::open_application(&mut group, &member, &reply_bytes).expect("open"),
            b"thanks, got it".to_vec(),
        );

        // A STALE snapshot must fail closed, not silently double-decrypt:
        // reusing state_three (pre-open) to open the same message again is
        // an MLS replay and the core refuses it... but a FRESH message
        // still opens with the LATEST snapshot.
        let sealed_two =
            core_mls::seal_application(&mut group, &member, &member_id, b"second").expect("seal");
        let latest_state = replied["result"]["state"].as_str().expect("state");
        let opened_two = handle_line(
            &serde_json::to_string(&json!({
                "id": "6", "verb": "client/open-application",
                "state": latest_state, "groupId": hex_encode(&group_id),
                "message": hex_encode(&sealed_two),
            }))
            .expect("request"),
        );
        assert_eq!(opened_two["ok"], Value::Bool(true));
    }

    #[test]
    fn malformed_and_unknown_requests_fail_closed() {
        assert_eq!(
            handle_line("not json")["error"]["code"],
            json!("bridge.malformed_request"),
        );
        assert_eq!(
            handle_line(r#"{"id":"d","verb":"nope"}"#)["error"]["code"],
            json!("bridge.unknown_verb"),
        );
        assert_eq!(
            handle_line(r#"{"verb":"bridge/describe"}"#)["error"]["code"],
            json!("bridge.malformed_request"),
        );
    }
}
