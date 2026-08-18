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

const BRIDGE_PROTOCOL: u64 = 1;
const MAX_REQUEST_LINE_BYTES: usize = 2 * 1024 * 1024;

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
        })),
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
