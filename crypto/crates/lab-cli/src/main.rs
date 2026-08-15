use juicebox_messaging_mls_lab_store::LabClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut alice = LabClient::new("alice")?;
    let mut bob = LabClient::new("bob")?;

    alice.create_group(b"pre-g1-cli-group")?;
    let pre_join = alice.seal("application:alice:prejoin", b"pre-join history")?;
    let bob_key_package = bob.publish_key_package("kp:bob:1")?;
    let (_add_commit, welcome) = alice.add_member(&bob_key_package, "commit:add:bob")?;
    bob.join(&welcome)?;
    if bob.open("incoming:alice:prejoin", &pre_join).is_ok() {
        return Err("pre-join history was unexpectedly readable".into());
    }

    let ciphertext = alice.seal("application:alice:1", b"synthetic hello")?;
    let plaintext = bob.open("incoming:alice:1", &ciphertext)?;
    if plaintext != b"synthetic hello" {
        return Err("Alice-to-Bob plaintext mismatch".into());
    }

    let reply = bob.seal("application:bob:1", b"synthetic reply")?;
    if alice.open("incoming:bob:1", &reply)? != b"synthetic reply" {
        return Err("Bob-to-Alice plaintext mismatch".into());
    }

    let update = bob.update("commit:update:bob:1")?;
    alice.process_commit("incoming:commit:update:bob:1", &update)?;
    let after_update = alice.seal("application:alice:2", b"after update")?;
    if bob.open("incoming:alice:2", &after_update)? != b"after update" {
        return Err("post-Update plaintext mismatch".into());
    }

    let remove = alice.remove("bob", "commit:remove:bob:1")?;
    bob.process_commit("incoming:commit:remove:bob:1", &remove)?;
    if bob.is_active()? {
        return Err("removed member remained active".into());
    }
    let after_remove = alice.seal("application:alice:3", b"after removal")?;
    if bob.open("incoming:alice:3", &after_remove).is_ok() {
        return Err("removed member decrypted a post-removal message".into());
    }

    println!("pre-G1 native MLS flow completed; no production claim");
    Ok(())
}
