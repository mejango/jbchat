//! Checked-in rejection corpus and deterministic mutation smoke (CRY-05/06).
//!
//! Every file under `crypto/corpus/<ingress>/` must be rejected by that
//! ingress without consuming state, and a seeded structured mutator drives
//! additional adversarial inputs through every ingress each run. The corpus
//! is regenerated with
//! `cargo test -p juicebox-messaging-mls-lab-store --test rejection_corpus \
//!    regenerate_rejection_corpus -- --ignored --exact`
//! and the resulting files are committed. Coverage-guided fuzzing on the
//! exact release artifact (CRY-06's sanitizer/fuzz smoke) additionally
//! requires the nightly cargo-fuzz toolchain and stays tracked as launch
//! work; this deterministic smoke is its offline floor, not its substitute.

use std::fs;
use std::path::{Path, PathBuf};

use juicebox_messaging_mls_lab_store::harness::scenarios;
use juicebox_messaging_mls_lab_store::{Error, LabClient};

const INGRESSES: [&str; 4] = ["application", "commit", "key-package", "welcome"];

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn must<T>(result: Result<T, Error>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("corpus fixture setup failed"),
    }
}

/// Fresh valid artifacts for one lab round: an application ciphertext, an
/// update Commit, a spendable KeyPackage, and a targeted Welcome, together
/// with the receivers that must reject mutants of them.
struct Round {
    alice: LabClient,
    bob: LabClient,
    carol: LabClient,
    application: Vec<u8>,
    commit: Vec<u8>,
    key_package: Vec<u8>,
    welcome: Vec<u8>,
}

fn round() -> Round {
    // Everything advances on Alice's chain so Bob's epoch stays behind the
    // artifacts he must still be able to accept after every rejection.
    let (mut alice, bob, _pre_join) = scenarios::joined_pair::<LabClient>();
    let mut carol = must(LabClient::new("carol"));
    let application = must(alice.seal("application:alice:corpus", b"corpus payload"));
    let commit = must(alice.update("commit:update:alice:corpus"));
    let key_package = must(carol.publish_key_package("key-package:carol:corpus"));
    let (_add, welcome) = must(alice.add_member(&key_package, "commit:add:carol:corpus"));
    Round {
        alice,
        bob,
        carol,
        application,
        commit,
        key_package,
        welcome,
    }
}

impl Round {
    /// Feeds one adversarial input to one ingress; the envelope id is unique
    /// per attempt so replay identity never masks a decode acceptance.
    fn ingest(&mut self, ingress: &str, attempt: usize, bytes: &[u8]) -> Result<(), Error> {
        match ingress {
            "application" => self
                .bob
                .open(&format!("incoming:corpus:app:{attempt}"), bytes)
                .map(|_| ()),
            "commit" => self
                .bob
                .process_commit(&format!("incoming:corpus:commit:{attempt}"), bytes),
            "key-package" => self
                .alice
                .add_member(bytes, &format!("commit:add:corpus:{attempt}"))
                .map(|_| ()),
            "welcome" => self.carol.join(bytes),
            _ => panic!("unknown ingress"),
        }
    }

    fn valid_artifact(&self, ingress: &str) -> &[u8] {
        match ingress {
            "application" => &self.application,
            "commit" => &self.commit,
            "key-package" => &self.key_package,
            "welcome" => &self.welcome,
            _ => panic!("unknown ingress"),
        }
    }
}

/// The fixed corpus derivations applied to one valid artifact. Each entry is
/// (name, bytes); identity transforms are excluded by construction.
fn derivations(valid: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<(String, Vec<u8>)> = vec![
        ("empty".into(), Vec::new()),
        ("single-zero".into(), vec![0]),
        ("garbage-64".into(), vec![0xff; 64]),
        ("garbage-1024".into(), vec![0xa5; 1024]),
        ("ascii-noise".into(), b"not an mls message at all".to_vec()),
    ];
    let mut trailing = valid.to_vec();
    trailing.push(0x42);
    entries.push(("trailing-byte".into(), trailing));
    let mut first_flip = valid.to_vec();
    first_flip[0] ^= 0xff;
    entries.push(("first-byte-flip".into(), first_flip));
    let mut mid_flip = valid.to_vec();
    let mid = mid_flip.len() / 2;
    mid_flip[mid] ^= 0x01;
    entries.push(("mid-byte-flip".into(), mid_flip));
    let mut last_flip = valid.to_vec();
    let last = last_flip.len() - 1;
    last_flip[last] ^= 0x80;
    entries.push(("last-byte-flip".into(), last_flip));
    entries.push(("truncated-half".into(), valid[..valid.len() / 2].to_vec()));
    entries.push(("truncated-one".into(), valid[..valid.len() - 1].to_vec()));
    let mut doubled = valid.to_vec();
    doubled.extend_from_slice(valid);
    entries.push(("doubled".into(), doubled));
    entries
}

#[test]
#[ignore = "writes the committed corpus; run explicitly to regenerate"]
fn regenerate_rejection_corpus() {
    let round = round();
    for ingress in INGRESSES {
        let directory = corpus_root().join(ingress);
        fs::create_dir_all(&directory).expect("corpus directory");
        for (name, bytes) in derivations(round.valid_artifact(ingress)) {
            fs::write(directory.join(format!("{name}.bin")), bytes).expect("corpus entry");
        }
    }
}

#[test]
fn every_checked_in_corpus_entry_is_rejected_without_consuming_state() {
    let mut round = round();
    for ingress in INGRESSES {
        let directory = corpus_root().join(ingress);
        let mut entries: Vec<PathBuf> = fs::read_dir(&directory)
            .unwrap_or_else(|_| panic!("missing corpus directory {}", directory.display()))
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|extension| extension == "bin"))
            .collect();
        entries.sort();
        assert!(
            entries.len() >= 12,
            "corpus for {ingress} is too small: {}",
            entries.len()
        );
        for (attempt, path) in entries.iter().enumerate() {
            let bytes = fs::read(path).expect("corpus entry readable");
            let revision_before = match ingress {
                "application" | "commit" => round.bob.revision(),
                "key-package" => round.alice.revision(),
                "welcome" => round.carol.revision(),
                _ => unreachable!(),
            };
            let result = round.ingest(ingress, attempt, &bytes);
            assert!(
                result.is_err(),
                "corpus entry {} was accepted by {ingress}",
                path.display()
            );
            let revision_after = match ingress {
                "application" | "commit" => round.bob.revision(),
                "key-package" => round.alice.revision(),
                "welcome" => round.carol.revision(),
                _ => unreachable!(),
            };
            assert_eq!(revision_before, revision_after);
        }
    }

    // The rejections consumed no state: the exact valid artifacts still land.
    let application = round.application.clone();
    assert_eq!(
        must(round.bob.open("incoming:corpus:valid", &application)),
        b"corpus payload"
    );
    let commit = round.commit.clone();
    must(
        round
            .bob
            .process_commit("incoming:corpus:valid-commit", &commit),
    );
    let welcome = round.welcome.clone();
    must(round.carol.join(&welcome));
}

struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

/// Deterministic structured-mutation smoke over every ingress. Scaled by
/// `JBM_G1_FUZZ_MUTATIONS` (default 500 per ingress; evidence runs raise it).
/// Every non-identity mutant must be rejected and must never panic.
#[test]
fn seeded_mutation_smoke_rejects_every_mutant() {
    let mutations: usize = std::env::var("JBM_G1_FUZZ_MUTATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(500);
    let mut generator = XorShift64(0x6a62_6d5f_6731_0001);
    for ingress in INGRESSES {
        let mut round = round();
        let valid = round.valid_artifact(ingress).to_vec();
        for attempt in 0..mutations {
            let mut mutant = valid.clone();
            match generator.below(4) {
                0 => {
                    let index = generator.below(mutant.len());
                    mutant[index] ^= (generator.next() % 255 + 1) as u8;
                }
                1 => {
                    let keep = generator.below(mutant.len());
                    mutant.truncate(keep);
                }
                2 => {
                    let extra = generator.below(32) + 1;
                    for _ in 0..extra {
                        mutant.push(generator.next() as u8);
                    }
                }
                _ => {
                    let index = generator.below(mutant.len());
                    let splice = generator.below(mutant.len());
                    mutant[index] = valid[splice] ^ 0x55;
                    if mutant == valid {
                        mutant[index] ^= 0x01;
                    }
                }
            }
            if mutant == valid {
                continue;
            }
            let result = round.ingest(ingress, attempt, &mutant);
            assert!(
                result.is_err(),
                "seeded mutant {attempt} was accepted by {ingress}"
            );
        }
    }
}
