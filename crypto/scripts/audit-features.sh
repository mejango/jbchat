#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_manifest_line() {
  grep -Fqx "$1" Cargo.toml || fail "missing frozen dependency declaration: $1"
}

require_manifest_line 'openmls = { version = "=0.9.0-rc.2", default-features = false }'
require_manifest_line 'openmls_traits = { version = "=0.6.0-rc.2", default-features = false }'
require_manifest_line 'openmls_rust_crypto = { version = "=0.6.0-rc.2", default-features = false }'
require_manifest_line 'openmls_basic_credential = { version = "=0.6.0-rc.2", default-features = false }'
require_manifest_line 'openmls_memory_storage = { version = "=0.6.0-rc.2", default-features = false }'
require_manifest_line 'tls_codec = { version = "=0.5.0", default-features = false, features = ["std", "mls"] }'

for manifest in Cargo.toml crates/*/Cargo.toml; do
  if grep -Eq '^\[(patch|replace)(\.|\])|git[[:space:]]*=' "$manifest"; then
    fail "git dependency, [patch], or [replace] is forbidden: $manifest"
  fi
  if grep -Eq '^(openmls|openmls_traits|openmls_rust_crypto|openmls_basic_credential|openmls_memory_storage|tls_codec)[[:space:]]*=.*path[[:space:]]*=' "$manifest"; then
    fail "path substitution of a frozen dependency is forbidden: $manifest"
  fi
done

check_lock_package() {
  name=$1
  version=$2
  checksum=$3
  awk -v wanted_name="$name" -v wanted_version="$version" -v wanted_checksum="$checksum" '
    function finish_package() {
      if (package_name == wanted_name) {
        matches += 1
        if (package_version == wanted_version &&
            package_source == "registry+https://github.com/rust-lang/crates.io-index" &&
            package_checksum == wanted_checksum) {
          valid += 1
        }
      }
    }
    /^\[\[package\]\]$/ {
      finish_package()
      package_name = ""
      package_version = ""
      package_source = ""
      package_checksum = ""
      next
    }
    /^name = "/ {
      package_name = $0
      sub(/^name = "/, "", package_name)
      sub(/"$/, "", package_name)
      next
    }
    /^version = "/ {
      package_version = $0
      sub(/^version = "/, "", package_version)
      sub(/"$/, "", package_version)
      next
    }
    /^source = "/ {
      package_source = $0
      sub(/^source = "/, "", package_source)
      sub(/"$/, "", package_source)
      next
    }
    /^checksum = "/ {
      package_checksum = $0
      sub(/^checksum = "/, "", package_checksum)
      sub(/"$/, "", package_checksum)
      next
    }
    END {
      finish_package()
      if (matches != 1 || valid != 1) {
        exit 1
      }
    }
  ' Cargo.lock || fail "frozen crates.io lock provenance mismatch: $name@$version"
}

check_lock_package openmls 0.9.0-rc.2 69bc05fbaa221e0c90274a444ac9b90f46df015a6ff2e64a32aa5d5e8776f2a6
check_lock_package openmls_traits 0.6.0-rc.2 30291504cce93833c94a57b10d02c23ccec2f305bf95d456595b7ab20ed3ccaa
check_lock_package openmls_rust_crypto 0.6.0-rc.2 98dd6e5c747d84276682dc86f332a6e345354af3320992bdd58051b50e64ae8a
check_lock_package openmls_basic_credential 0.6.0-rc.2 989fdeb6e749cdf23360461fc4c2f006cdfa129b49a39bf4367ba3f7bbf0620c
check_lock_package openmls_memory_storage 0.6.0-rc.2 0d6a05628cc28c6b01fbcadd6fc139c214bb71b43fdfcecc44e91071d7c6f414
check_lock_package tls_codec 0.5.0 18cc98286004cea38f717e2b03d990fc774fbfd38a82720de40e5c94365067c8

feature_tree="$(cargo tree --locked -e features --prefix none)"
forbidden='(^openmls(_traits|_rust_crypto|_basic_credential|_memory_storage)? feature "(crypto-debug|content-debug|test-utils|backtrace|all-ciphersuites|generate-kats|draft-ietf-mls-pq-ciphersuites|extensions-draft|extensions-draft-test-dependencies|targeted-messages-draft|virtual-clients-draft|virtual-clients-draft-test-dependencies|fork-resolution|migration-import|migration-export|0-8-1-storage-format|libcrux-provider|sqlite-provider|unchecked-conversions|js|js-test|persistence|clonable)"|^openmls_(libcrux_crypto|sqlite_storage|test) v)'

if printf '%s\n' "$feature_tree" | grep -Eq "$forbidden"; then
  printf '%s\n' 'forbidden OpenMLS crate or feature enabled' >&2
  printf '%s\n' "$feature_tree" | grep -E "$forbidden" >&2
  exit 1
fi

effective_direct_features="$({
  printf '%s\n' "$feature_tree" |
    grep -E '^(openmls|openmls_traits|openmls_rust_crypto|openmls_basic_credential|openmls_memory_storage|tls_codec) feature ' || true
} | sed 's/ (\*)$//' | sort -u)"
unexpected_direct_features="$({
  printf '%s\n' "$effective_direct_features" |
    grep -Ev '^(openmls_memory_storage feature "default"|openmls_traits feature "default"|tls_codec feature "(default|derive|mls|serde|std|tls_codec_derive)")$' || true
})"
if [ -n "$unexpected_direct_features" ]; then
  printf '%s\n' 'unexpected effective feature on a frozen direct dependency' >&2
  printf '%s\n' "$unexpected_direct_features" >&2
  exit 1
fi

printf '%s\n' 'OpenMLS manifest, lock provenance, and host feature policy: pass'
