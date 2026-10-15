#!/usr/bin/env bash
# Copy or check the old-API model classes and extension interfaces taken from the Dafny-based MPL,
# used by the test adapter (test sources). These files carry no Dafny types,
# so they are copied from the smithy-generated sources instead of rewritten.
# The only change is dropping the "machine generated, do not modify" header line.
#
# Usage: scripts/sync-model.sh <mpl-checkout> <git-ref> [--check]
#   --check  compare instead of copy; exit 1 on any difference.
# The commit used for the current copy is recorded in MODEL_PROVENANCE.md.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <mpl-checkout> <git-ref> [--check]" >&2
  exit 2
fi
mpl_repo=$1
ref=$2
mode=${3:-copy}
if [[ $mode != copy && $mode != --check ]]; then
  echo "unknown option: $mode (expected --check)" >&2
  exit 2
fi

module_dir=$(cd "$(dirname "$0")/.." && pwd)
dest=$module_dir/src/test/java
mpl_gen=AwsCryptographicMaterialProviders/runtimes/java/src/main/smithy-generated
prim_gen=AwsCryptographyPrimitives/runtimes/java/src/main/smithy-generated

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
git -C "$mpl_repo" archive "$ref" "$mpl_gen" "$prim_gen" | tar -x -C "$staging"

# <generated root>|<path under it>, one per copied directory or file glob.
sources=(
  "$mpl_gen|software/amazon/cryptography/materialproviders/model"
  "$mpl_gen|software/amazon/cryptography/keystore/model"
  "$prim_gen|software/amazon/cryptography/primitives/model"
  "$mpl_gen|software/amazon/cryptography/materialproviders/IKeyring.java"
  "$mpl_gen|software/amazon/cryptography/materialproviders/ICryptographicMaterialsManager.java"
  "$mpl_gen|software/amazon/cryptography/materialproviders/ICryptographicMaterialsCache.java"
  "$mpl_gen|software/amazon/cryptography/materialproviders/IClientSupplier.java"
  "$mpl_gen|software/amazon/cryptography/materialproviders/IBranchKeyIdSupplier.java"
)

expected=$staging/expected
mkdir -p "$expected"
for entry in "${sources[@]}"; do
  root=${entry%%|*}
  path=${entry#*|}
  mkdir -p "$expected/$(dirname "$path")"
  cp -R "$staging/$root/$path" "$expected/$(dirname "$path")/"
done
find "$expected" -name '*.java' -exec sed -i.bak '/^\/\/ Do not modify this file\. This file is machine generated/d' {} +
find "$expected" -name '*.bak' -delete

if [[ $mode == --check ]]; then
  status=0
  for entry in "${sources[@]}"; do
    path=${entry#*|}
    diff -r "$expected/$path" "$dest/$path" || status=1
  done
  if [[ $status -eq 0 ]]; then
    echo "model classes match $ref"
  fi
  exit $status
fi

for entry in "${sources[@]}"; do
  path=${entry#*|}
  rm -rf "${dest:?}/$path"
  mkdir -p "$dest/$(dirname "$path")"
  cp -R "$expected/$path" "$dest/$(dirname "$path")/"
done
echo "copied model classes from $ref; update MODEL_PROVENANCE.md"
