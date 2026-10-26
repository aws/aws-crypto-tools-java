#!/usr/bin/env bash
# Copy or check the old-API model classes and extension interfaces taken from the Dafny-based MPL,
# used by the test adapter (test sources). These files carry no Dafny types,
# so they are copied from the smithy-generated sources instead of rewritten.
# The copy moves them under software.amazon.cryptography.oldapi, because the main sources
# use their package names; it changes the package and import lines to match,
# and drops the "machine generated, do not modify" header line.
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
package_root=software/amazon/cryptography
old_api=$package_root/oldapi
mpl_gen=AwsCryptographicMaterialProviders/runtimes/java/src/main/smithy-generated
prim_gen=AwsCryptographyPrimitives/runtimes/java/src/main/smithy-generated

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
git -C "$mpl_repo" archive "$ref" "$mpl_gen" "$prim_gen" | tar -x -C "$staging"

# <generated root>|<path under $package_root>, one per copied directory or file.
# Each lands at the same path under $old_api in the test sources.
sources=(
  "$mpl_gen|materialproviders/model"
  "$mpl_gen|keystore/model"
  "$prim_gen|primitives/model"
  "$mpl_gen|materialproviders/IKeyring.java"
  "$mpl_gen|materialproviders/ICryptographicMaterialsManager.java"
  "$mpl_gen|materialproviders/ICryptographicMaterialsCache.java"
  "$mpl_gen|materialproviders/IClientSupplier.java"
  "$mpl_gen|materialproviders/IBranchKeyIdSupplier.java"
)

expected=$staging/expected
mkdir -p "$expected"
for entry in "${sources[@]}"; do
  root=${entry%%|*}
  path=${entry#*|}
  mkdir -p "$expected/$old_api/$(dirname "$path")"
  cp -R "$staging/$root/$package_root/$path" "$expected/$old_api/$(dirname "$path")/"
done
find "$expected" -name '*.java' -exec sed -i.bak -E \
  -e '/^\/\/ Do not modify this file\. This file is machine generated/d' \
  -e 's/^((package|import) software\.amazon\.cryptography\.)(materialproviders|keystore|primitives)([.;])/\1oldapi.\3\4/' \
  {} +
find "$expected" -name '*.bak' -delete

if [[ $mode == --check ]]; then
  status=0
  for entry in "${sources[@]}"; do
    path=$old_api/${entry#*|}
    diff -r "$expected/$path" "$dest/$path" || status=1
  done
  if [[ $status -eq 0 ]]; then
    echo "model classes match $ref"
  fi
  exit $status
fi

for entry in "${sources[@]}"; do
  path=$old_api/${entry#*|}
  rm -rf "${dest:?}/$path"
  mkdir -p "$dest/$(dirname "$path")"
  cp -R "$expected/$path" "$dest/$(dirname "$path")/"
done
echo "copied model classes from $ref; update MODEL_PROVENANCE.md"
