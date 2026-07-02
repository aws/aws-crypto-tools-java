#!/usr/bin/env bash
# ============================================================================
# Integration test — ESDK TestServer clone/setup failure path (task 11.3)
# ----------------------------------------------------------------------------
# Asserts the behavior the design and Requirement 8.5 mandate for the
# aws-crypto-tools-java Language_Repository wiring:
#
#   * When cloning OR setting up the Commons_Repository fails, the run HALTS
#     (non-zero exit), runs NO Tests, and reports a failure that IDENTIFIES the
#     setup failure (Requirement 8.5).
#   * The success path consumes THIS repo's working tree as the LIVE ESDK Java
#     source, i.e. builds + installs it as a distinct local Maven artifact that
#     the commons servers/java build then consumes in live mode (Req 8.4, 11.2).
#
# The two FAILURE cases are network-independent and deterministic:
#   A. clone failure  -> point COMMONS_REPO at a non-existent local file:// repo.
#   B. setup failure  -> clone a real (local) repo that LACKS esdk/test-server.
# The SUCCESS case (C) builds the live working tree; it needs Maven deps (cached
# in CI) and the test-vectors stub the CI workflow installs.
#
# Usage:  bash tests/clone_setup_failure_it.sh
#         SKIP_LIVE_BUILD=1 bash tests/clone_setup_failure_it.sh   # skip case C
# Exit code is non-zero if any assertion fails.
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$(cd "$HERE/.." && pwd)"          # aws-crypto-tools-java/esdk/test-server
MAKE=(make -C "$TS_DIR")

pass=0
fail=0
ok()  { echo "  PASS: $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL: $1"; fail=$((fail + 1)); }

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# ----------------------------------------------------------------------------
# Test A: a clone failure halts the run, runs no Tests, and names the failure.
# ----------------------------------------------------------------------------
echo "== Test A: clone failure halts the run (Req 8.5) =="
logA="$scratch/a.log"
cloneA="$scratch/cloneA"
if "${MAKE[@]}" clone-commons-at-head \
      COMMONS_REPO="file:///nonexistent/does-not-exist-$$-.git" \
      COMMONS_BRANCH="main" \
      CLONE_DIR="$cloneA" >"$logA" 2>&1; then
  bad "expected a non-zero exit when the clone fails"
else
  ok "run halted with a non-zero exit"
fi
if grep -qi "failed to clone" "$logA"; then
  ok "failure output identifies the clone failure"
else
  bad "failure output does not identify the clone failure"
fi
if [ ! -d "$cloneA" ] || ! find "$cloneA" -path '*build/test-results*' 2>/dev/null | grep -q .; then
  ok "no Tests were run (no test-results produced)"
else
  bad "test results were produced despite a clone failure"
fi

# ----------------------------------------------------------------------------
# Test B: clone succeeds but the repo lacks esdk/test-server -> setup failure
# halts the run, runs no Tests, and names the setup failure.
# ----------------------------------------------------------------------------
echo "== Test B: setup failure (missing esdk/test-server) halts the run (Req 8.5) =="
fakeRepo="$scratch/fake-commons"
git init -q -b main "$fakeRepo"
echo "this repo is intentionally NOT a valid commons checkout" > "$fakeRepo/README.md"
git -C "$fakeRepo" add -A
git -C "$fakeRepo" -c user.email=it@example.com -c user.name="esdk-it" commit -qm "init"
logB="$scratch/b.log"
cloneB="$scratch/cloneB"
if "${MAKE[@]}" clone-commons-at-head \
      COMMONS_REPO="file://$fakeRepo" \
      COMMONS_BRANCH="main" \
      CLONE_DIR="$cloneB" >"$logB" 2>&1; then
  bad "expected a non-zero exit when setup fails"
else
  ok "run halted with a non-zero exit"
fi
if grep -qiE "missing esdk/test-server|setup failed|Halting: no Tests will run" "$logB"; then
  ok "failure output identifies the setup failure"
else
  bad "failure output does not identify the setup failure"
fi
if ! find "$cloneB" -path '*build/test-results*' 2>/dev/null | grep -q .; then
  ok "no Tests were run (no test-results produced)"
else
  bad "test results were produced despite a setup failure"
fi

# ----------------------------------------------------------------------------
# Test C: the success path consumes the working tree as LIVE source, i.e. it
# builds + installs the live ESDK Java artifact under a distinct version.
# ----------------------------------------------------------------------------
if [ "${SKIP_LIVE_BUILD:-0}" = "1" ]; then
  echo "== Test C: skipped (SKIP_LIVE_BUILD=1) =="
else
  echo "== Test C: success path consumes the working tree as live source (Req 11.2) =="
  itVersion="0.0.0-IT-$$"
  logC="$scratch/c.log"
  "${MAKE[@]}" build-live-esdk ESDK_LIVE_VERSION="$itVersion" >"$logC" 2>&1
  rcC=$?
  artifact="$HOME/.m2/repository/com/amazonaws/aws-encryption-sdk-java/$itVersion/aws-encryption-sdk-java-$itVersion.jar"
  if [ "$rcC" -eq 0 ] && [ -f "$artifact" ]; then
    ok "live ESDK working tree built + installed as $itVersion"
  else
    bad "live build did not install the artifact (rc=$rcC); see $logC"
    tail -n 15 "$logC" | sed 's/^/      /'
  fi
  # Clean up the throwaway IT artifact so it never leaks into a real run.
  rm -rf "$HOME/.m2/repository/com/amazonaws/aws-encryption-sdk-java/$itVersion"
fi

echo ""
echo "== Summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
