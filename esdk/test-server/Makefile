# ============================================================================
# ESDK TestServer integration for the aws-crypto-tools-java Language_Repository
# ----------------------------------------------------------------------------
# This repository (aws-crypto-tools-java) is a Language_Repository: it holds the
# live ESDK Java source (../ , i.e. esdk/) and its tests, and it does NOT embed
# the cross-language TestServer. Instead, per the NextGen multi-repo factoring
# (Requirements 8.2, 8.3, 8.4), it obtains the TestServer by CLONING the
# Commons_Repository fresh at the latest head of a branch on every run, sets the
# clone up, and then invokes the commons orchestrator with THIS repo's working
# tree as the LIVE Java source. The commons servers/java Language_Server then
# runs against the live ESDK Java build instead of the published artifact.
#
# The whole flow is a single target:
#
#   make run                    # clone commons@head + build live ESDK + orchestrate(live=java)
#
# broken into composable pieces you can run individually:
#
#   make clone-commons-at-head  # (8.2/8.3) clone Commons_Repository @ COMMONS_BRANCH head + set up
#   make build-live-esdk        # (11.1)    mvn-install THIS working tree as the live ESDK artifact
#   make orchestrate-live       # (11.1/11.2) run the commons orchestrator with live:java=<this tree>
#   make clean                  # remove the commons clone
#
# ----------------------------------------------------------------------------
# COMMONS COORDINATES — SINGLE SOURCE OF TRUTH (read this before your first run)
# ----------------------------------------------------------------------------
# The Commons_Repository coordinates (name, URL, branch to clone) are the
# Commons_Source_Config and live in ONE place: `commons-source.json` next to
# this Makefile (Requirement 8.2). Both this Makefile and the CI workflow
# (.github/workflows/esdk-test-server.yml) READ that file rather than carrying
# their own hardcoded defaults, so the coordinates never drift between the two.
#
# COMMONS_REPO and COMMONS_BRANCH DEFAULT to the values parsed from that JSON
# (via python3 — no jq dependency), but stay OVERRIDABLE on the command line:
#
#   make run COMMONS_BRANCH=some-branch      # explicit var overrides the JSON
#
# The design specifies cloning at the head of the commons DEFAULT branch with
# NO stored commit pin (Requirement 8.4). The design default for `branch` is
# `main`. HOWEVER, until the ESDK TestServer is merged to commons `main`, the
# TestServer only exists on the feature branch `kessplas/esdk-test-server`, so
# `commons-source.json` currently pins `branch` to that feature branch and the
# flow works out of the box. Once the TestServer merges to commons main, flip
# the `branch` value in commons-source.json back to `main`.
#
# If commons-source.json is missing or unparseable, this Makefile fails fast
# with an error naming the file: it is the single source of truth and its
# absence is a hard error, not a fall-back-to-defaults situation.
#
# NOTE: written for the GNU Make 3.81 that ships with macOS (no .ONESHELL), so
# multi-step recipes run as one script via `bash -c "$$VAR"` or on continued
# lines, mirroring the commons esdk/test-server/Makefile.
# ============================================================================

SHELL := bash

# Absolute directory containing this Makefile (works with `make -C`).
MAKEFILE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# The live ESDK Java working tree is the parent of this test-server directory
# (aws-crypto-tools-java/esdk). This is what we hand to the orchestrator as the
# Live_Source_Code (Requirement 11.2) and what we mvn-install as the live build.
ESDK_SRC_DIR := $(abspath $(MAKEFILE_DIR)/..)

# --- Commons clone configuration (from the Commons_Source_Config) ------------
# commons-source.json is the Commons_Source_Config: the single source of truth
# in this Language_Repository for the Commons_Repository name, URL, and branch
# (Requirement 8.2). We parse it ONCE, at parse time, with python3 — reliably
# present on macOS and ubuntu, so no jq dependency. The python script prints the
# url, branch, and name (one per line); if the file is missing or unparseable it
# prints nothing to stdout (stderr suppressed), which we turn into a hard error.
COMMONS_SOURCE_CONFIG := $(MAKEFILE_DIR)/commons-source.json
_COMMONS_COORDS := $(shell python3 -c 'import json; c=json.load(open("$(COMMONS_SOURCE_CONFIG)"))["commonsRepository"]; print(c["url"]); print(c["branch"]); print(c["name"])' 2>/dev/null)

ifeq ($(strip $(_COMMONS_COORDS)),)
$(error Cannot read the Commons_Source_Config at $(COMMONS_SOURCE_CONFIG). \
It is the single source of truth for the Commons_Repository name/URL/branch; \
ensure the file exists and is valid JSON with a .commonsRepository object \
containing "url", "branch", and "name" (python3 is required to parse it))
endif

# Split the three whitespace-separated coordinates (git URLs/branches/names
# never contain spaces) into the DEFAULT values for the overridable vars.
COMMONS_REPO_DEFAULT   := $(word 1,$(_COMMONS_COORDS))
COMMONS_BRANCH_DEFAULT := $(word 2,$(_COMMONS_COORDS))
COMMONS_NAME           := $(word 3,$(_COMMONS_COORDS))

# The Commons_Repository holding the shared TestServer (model, Tests,
# Configuration_Set, servers, orchestrator). The DEFAULTs come from
# commons-source.json above; both stay overridable on the command line so the
# failure-path integration test can point at a bogus repo, and so local
# verification can use a file:// path or a fork (`?=` yields to command-line vars).
COMMONS_REPO   ?= $(COMMONS_REPO_DEFAULT)
COMMONS_BRANCH ?= $(COMMONS_BRANCH_DEFAULT)
# Where the fresh clone lands. Kept under a scratch dir ignored by .gitignore so
# the clone is never committed back into this Language_Repository.
CLONE_DIR      ?= $(MAKEFILE_DIR)/.commons-clone
# Path to the ESDK TestServer inside the clone.
COMMONS_TS_DIR := $(CLONE_DIR)/esdk/test-server

# --- Live ESDK artifact coordinates -----------------------------------------
# We install the live working tree to the local Maven repository under a
# DISTINCT, unambiguous version so the commons servers/java build provably
# consumes THIS live build (via mavenLocal) rather than the published GA
# artifact. The commons build honors `-PesdkVersion=<v>` + mavenLocal().
ESDK_GROUP        := com.amazonaws
ESDK_ARTIFACT     := aws-encryption-sdk-java
ESDK_LIVE_VERSION ?= 3.0.2-LIVE-SNAPSHOT

# --- JDK resolution ----------------------------------------------------------
# There is a JDK SPLIT here (documented so nobody trips on it):
#   * The commons harness (smithy-java client/server + orchestrator) requires
#     JDK 21+  -> HARNESS_JAVA_HOME.
#   * The live ESDK Java build targets Java 8 (esdk/pom.xml source/target 1.8)
#     and builds fine on JDK 8/11/17 -> ESDK_JAVA_HOME.
# Both are resolved independently; override either on the command line.
#
# HARNESS_JAVA_HOME: honor caller, else try macOS java_home for 23/22/21 and
# require major >= 21, else the known Homebrew JDK 23.
# NOTE: the version is parsed from the line CONTAINING "version" (grep), not
# `head -1`, because a JAVA_TOOL_OPTIONS notice is often printed to stderr before
# the version line and would otherwise be mis-parsed as an empty major version.
HARNESS_JAVA_HOME ?= $(shell for c in "$$(/usr/libexec/java_home -v 23 2>/dev/null)" "$$(/usr/libexec/java_home -v 22 2>/dev/null)" "$$(/usr/libexec/java_home -v 21 2>/dev/null)" "/opt/homebrew/Cellar/openjdk/23.0.2/libexec/openjdk.jdk/Contents/Home"; do if [ -n "$$c" ] && [ -x "$$c/bin/java" ]; then v=$$("$$c/bin/java" -version 2>&1 | grep -i version | head -1 | sed -E 's/.*version .?([0-9]+).*/\1/'); if [ -n "$$v" ] && [ "$$v" -ge 21 ] 2>/dev/null; then echo "$$c"; break; fi; fi; done)

# ESDK_JAVA_HOME: honor caller, else try java_home for 17/11/8 (any works for
# source/target 1.8), else leave empty (mvn on PATH is then used as-is).
ESDK_JAVA_HOME ?= $(shell for c in "$$(/usr/libexec/java_home -v 17 2>/dev/null)" "$$(/usr/libexec/java_home -v 11 2>/dev/null)" "$$(/usr/libexec/java_home -v 1.8 2>/dev/null)"; do if [ -n "$$c" ] && [ -x "$$c/bin/java" ]; then echo "$$c"; break; fi; done)

.DEFAULT_GOAL := help

.PHONY: help clone-commons-at-head build-live-esdk orchestrate-live run \
        check-harness-java clean clean-live-esdk it

# ----------------------------------------------------------------------------
help: ## Show this help
	@echo "ESDK TestServer — aws-crypto-tools-java Language_Repository targets"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' "$(lastword $(MAKEFILE_LIST))" \
		| sort \
		| awk 'BEGIN{FS=":.*## "}{printf "  %-24s %s\n", $$1, $$2}'
	@echo ""
	@echo "Commons coordinates (single source of truth: commons-source.json):"
	@echo "  COMMONS_SOURCE_CONFIG=$(COMMONS_SOURCE_CONFIG)"
	@echo "  COMMONS_NAME=$(COMMONS_NAME)   (from commons-source.json)"
	@echo "  COMMONS_REPO=$(COMMONS_REPO)   (default from commons-source.json; overridable)"
	@echo "  COMMONS_BRANCH=$(COMMONS_BRANCH)   (default from commons-source.json; overridable)"
	@echo "      design default is 'main'; currently 'kessplas/esdk-test-server' until the"
	@echo "      TestServer merges to commons main — then flip branch back to 'main' in the JSON"
	@echo ""
	@echo "Key variables:"
	@echo "  CLONE_DIR=$(CLONE_DIR)"
	@echo "  ESDK_SRC_DIR=$(ESDK_SRC_DIR)"
	@echo "  ESDK_LIVE_VERSION=$(ESDK_LIVE_VERSION)"
	@echo "  HARNESS_JAVA_HOME=$(if $(strip $(HARNESS_JAVA_HOME)),$(HARNESS_JAVA_HOME),<unresolved — set a JDK 21+>)"
	@echo "  ESDK_JAVA_HOME=$(if $(strip $(ESDK_JAVA_HOME)),$(ESDK_JAVA_HOME),<PATH default>)"

# ----------------------------------------------------------------------------
check-harness-java: ## Verify a JDK 21+ is resolved for the commons harness
	@if [ -z "$(strip $(HARNESS_JAVA_HOME))" ]; then \
		echo "ERROR: could not resolve a JDK 21+ for the commons harness (smithy-java needs 21+)." >&2; \
		echo "       Set one explicitly, e.g.:  make HARNESS_JAVA_HOME=/path/to/jdk21 <target>" >&2; \
		exit 1; \
	fi
	@echo "==> Harness JAVA_HOME=$(HARNESS_JAVA_HOME)"

# ----------------------------------------------------------------------------
# 8.2 / 8.3 / 8.4: clone the Commons_Repository fresh at the latest head of
# COMMONS_BRANCH (no stored pin) and set it up. A fresh clone each run keeps the
# TestServer reference from drifting. On clone OR setup failure this recipe
# exits non-zero WITHOUT proceeding (so no Tests can run) — Requirement 8.5, and
# the failure-path integration test asserts exactly this.
clone-commons-at-head: ## (8.2/8.3) Clone Commons_Repository @ COMMONS_BRANCH head and set it up
	@set -eo pipefail; \
	echo "==> Cloning commons at head of '$(COMMONS_BRANCH)'"; \
	echo "    repo:   $(COMMONS_REPO)"; \
	echo "    branch: $(COMMONS_BRANCH)"; \
	echo "    into:   $(CLONE_DIR)"; \
	rm -rf "$(CLONE_DIR)"; \
	if ! git clone --depth 1 --single-branch --branch "$(COMMONS_BRANCH)" "$(COMMONS_REPO)" "$(CLONE_DIR)"; then \
		echo "ERROR: failed to clone the Commons_Repository ($(COMMONS_REPO)@$(COMMONS_BRANCH))." >&2; \
		echo "       Halting: no Tests will run (Requirement 8.5)." >&2; \
		exit 1; \
	fi; \
	echo "==> Setting up the commons clone"; \
	if [ ! -d "$(COMMONS_TS_DIR)" ] || [ ! -f "$(COMMONS_TS_DIR)/Makefile" ]; then \
		echo "ERROR: cloned Commons_Repository is missing esdk/test-server (setup failed)." >&2; \
		echo "       The branch '$(COMMONS_BRANCH)' may not contain the ESDK TestServer yet." >&2; \
		echo "       Halting: no Tests will run (Requirement 8.5)." >&2; \
		exit 1; \
	fi; \
	if ! make -C "$(COMMONS_TS_DIR)" JAVA_HOME="$(HARNESS_JAVA_HOME)" build; then \
		echo "ERROR: failed to set up (build) the cloned commons TestServer." >&2; \
		echo "       Halting: no Tests will run (Requirement 8.5)." >&2; \
		exit 1; \
	fi; \
	echo "==> Commons clone ready at $(COMMONS_TS_DIR)"

# ----------------------------------------------------------------------------
# 11.1: build THIS repo's live ESDK Java working tree and install it to the
# local Maven repository under ESDK_LIVE_VERSION, so the commons servers/java
# build can consume the LIVE build (via mavenLocal + -PesdkVersion) instead of
# the published GA artifact. Uses versions:set to stamp the distinct version so
# the consumed artifact is provably the live one. Tests/coverage/javadoc are
# skipped: we are producing a build artifact, not gating the ESDK's own suite.
build-live-esdk: ## (11.1) mvn-install THIS working tree as the live ESDK artifact (ESDK_LIVE_VERSION)
	@set -eo pipefail; \
	echo "==> Building live ESDK Java from working tree: $(ESDK_SRC_DIR)"; \
	echo "    installing as $(ESDK_GROUP):$(ESDK_ARTIFACT):$(ESDK_LIVE_VERSION) -> local Maven repo"; \
	MVN_JAVA=""; \
	if [ -n "$(strip $(ESDK_JAVA_HOME))" ]; then MVN_JAVA="-Dmaven.compiler.fork=true"; export JAVA_HOME="$(ESDK_JAVA_HOME)"; echo "    JAVA_HOME=$$JAVA_HOME"; fi; \
	cd "$(ESDK_SRC_DIR)"; \
	if ! mvn -q -DnewVersion=$(ESDK_LIVE_VERSION) versions:set -DgenerateBackupPoms=true; then \
		echo "ERROR: failed to stamp the live version onto the ESDK working tree." >&2; \
		exit 1; \
	fi; \
	rc=0; \
	mvn -q -DskipTests -Dmaven.test.skip=true -Djacoco.skip=true -Dmaven.javadoc.skip=true install || rc=$$?; \
	echo "==> restoring original pom version"; \
	mvn -q versions:revert || true; \
	if [ "$$rc" -ne 0 ]; then \
		echo "ERROR: live ESDK Java build/install failed (rc=$$rc); Live_Source_Code cannot be consumed (Requirement 11.4)." >&2; \
		exit $$rc; \
	fi; \
	echo "==> Live ESDK installed: $(ESDK_GROUP):$(ESDK_ARTIFACT):$(ESDK_LIVE_VERSION)"

# ----------------------------------------------------------------------------
# 11.1 / 11.2: run the commons orchestrator against the launched Java server
# with THIS repo's working tree as the LIVE Java source. `live:java=<path>`
# selects live mode for Java; every Other language resolves to head-of-main
# (Requirement 11.1). `-PesdkVersion` + mavenLocal (added in the commons
# servers/java build) make the Java server consume the live build.
orchestrate-live: check-harness-java ## (11.1/11.2) Run commons orchestrator with live:java=<this working tree>
	@set -eo pipefail; \
	if [ ! -d "$(COMMONS_TS_DIR)/orchestrator" ]; then \
		echo "ERROR: commons clone not found at $(COMMONS_TS_DIR); run 'make clone-commons-at-head' first." >&2; \
		exit 1; \
	fi; \
	echo "==> Orchestrating with LIVE Java source: $(ESDK_SRC_DIR)"; \
	export JAVA_HOME="$(HARNESS_JAVA_HOME)"; \
	echo "    JAVA_HOME=$$JAVA_HOME"; \
	cd "$(COMMONS_TS_DIR)/orchestrator"; \
	./gradlew --console=plain run \
		-PesdkVersion=$(ESDK_LIVE_VERSION) \
		--args="live:java=$(ESDK_SRC_DIR)"

# ----------------------------------------------------------------------------
# 11.1 headline: the full live PR flow, in order. Any step failing aborts the
# whole run (set -e), so a clone/setup failure runs no Tests (Requirement 8.5).
run: clone-commons-at-head build-live-esdk orchestrate-live ## (11.1) Full flow: clone commons@head + build live ESDK + orchestrate(live=java)
	@echo "==> ESDK TestServer live run complete."

# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# 11.3: integration test for the clone/setup failure path (and the live-source
# success path). Network-independent for the failure cases; set SKIP_LIVE_BUILD=1
# to skip the Maven-dependent success case.
it: ## (11.3) Run the clone/setup failure-path integration test
	@bash "$(MAKEFILE_DIR)/tests/clone_setup_failure_it.sh"

# ----------------------------------------------------------------------------
clean-live-esdk: ## Remove the live ESDK artifact from the local Maven repo
	@echo "==> Removing $(ESDK_LIVE_VERSION) from local Maven repo"
	@rm -rf "$$HOME/.m2/repository/com/amazonaws/$(ESDK_ARTIFACT)/$(ESDK_LIVE_VERSION)" || true

clean: clean-live-esdk ## Remove the commons clone and the live ESDK artifact
	@echo "==> Removing commons clone ($(CLONE_DIR))"
	@rm -rf "$(CLONE_DIR)"
