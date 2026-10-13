# B4 — Live Beacon-Key-Store Retrieval (scope)

Grounded against `SearchInfo.dfy` (`KeySource`/`getKeyMap`/`getKeysCache`/`getKeyMaterials`/
`getAllKeys`) and MPL `CMCs/CacheConstants.dfy`. This is a scope, not an implementation —
it defines what B4 builds, what is offline-testable, what is CI-only, and the one
architectural decision that needs a human call before code is written.

## What B4 is

B1 wired the beacon write path with **injected** HMAC keys (a stand-in). B4 replaces the
injection with the real path: obtain beacon HMAC keys from the configured **beacon key
source**, which for the non-literal cases retrieves a branch key from the **MPL key store**
(hitting DynamoDB + KMS) and caches it. The per-standard-name HMAC key **derivation** on
top of the raw beacon key is already native (`BeaconKeyDerivation` = Dafny `getAllKeys`,
spec `BeaconKeyMaterials.md`); B4 is the **retrieval + cache** layer that feeds it.

## Grounded retrieval path

`KeySource.getKeyMap(stdNames, keyId)` dispatches on the key location:

- **`LiteralLoc(keys)`** — return the configured keys directly. No store, no cache, fully
  offline. **This is exactly B1's injected-keys path**; already covered natively.
  (A query keyId must NOT be supplied with a literal store → error.)
- **`SingleLoc(keyId)`** — single-tenant: a fixed branch-key id baked into the config. A
  query keyId must NOT be supplied → error. Calls `getKeysCache(..., keyLoc.keyId, ...)`.
- **`MultiLoc(keyName, deleteKey)`** — multi-tenant: the keyId comes from the query/item
  (the `CompoundBeacon.keyIdFromValue` / `KeyIdFromAttr` path, built in B3). The
  `MaybeKeyId` tri-state drives it:
  - `DontUseKeyId` → error (a multi-store requires a keyId),
  - `ShouldHaveKeyId` → return `ShouldHaveKeys` (a query-planning marker: "a keyId is
    required here but isn't resolved yet" — not an error, not keys),
  - `KeyId(id)` → `getKeysCache(..., id, ...)`.

`getKeysCache`/`getKeyMaterials` (the cache + store body):

1. Build the **cache identifier** (exact byte layout, MPL `CacheConstants.dfy`):
   `RESOURCE_ID_HIERARCHICAL_KEYRING (=[0x02]) + NULL (=[0x00]) +
    SCOPE_ID_SEARCHABLE_ENCRYPTION (=[0x03]) + NULL + partitionIdBytes + NULL +
    logicalKeyStoreNameBytes + NULL + utf8(keyId)`, then **SHA-384** it (via
   `AtomicPrimitives.Digest`). The digest is the cache key.
2. `cache.GetCacheEntry` → if present **and** within TTL (`cacheEntryWithinLimits`:
   `now - creationTime <= cacheTTL`), return the cached `BeaconKey.hmacKeys` (asserting the
   cached `beaconKeyIdentifier == keyId` and material type is `BeaconKey`).
3. Else `store.GetBeaconKey(GetBeaconKeyInput(branchKeyIdentifier := keyId))` — **the MPL
   key-store call** that unwraps the branch key (DynamoDB keystore row + KMS decrypt) →
   `beaconKeyMaterials.beaconKey` (raw key; must be present).
4. `getAllKeys(stdNames, beaconKey)` → derive per-standard-name HMAC keys
   (**already native: `BeaconKeyDerivation`**).
5. `cache.PutCacheEntry` with `expiryTime = now + cacheTTL`, then return the derived keys.

## The MPL boundary (the decision B4 forces)

The store (`AwsCryptographyKeyStoreTypes.IKeyStoreClient`), the cache
(`MP.ICryptographicMaterialsCache`), and `Digest` (`AtomicPrimitives`) are **MPL-owned**.
The ESDK/MPL hard-boundary rule says native implementations **reuse the Dafny-transpiled
MPL** for the materials layer rather than reimplementing keystore/KMS/cache. But the native
dbesdk library is currently **MPL-free at runtime** (MPL/Dafny are `testImplementation`
only). B4 is the first component that genuinely needs the materials layer, so it forces a
choice that is an architectural/dependency-contract decision — **needs a human call before
coding** (grounding rule: don't make an irreversible repo-layout/dependency decision on a
guess):

- **Option A — native key-source seam (recommended, consistent with existing patterns).**
  Define a small native `BeaconKeySource` abstraction in the library:
  - `LiteralBeaconKeySource` (done — the injected keys), and
  - a `KeyStoreBeaconKeySource` that owns the cache-id construction (step 1), the TTL
    check, and the `getAllKeys` derivation (all native/offline), and depends on **two
    narrow seams** it does not implement: a `BeaconKeyRetriever`
    (`keyId -> rawBeaconKey`) and a `BeaconKeyCache` (get/put). The library stays
    MPL-free; an **MPL-backed adapter** (wrapping `IKeyStoreClient` + `ICryptographicMaterialsCache`)
    lives in the test-server/integration layer — the same shape as the existing
    `ItemCryptor` seam and B1's injected keys. Live KMS/DynamoDB is exercised only through
    that adapter.
- **Option B — direct MPL runtime dependency.** Add the transpiled MPL keystore/cache as a
  runtime dependency of the library and call `IKeyStoreClient`/`ICryptographicMaterialsCache`
  directly. Simplest literal parity with Dafny, but breaks the library's current MPL-free
  property and couples the native library to Dafny-generated types.

Recommendation: **Option A** — it preserves the MPL-free library, matches the seam pattern
already in use (`ItemCryptor`, injected search keys), and keeps all the offline-testable
logic (cache-id bytes, TTL, derivation) in the native library where it can be unit-tested
without AWS. The MPL reuse happens in the adapter, honoring the boundary rule without
dragging MPL into the core.

## Already native (reuse, don't rebuild)
- `BeaconKeyDerivation` — the `getAllKeys` per-standard-name HMAC derivation.
- `SearchInfo` injected-keys write path — the `LiteralLoc` case.
- SHA-384 — available via the same JCE path the beacon hashing already uses (no MPL needed
  for the cache-id digest under Option A).

## Build plan (once the boundary decision is made)

**Offline-testable (native library, no AWS):**
1. Cache-identifier construction + SHA-384 — pin the exact byte layout against the Dafny
   constants (`0x02 / 0x00 / 0x03`, partitionId, logicalKeyStoreName, utf8(keyId)). This is
   a concrete, checkable value; a known-input vector test guards it.
2. `getKeyMap` dispatch logic — the LiteralLoc/SingleLoc/MultiLoc + `MaybeKeyId` tri-state
   routing, including the three error/marker cases (`DontUseKeyId` on multi → error,
   `ShouldHaveKeyId` → `ShouldHaveKeys`, keyId-with-literal/single → error).
3. TTL check (`cacheEntryWithinLimits`) and cache get/put sequencing against a fake
   in-memory cache seam.
4. End-to-end key-source → derived HMAC keys using a **fake** retriever returning a fixed
   raw beacon key (so the derivation + cache path is fully exercised offline).

**CI-only (live AWS, dedicated test account — matches the Rust benchmark's keystore setup):**
5. The real `store.GetBeaconKey` against a live DynamoDB keystore + KMS, and the end-to-end
   beacon write/query using retrieved (not injected) keys. Gated behind the orchestrator's
   KMS-credentialed path; cannot run on this host (no KMS creds / SSH-clone of peer servers,
   per the orchestrate run already attempted).

## Open items to resolve during the build
- Exact `MaybeKeyMap` tri-state (`Keys` / `DontUseKeys` / `ShouldHaveKeys`) threading into
  the write vs query dispatch — `DontUseKeys` is the keyless plain-beacon path already
  covered by `getValue(..., null keys)` / `GenerateBeacons2(..., DontUseKeys, ...)`;
  `ShouldHaveKeys` is a query-planning marker. Confirm where each is produced/consumed when
  wiring, not before.
- Cache sharing / TTL-per-source nuance (spec note: a shared cache across sources keeps the
  populating source's TTL) — relevant only if a shared cache seam is exposed; defer until
  the cache seam shape is decided.
- `deleteKey` on `MultiLoc` — confirm its effect on retrieval before porting the multi path.

## Status
Option A chosen and **built at the library level** (native seam + `SearchInfo` integration);
the MPL adapter is grounded and specified below, gated on the test-server beacon-config
wiring slice (so it is not committed as an unused class).

## Option A — built (native library, offline-verified)
- `BeaconKeySource` (sealed) + `LiteralBeaconKeySource` (directly-configured keys) +
  `KeyStoreBeaconKeySource` (cache-id → cache/TTL → `BeaconKeyRetriever` → `BeaconKeyDerivation`
  → cache put). Dispatch tri-states `MaybeKeyId`/`MaybeKeyMap`. Narrow seams the library does
  not implement: `BeaconKeyRetriever` (`keyId -> byte[]`) and `BeaconKeyCache` (get/put).
- `SearchInfo` now holds a `BeaconKeySource` (was an injected `Map`); its write path resolves
  keys via `getKeyMap(DontUse)` (literal/single-tenant). `LiteralBeaconKeySource` is the
  injected-keys path, genuinely used by the transforms tests.
- 6 `BeaconKeySourceTest` cases: literal dispatch + key-id rejection; single-tenant
  derive-then-cache within TTL (retriever called once); single-tenant key-id rejection;
  multi-tenant tri-state dispatch; expired-entry refetch; and the cache identifier pinned to
  the exact SHA-384 byte layout against an independent oracle.

## MPL adapter — grounded, pending the wiring slice
The retriever adapter (wraps MPL `software.amazon.cryptography.keystore.KeyStore`, already
constructed in the test-server's `ItemEncryptorFactory`). Grounded signatures:
`KeyStore.GetBeaconKey(GetBeaconKeyInput) -> GetBeaconKeyOutput`;
`GetBeaconKeyInput.builder().branchKeyIdentifier(String).build()`;
`GetBeaconKeyOutput.beaconKeyMaterials().beaconKey()` returns `java.nio.ByteBuffer`.
Shape (drop into the test-server config package when beacons are wired):
```
final class MplBeaconKeyRetriever implements BeaconKeyRetriever {
    private final KeyStore keyStore;                        // MPL client
    public byte[] getBeaconKey(String keyId) {
        ByteBuffer k = keyStore.GetBeaconKey(
            GetBeaconKeyInput.builder().branchKeyIdentifier(keyId).build())
          .beaconKeyMaterials().beaconKey();
        byte[] out = new byte[k.remaining()];
        k.duplicate().get(out);
        return out;
    }
}
```
A straightforward in-memory `BeaconKeyCache` suffices (TTL is enforced natively in
`KeyStoreBeaconKeySource`); an MPL-CMC-backed cache is only needed for cross-source sharing.

## Wiring — landed (compiles; live verification CI-only)
The test-server transforms path now builds the beacon write path from config:
- `MplBeaconKeyRetriever` (test-server config pkg) wraps the MPL `KeyStore` and implements
  the native `BeaconKeyRetriever`; `InMemoryBeaconKeyCache` implements `BeaconKeyCache`.
- `SearchInfoFactory` translates the modeled `SearchConfig` (single key store) → native
  `BeaconVersion` + `KeyStoreBeaconKeySource(Single(keyId), beaconNames, Context(retriever,
  cache, cacheTtl, randomPartitionId, utf8(logicalKeyStoreName), systemUTC))` → `SearchInfo`.
  Scope: standard beacons over the single key store (the base `searchable-encryption`
  shape). Compound beacons, virtual fields, multiple versions, and the shared-set style fail
  loudly (`UnsupportedOperationException`) rather than mis-handle — they are separate
  features. `partitionId` is a fresh UUID (matching the Dafny no-partitionId fallback).
- `TransformsClientFactory` attaches the `SearchInfo` whenever `config.getSearch() != null`.
- Verified: the native library (175 tests) and the test-server (`compileJava` + `test`) both
  build green; the server resolves the library via `includeBuild` (composite), so it compiles
  against the live seam. End-to-end beacon write/query with retrieved keys still needs the
  live branch-key store (account 370957321024) + orchestrator — CI-only, unverifiable here.

## Status
Option A built and wired end-to-end at the compile level. Remaining: flip
`searchable-encryption` in `feature-config.json` and verify on the KMS-credentialed
orchestrator (CI); extend the wiring to compound/virtual beacons when those write paths are
wired into `SearchInfo`.

## Orchestrator attempt (2026-10-05, empirical)
Flipped `searchable-encryption` to supported and ran `make orchestrate TESTS='*earch*'`
(bounded). Captured results:
- **Config validation passed** — no feature-declaration error; the union still equals the
  catalog. The flip is structurally coherent to the orchestrator.
- **The native server resolved clean** — `library:java-native` / `server:java-native` from
  the `dbesdk-native-java-unverified` working tree, `dirty=true` (overlay picks up the
  uncommitted wiring).
- **Only blocker reached: peer-server SSH clone.** Source materialization `git clone
  git@github.com:aws/aws-database-encryption-sdk-dynamodb.git` (java-v3/rust-v1/net-v4
  reference servers) → `Permission denied (publickey)`. Host has no GitHub SSH key; this is
  a host/network limit, hit at the git step (0.9s) before any server launch, test, or KMS
  credential use. Not searchable-specific, not a code/config fault.
- **Flip reverted** — declaring `searchable-encryption` supported is premature for two real
  reasons beyond the host SSH limit: (1) searchable test vectors use the hierarchical
  keyring / branch-key store, so they also need `aws-kms-hierarchical` declared supported
  (still unsupported); (2) the native write path is standard-beacons-only — compound/virtual/
  multi-version/shared-set fail loud, so those vectors would fail. An honest flip waits on
  the compound/virtual write paths + a KMS-credentialed CI host that can clone the peers.
