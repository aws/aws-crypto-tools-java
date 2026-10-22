# Native Java MPL: API summary and migration path

Status: draft for planning, 2026-10-20 (updated for request/response objects and Duration). Unreviewed: the API can still change after team review.

- **Current API:** the Dafny-based MPL for Java, 1.11.1, package `software.amazon.cryptography.materialproviders`, the `keystore` package, and `primitives`.
- **Native API:** this branch (`mpl-native-java-unverified`), module `mpl/`, not yet published to Maven, package `software.amazon.cryptography.mpl`, Java 8, no Dafny runtime.
- **Conventions:** the API follows the AWS SDK for Java v2 (request and response objects, `builder()`/`toBuilder()`, `name()` accessors with no `get` prefix), except that absent values are `Optional` and secrets are `SecretBytes`.
- **Details:** the javadoc in `mpl/src/main/java/software/amazon/cryptography/mpl` and the examples in `mpl/src/examples` (ESDK and DB-ESDK usage). The R ids in section 4 refer to the behavior-change register, which is shared separately with the design review.

## 1. What changes and what doesn't

| Changes | Stays the same |
|---|---|
| New package `software.amazon.cryptography.mpl`, which can sit on the classpath next to the Dafny MPL | Wire format: EDKs, the canonical encryption context, key store items. Existing data decrypts; nothing is re-encrypted. |
| No `MaterialProviders` factory client and no `*Input`/`*Output` wrappers; every component has `builder()` | Pass/fail for every input (four approved exceptions, sec. 4) |
| Enums for closed sets, immutable values, secrets as `SecretBytes`, `Optional` instead of null | Defaults, KMS and DynamoDB calls, cache behavior |
| One unchecked exception root with `kind()` and `isRetryable()` | Member names and enum constants (only casing changes: `ALG_AES_256_...`, `branchKeyIdentifier`, `ddbTableName`) |

## 2. API names: current vs native

### Entry points

| Current (1.11.1) | Native |
|---|---|
| `MaterialProviders.builder().MaterialProvidersConfig(...).build()` | removed |
| `matProv.CreateAwsKmsKeyring(CreateAwsKmsKeyringInput)` | `AwsKmsKeyring.builder()...build()` |
| `CreateAwsKmsMrkKeyring` | `AwsKmsMrkKeyring.builder()` |
| `CreateAwsKmsDiscoveryKeyring` | `AwsKmsDiscoveryKeyring.builder()` |
| `CreateAwsKmsMrkDiscoveryKeyring` | `AwsKmsMrkDiscoveryKeyring.builder()` |
| `CreateAwsKmsMultiKeyring` | `AwsKmsMultiKeyring.builder()` (`AutoCloseable`) |
| `CreateAwsKmsMrkMultiKeyring` | `AwsKmsMrkMultiKeyring.builder()` (`AutoCloseable`) |
| `CreateAwsKmsDiscoveryMultiKeyring` | `AwsKmsDiscoveryMultiKeyring.builder()` (`AutoCloseable`) |
| `CreateAwsKmsMrkDiscoveryMultiKeyring` | `AwsKmsMrkDiscoveryMultiKeyring.builder()` (`AutoCloseable`) |
| `CreateAwsKmsRsaKeyring` | `AwsKmsRsaKeyring.builder()` |
| `CreateAwsKmsEcdhKeyring` | `AwsKmsEcdhKeyring.builder()` + `KmsEcdhStaticConfigurations` |
| `CreateAwsKmsHierarchicalKeyring` | `AwsKmsHierarchicalKeyring.builder()` |
| `CreateRawAesKeyring` | `RawAesKeyring.builder()` |
| `CreateRawRsaKeyring` | `RawRsaKeyring.builder()` |
| `CreateRawEcdhKeyring` | `RawEcdhKeyring.builder()` + `RawEcdhStaticConfigurations` |
| `CreateMultiKeyring` | `MultiKeyring.builder()` |
| `CreateDefaultCryptographicMaterialsManager` | `DefaultCryptographicMaterialsManager.of(keyring)` |
| `CreateRequiredEncryptionContextCMM` | `RequiredEncryptionContextCryptographicMaterialsManager.builder()` |
| `CreateCryptographicMaterialsCache` | `CryptographicMaterialsCache.create(CacheType)` |
| `CreateDefaultClientSupplier` | `ClientSupplier.defaultSupplier()` |
| `GetAlgorithmSuiteInfo` | `AlgorithmSuite.fromBinaryId(...)` |
| `ValidateCommitmentPolicyOnEncrypt` / `OnDecrypt` | `CommitmentPolicy.allowsEncrypt(suite)` / `allowsDecrypt(suite)` |
| `InitializeEncryptionMaterials` / `InitializeDecryptionMaterials` | `EncryptionMaterials.builder(suite)` / `DecryptionMaterials.builder(suite)` |
| `Valid*MaterialsTransition` | `materials.isValidTransitionFrom(start)` |
| `AtomicPrimitives` (24 operations) | internal, not public |

### Key store

| Current | Native |
|---|---|
| `KeyStore.builder().KeyStoreConfig(KeyStoreConfig...)` | `BranchKeyStore.builder()` (same members; `AutoCloseable`) |
| `KMSConfiguration` | `KmsConfiguration.kmsKeyArn(..)`, `kmsMrKeyArn(..)`, `discovery()`, `mrDiscovery(region)` |
| `CreateKeyStore(CreateKeyStoreInput)` | `createKeyStore()` → `CreateKeyStoreResponse.tableArn()` |
| `CreateKey(CreateKeyInput)` | `createKey()` or `createKey(b -> b.branchKeyIdentifier(id).encryptionContext(ec))` → `CreateKeyResponse.branchKeyIdentifier()` |
| `VersionKey`, `GetActiveBranchKey`, `GetBranchKeyVersion`, `GetBeaconKey`, `GetKeyStoreInfo` | `versionKey`, `getActiveBranchKey`, `getBranchKeyVersion`, `getBeaconKey`, `getKeyStoreInfo`, each taking `XRequest` (or `Consumer<XRequest.Builder>`) and returning `XResponse` |

### Interfaces customers implement

| Current | Native |
|---|---|
| `IKeyring`: `OnEncrypt(OnEncryptInput)`, `OnDecrypt(OnDecryptInput)` | `Keyring`: `onEncrypt(OnEncryptRequest)` → `OnEncryptResponse`, `onDecrypt(OnDecryptRequest)` → `OnDecryptResponse` |
| `ICryptographicMaterialsManager` | `CryptographicMaterialsManager`: `getEncryptionMaterials(GetEncryptionMaterialsRequest)` → `GetEncryptionMaterialsResponse`, `decryptMaterials(DecryptMaterialsRequest)` → `DecryptMaterialsResponse` |
| `ICryptographicMaterialsCache` (4 operations) | `CryptographicMaterialsCache`: `getCacheEntry`, `putCacheEntry`, `deleteCacheEntry`, each with request/response (a miss is an empty `entry()`) |
| `IBranchKeyIdSupplier`: `GetBranchKeyId(GetBranchKeyIdInput)` | `BranchKeyIdSupplier`: `GetBranchKeyIdResponse getBranchKeyId(GetBranchKeyIdRequest)` (lambda) |
| `IClientSupplier`: `GetClient(GetClientInput)` | `ClientSupplier`: `KmsClient getClient(String region)` (lambda) |

### Values

| Current | Native |
|---|---|
| `AlgorithmSuiteId` / `ESDKAlgorithmSuiteId` / `DBEAlgorithmSuiteId` / `AlgorithmSuiteInfo` | One enum, `AlgorithmSuite`, same constant names; `isSigning()`, `isCommitting()`, `binaryId()`, `format()` |
| `CommitmentPolicy` union, `ESDKCommitmentPolicy`, `DBECommitmentPolicy` | `CommitmentPolicy` interface, `EsdkCommitmentPolicy`, `DbeCommitmentPolicy` |
| `Map<String,String>` encryption context | `EncryptionContext` (immutable `Map<String,String>`) |
| `ByteBuffer` keys and secrets | `byte[]` (copied) and `SecretBytes` |
| `CacheType` union (`Default`, `No`, `SingleThreaded`, `MultiThreaded`, `StormTracking`, `Shared`) | `CacheType.defaultCache(n)`, `noCache()`, `singleThreaded(..)`, `multiThreaded(..)`, `stormTracking(..)`, `shared(cache)` |
| `ttlSeconds(long)`, storm-tracking `int` times + `TimeUnits` | `java.time.Duration`: `ttl(Duration)`; `gracePeriod`, `graceInterval`, `inFlightTtl`, `sleep`; `TimeUnits` removed |

### Exceptions

| Current | Native (all extend `MaterialProvidersException`) |
|---|---|
| `AwsCryptographicMaterialProvidersException` | The subclass for the failure's kind, for example `ValidationException` |
| `CollectionOfErrors` | `NoMatchingDataKeyException` (`failures()` lists each attempt) |
| `InvalidEncryptionMaterials`, `InvalidDecryptionMaterials`, `*Transition` | `InvalidMaterialsException` |
| `InFlightTTLExceeded` | `ThrottlingException` (retryable) |
| `EntryDoesNotExist` | empty `GetCacheEntryResponse.entry()` |
| `KeyStoreException` | The subclass for the failure's kind |
| `OpaqueError` | Removed: exceptions thrown by customer code pass through unchanged |
| `KmsException` / `DynamoDbException` rethrown as-is | `AccessDeniedException`, `ThrottlingException`, `ResourceNotFoundException`, `ServiceException` or `DispatchException`, with the SDK exception as cause (`findCause(KmsException.class)`) |

The 12 kinds are VALIDATION, INVALID_MATERIALS, ENCRYPTION_CONTEXT_MISMATCH, NO_MATCHING_DATA_KEY, CRYPTOGRAPHIC, ACCESS_DENIED, RESOURCE_NOT_FOUND, THROTTLING, CONFLICT, SERVICE, DISPATCH and INTERNAL, the same as the native Rust MPL's development line.

### Before and after

```java
// Current
MaterialProviders mpl = MaterialProviders.builder()
    .MaterialProvidersConfig(MaterialProvidersConfig.builder().build()).build();
IKeyring keyring = mpl.CreateAwsKmsMultiKeyring(
    CreateAwsKmsMultiKeyringInput.builder().generator(keyArn).build());

// Native
AwsKmsMultiKeyring keyring = AwsKmsMultiKeyring.builder().generator(keyArn).build();

crypto.encryptData(keyring, data, encryptionContext);   // ESDK call unchanged
```

## 3. Migration path

Data does not migrate. Messages and items written with either MPL decrypt with the other.

### ESDK-Java customers

| Phase | What the ESDK ships | What the customer does |
|---|---|---|
| 1. ESDK 3.x minor (recommended first) | `AwsCrypto` overloads that take a native `Keyring` or `CryptographicMaterialsManager`. The Dafny-MPL overloads stay. | Nothing, to stay where they are. To adopt: change the imports, replace each keyring, CMM, key store and cache construction (one statement per site), and update catch blocks. |
| 2. ESDK 4.0 (later) | Native MPL only; the Dafny MPL dependency is dropped | Required: everything in phase 1, plus rewriting custom keyrings and CMMs against the new interfaces |

Effort for the ESDK team, measured on a prototype:
- **Phase 1:** about 2–3 weeks after the native MPL is on Maven Central. The prototype changed 5 files.
- **Phase 2:** about 4–6 weeks.

The prototype's results:
- 2244 of 2244 native/Dafny interop cases pass.
- 7101 raw-key test vectors give identical results on both MPLs.
- The 1988 KMS test vectors give identical pass/fail on both MPLs. 885 of them, the ones on the multi-Region key, could not run with ReadOnly credentials.
- What customers see: the exception classes change. 69 messages also differ because the ESDK still pins Dafny MPL 1.7.0.

### DB-ESDK customers

- **Dafny DB-ESDK:** stays on the Dafny MPL. No customer change.
- **Native DB-ESDK:** customers build keyrings with the native API in the table config, and use `BranchKeyStore` for beacons.
  - DB-ESDK team effort: about 4 days for the item path; about 3–4 weeks to remove the Dafny MPL fully.
  - The prototype passed 120/120 library tests and 62/62 real-KMS cross-implementation cases.

### Direct MPL users, step by step

1. Add the native MPL dependency (Maven coordinates are still open). The Dafny MPL can stay alongside it during the move.
2. Change imports from `software.amazon.cryptography.materialproviders.*` and `...keystore.*` to `software.amazon.cryptography.mpl.*`.
3. Replace `matProv.CreateX(CreateXInput.builder()...build())` with `X.builder()...build()`, using the member names from the tables above.
4. Turn `IBranchKeyIdSupplier` and `IClientSupplier` classes into lambdas, e.g. `req -> GetBranchKeyIdResponse.builder().branchKeyId(pick(req.encryptionContext())).build()`.
5. Port custom `IKeyring` and `ICryptographicMaterialsManager` implementations:
   - change the method names to lower case;
   - return `OnEncryptResponse.builder().materials(materials).build()` / `OnDecryptResponse.builder().materials(materials).build()` (CMMs: the matching `...Response.builder()`);
   - use `materials.with...` instead of mutating the materials.
6. Update exception handling:
   - catch `MaterialProvidersException`, or a specific subclass;
   - for SDK errors, use `findCause(KmsException.class)` instead of `catch (KmsException e)`;
   - use `isRetryable()` for retry decisions.
7. Pass secrets as `SecretBytes`, not `ByteBuffer`.

## 4. Behavior differences to know before migrating

| Id | Difference | Status |
|---|---|---|
| R31 | `DiscoveryFilter.of` rejects an empty account list or partition | Breaking, proposed (pending team review) |
| R22 | No global BouncyCastle provider registration | Breaking, proposed (pending team review) |
| R11 | ECDH rejects a public key with x = 0 | Breaking, needs security sign-off |
| R46 | Hierarchical keyring rejects a zero `ttl` (the spec requires it) | Breaking, proposed (pending team review) |
| R9, R10 | Discovery filter matching fixed; some decryptions that failed now succeed | Non-breaking |
| R3, R4 | Cache miss is an empty response, not an exception; cache usage counters removed | API shape only |

## 5. Open before release

1. Maven artifact name.
2. Whether DynamoDB stays a compile dependency.
3. Cache selection shape (`CacheType` versus passing a cache object, as the native Rust MPL does); request/response objects and `Duration` are already adopted.
4. Three spec-versus-Dafny questions for the MPL owners: raw AES namespaces starting with `aws-kms`, the default suite under `FORBID_ENCRYPT_ALLOW_DECRYPT`, and verification key length checks.
5. Security sign-off for R11.
