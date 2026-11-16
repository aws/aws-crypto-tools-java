# Native Java MPL: API summary and migration path

Status: draft for planning, 2026-11-16 (API round with reviewer feedback: suite enums, builders, create). Unreviewed: the API can still change after team review.

- **Current API:** the Dafny-based MPL for Java, 1.11.1, package `software.amazon.cryptography.materialproviders`, the `keystore` package, and `primitives`.
- **Native API:** this branch (`mpl-native-java-unverified`), module `mpl/`, not yet published to Maven; packages `software.amazon.cryptography.materialproviders` and `software.amazon.cryptography.keystore`, artifact `aws-cryptographic-material-providers` 2.0.0; Java 8, no Dafny runtime.
- **Conventions:** the API follows the AWS SDK for Java v2 (request and response objects, `builder()`/`toBuilder()`, `name()` accessors with no `get` prefix), except that absent values are `Optional` and secrets are `SecretBytes`.
- **Details:** the javadoc in `mpl/src/main/java/software/amazon/cryptography/materialproviders` and `.../keystore`, and the examples in `mpl/src/examples` (ESDK and DB-ESDK usage). The R ids in section 4 refer to the behavior-change register, which is shared separately with the design review.

## 1. What changes and what doesn't

| Changes | Stays the same |
|---|---|
| Same packages as today (`software.amazon.cryptography.materialproviders`, `software.amazon.cryptography.keystore`), shipped as `aws-cryptographic-material-providers` 2.0.0; it replaces the Dafny MPL, not runs beside it | Wire format: EDKs, the canonical encryption context, key store items. Existing data decrypts; nothing is re-encrypted. |
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
| `CreateAwsKmsEcdhKeyring` | `AwsKmsEcdhKeyring.builder()` + `KmsEcdhKeyAgreementScheme` |
| `CreateAwsKmsHierarchicalKeyring` | `AwsKmsHierarchicalKeyring.builder()` |
| `CreateRawAesKeyring` | `RawAesKeyring.builder()` |
| `CreateRawRsaKeyring` | `RawRsaKeyring.builder()` |
| `CreateRawEcdhKeyring` | `RawEcdhKeyring.builder()` + `RawEcdhKeyAgreementScheme` |
| `CreateMultiKeyring` | `MultiKeyring.builder()` |
| `CreateDefaultCryptographicMaterialsManager` | `DefaultCryptographicMaterialsManager.create(keyring)` |
| `CreateRequiredEncryptionContextCMM` | `RequiredEncryptionContextCryptographicMaterialsManager.builder()` |
| `CreateCryptographicMaterialsCache` | `CryptographicMaterialsCache.create(CacheType)` |
| `CreateDefaultClientSupplier` | `ClientSupplier.defaultSupplier()` |
| `GetAlgorithmSuiteInfo` | `EsdkAlgorithmSuite.fromBinaryId(...)` or `DbeAlgorithmSuite.fromBinaryId(...)`; each finds only its own format |
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
| `AlgorithmSuiteId` / `ESDKAlgorithmSuiteId` / `DBEAlgorithmSuiteId` / `AlgorithmSuiteInfo` | `EsdkAlgorithmSuite` and `DbeAlgorithmSuite` enums, same constant names, both implementing the `AlgorithmSuite` interface that materials and CMM requests take; `isSigning()`, `isCommitting()`, `binaryId()`, `format()` |
| `CommitmentPolicy` union, `ESDKCommitmentPolicy`, `DBECommitmentPolicy` | `CommitmentPolicy` interface, `EsdkCommitmentPolicy`, `DbeCommitmentPolicy` |
| `Map<String,String>` encryption context | `EncryptionContext` (immutable `Map<String,String>`) |
| `ByteBuffer` keys and secrets | `byte[]` (copied) and `SecretBytes`; builders that take a `SecretBytes` secret also take a `byte[]`, and the raw AES keyring a JCA `SecretKey` |
| `EncryptedDataKey.builder()` (`ByteBuffer` members) | `EncryptedDataKey.builder().keyProviderId(..).keyProviderInfo(..).ciphertext(..).build()`; `keyProviderIdUtf8(byte[])` for the id as a message stores it |
| `GetEncryptionMaterialsInput.algorithmSuiteId`, `DecryptMaterialsInput.algorithmSuiteId` | `algorithmSuite()` on `GetEncryptionMaterialsRequest` (`Optional`) and `DecryptMaterialsRequest` |
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

The 12 kinds are VALIDATION, INVALID_MATERIALS, ENCRYPTION_CONTEXT_MISMATCH, NO_MATCHING_DATA_KEY, CRYPTOGRAPHIC, ACCESS_DENIED, RESOURCE_NOT_FOUND, THROTTLING, CONFLICT, SERVICE, DISPATCH and INTERNAL.

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

### Async APIs (proposed for a later minor release)

Same pattern as the AWS SDK for Java v2, where `KmsClient` and `KmsAsyncClient` take the same requests and return the same responses, the async one as a `CompletableFuture`, and neither wraps the other. Details, SDK examples, and sources: section 3.2 of the [API doc](https://chorus.aws.dev/doc/hWnwq7qGvcut).

| Sync (v1.0) | Async (added later, same request and response types) |
| --- | --- |
| `Keyring` | `AsyncKeyring`: `CompletableFuture<OnEncryptResponse> onEncrypt(OnEncryptRequest)` |
| `CryptographicMaterialsManager` | `AsyncCryptographicMaterialsManager` |
| `AwsKmsKeyring` (takes `KmsClient`) | `AwsKmsAsyncKeyring` (takes `KmsAsyncClient`) |
| `BranchKeyStore` (takes `DynamoDbClient`, `KmsClient`) | `AsyncBranchKeyStore` (takes `DynamoDbAsyncClient`, `KmsAsyncClient`) |
| `AwsKmsHierarchicalKeyring` | An async hierarchical keyring on `AsyncBranchKeyStore` |
| `BranchKeyIdSupplier` | `AsyncBranchKeyIdSupplier` |
| Raw AES, RSA, ECDH keyrings (no I/O) | Not duplicated; an adapter lifts them into async |
| ESDK 4.0 `EsdkClient` | `EsdkAsyncClient`: `CompletableFuture<EncryptResponse> encrypt(EncryptRequest)` |

```java
// Sync, as in v1.0
Keyring keyring = AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(KmsClient.create()).build();
EncryptResponse encrypted = esdk.encrypt(b -> b.plaintext(data).keyring(keyring));

// Async, same requests and responses
AsyncKeyring asyncKeyring = AwsKmsAsyncKeyring.builder().kmsKeyId(keyArn).kmsClient(KmsAsyncClient.create()).build();
CompletableFuture<EncryptResponse> future = esdkAsync.encrypt(b -> b.plaintext(data).keyring(asyncKeyring));
```

The async types are new types beside the sync ones, so they ship in a later minor release without changing the sync API. Names are proposals.

## 3. Migration path

Data does not migrate. Messages and items written with either MPL decrypt with the other.

### ESDK-Java customers

| Phase | What the ESDK ships | What the customer does |
|---|---|---|
| Stay on ESDK 3.x | ESDK 3.x on MPL 1.x, unchanged | Nothing |
| Move to ESDK 4.0 | A new major version on MPL 2.0.0 only (the two MPLs share packages, so they cannot be combined) | Upgrade both together; replace each keyring, CMM, key store and cache construction (one statement per site), rewrite custom keyrings and CMMs against the new interfaces, and update catch blocks |

In the proposed ESDK 4.0 API, ESDK calls throw the ESDK's own `EsdkException` subclasses; an MPL failure is the cause and keeps its kind, so catch blocks switch on `EsdkErrorKind` and use `findCause(...)` for the MPL or AWS SDK exception.

Effort for the ESDK team: about 4–6 weeks for ESDK 4.0, estimated from a prototype that added native overloads to 3.x (5 files).

The prototype's results:
- 2244 of 2244 native/Dafny interop cases pass.
- 7101 raw-key test vectors give identical results on both MPLs.
- The 1988 KMS test vectors give identical pass/fail on both MPLs. 885 of them, the ones on the multi-Region key, could not run with ReadOnly credentials.
- What customers see: the exception classes change. 69 messages also differ because the ESDK still pins Dafny MPL 1.7.0.

### DB-ESDK customers

- **Dafny DB-ESDK:** stays on MPL 1.x. No customer change, but an application on it cannot also use ESDK 4.0 (MPL 2.0.0) in the same build.
- **Native DB-ESDK:** customers build keyrings with the native API in the table config, and use `BranchKeyStore` for beacons.
  - DB-ESDK team effort: about 4 days for the item path; about 3–4 weeks to remove the Dafny MPL fully.
  - The prototype passed 120/120 library tests and 62/62 real-KMS cross-implementation cases.

### Direct MPL users, step by step

1. Upgrade `software.amazon.cryptography:aws-cryptographic-material-providers` to 2.0.0, together with any library built on it (ESDK 4.0). The two versions cannot be combined.
2. Update imports: the packages stay (`software.amazon.cryptography.materialproviders`, `software.amazon.cryptography.keystore`), but `materialproviders.model.*` types move to the `keyrings`, `cmm`, `cache`, and `exceptions` subpackages, and `primitives` is no longer public.
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
7. Pass secrets as `SecretBytes` or `byte[]` (copied; zero your own array), not `ByteBuffer`. A raw AES key can also be a JCA `SecretKey`.
8. Replace `AlgorithmSuiteId` values with `EsdkAlgorithmSuite` or `DbeAlgorithmSuite` constants, and `GetAlgorithmSuiteInfo` with the matching enum's `fromBinaryId`.

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

1. Whether DynamoDB stays a compile dependency.
2. Cache selection shape (`CacheType` versus passing a cache object); request/response objects and `Duration` are already adopted.
3. Spec-versus-Dafny questions C1–C3.
4. Security sign-off for R11.
