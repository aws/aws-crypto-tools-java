# API review: before and after code

This is the code behind the API review of the native MPL 2.0.0. Each change in the review has a before and after
example: before on the Dafny-based MPL 1.11.1, after on the native MPL. Both sides compile, so you can comment on
exact lines. Not for merge.

## How to read it

- One class per section of the review, with the same name on both sides. Compare
  `before/.../Section1_1Keyrings.java` with `after/sync/.../Section1_1Keyrings.java`.
- Each method shows one change. The comment above it names the change, and the code between `// @card` and
  `// @end` is what the review shows. The rest is setup that makes it compile.
- The tables below link each change to its before and after code.

## What is a proposal

- **The ESDK and DB-ESDK calls.** The after side calls the ESDK through the ESDK 4.0 sketch (`EsdkClient`) and the
  DB-ESDK through stand-in classes. Both are in `after/stand-ins`, only so the examples compile; the clients
  throw if built. Review the MPL calls. The ESDK and DB-ESDK shapes are discussed separately.
- **The async API (Part 3).** `after/async-proposal` holds the async spike (`spike`) and the proposed interfaces
  (`proposal`). Nothing in it is part of 2.0.0 yet.

## Layout

| Folder | What it is | Built against |
|---|---|---|
| `before` | Before examples | MPL 1.11.1, ESDK 3.0.2, DB-ESDK 3.3.0 from Maven Central |
| `after/sync` | After examples, Parts 0 to 2 | The native MPL in `../mpl`, and the stand-ins |
| `after/async-proposal` | After examples for Part 3, the async spike, and the proposed interfaces | The native MPL, and the stand-ins |
| `after/stand-ins` | The ESDK 4.0 sketch and the DB-ESDK stand-ins (not for review) | The native MPL |

The before and after sides are separate Gradle builds because the two MPLs are the same artifact in the same
packages.

## Build

From `mpl/`:

```
./gradlew -p ../api-review/before build
./gradlew -p ../api-review/after build
```

Both compile for Java 8 with `-Xlint:all -Werror`, except the stand-ins.

## Changes, by section

### Part 0: What changes, on one page

| Card | Before | After |
|---|---|---|
| 1. Keyrings build themselves | [Part0OnePage.java:41](before/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L41) | [Part0OnePage.java:34](after/sync/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L34) |
| 2. Operations take a request and return a response | [Part0OnePage.java:57](before/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L57) | [Part0OnePage.java:43](after/sync/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L43) |
| 3. The key store is `DynamoDbKeyStore`, behind a `KeyStore` interface | [Part0OnePage.java:77](before/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L77) | [Part0OnePage.java:63](after/sync/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L63) |
| 4. Caches are objects | [Part0OnePage.java:88](before/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L88) | [Part0OnePage.java:74](after/sync/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L74) |
| 5. One suite enum per message format | [Part0OnePage.java:99](before/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L99) | [Part0OnePage.java:85](after/sync/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L85) |
| 6. One exception family | [Part0OnePage.java:119](before/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L119) | [Part0OnePage.java:106](after/sync/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L106) |
| 7. Same artifact, version 2.0.0 | [dependency.xml:11](before/dependency.xml#L11) | [dependency.xml:12](after/dependency.xml#L12) |
| 8. ESDK calls in SDK style (proposal) | [Part0OnePage.java:109](before/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L109) | [Part0OnePage.java:94](after/sync/src/main/java/software/amazon/cryptography/apireview/Part0OnePage.java#L94) |

### 1.1 Keyrings

| Card | Before | After |
|---|---|---|
| Keyrings build themselves | [Section1_1Keyrings.java:40](before/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L40) | [Section1_1Keyrings.java:35](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L35) |
| Key lists take a list or several keys | [Section1_1Keyrings.java:53](before/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L53) | [Section1_1Keyrings.java:49](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L49) |
| Discovery keyrings need a filter that names accounts | [Section1_1Keyrings.java:69](before/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L69) | [Section1_1Keyrings.java:68](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L68) |
| Keys go in as SecretBytes, bytes, or JCA keys | [Section1_1Keyrings.java:85](before/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L85) | [Section1_1Keyrings.java:81](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L81) |
| One builder per ECDH scheme | [Section1_1Keyrings.java:100](before/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L100) | [Section1_1Keyrings.java:96](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L96) |
| The client supplier takes a Region string | [Section1_1Keyrings.java:117](before/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L117) | [Section1_1Keyrings.java:111](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_1Keyrings.java#L111) |

### 1.2 Key store

| Card | Before | After |
|---|---|---|
| DynamoDbKeyStore builds itself | [Section1_2KeyStore.java:33](before/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L33) | [Section1_2KeyStore.java:33](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L33) |
| KMS configuration comes from factories | [Section1_2KeyStore.java:50](before/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L50) | [Section1_2KeyStore.java:49](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L49) |
| Operations take a request, or a lambda | [Section1_2KeyStore.java:67](before/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L67) | [Section1_2KeyStore.java:64](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L64) |
| The key store is an interface you can implement | [Section1_2KeyStore.java:79](before/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L79) | [Section1_2KeyStore.java:76](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L76) |
| branchKeyId everywhere | [Section1_2KeyStore.java:91](before/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L91) | [Section1_2KeyStore.java:115](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_2KeyStore.java#L115) |

### 1.3 Hierarchical keyring and caches

| Card | Before | After |
|---|---|---|
| The hierarchical keyring builds itself | [Section1_3HierarchicalKeyringAndCaches.java:27](before/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L27) | [Section1_3HierarchicalKeyringAndCaches.java:24](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L24) |
| Caches are objects | [Section1_3HierarchicalKeyringAndCaches.java:40](before/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L40) | [Section1_3HierarchicalKeyringAndCaches.java:38](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L38) |
| Share a cache by passing the same object | [Section1_3HierarchicalKeyringAndCaches.java:56](before/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L56) | [Section1_3HierarchicalKeyringAndCaches.java:52](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L52) |
| Storm-tracking times are Durations | [Section1_3HierarchicalKeyringAndCaches.java:72](before/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L72) | [Section1_3HierarchicalKeyringAndCaches.java:66](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L66) |
| The TTL check covers any storm-tracking cache | [Section1_3HierarchicalKeyringAndCaches.java:89](before/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L89) | [Section1_3HierarchicalKeyringAndCaches.java:80](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_3HierarchicalKeyringAndCaches.java#L80) |

### 1.4 CMMs

| Card | Before | After |
|---|---|---|
| The default CMM is created from a keyring | [Section1_4Cmms.java:23](before/src/main/java/software/amazon/cryptography/apireview/Section1_4Cmms.java#L23) | [Section1_4Cmms.java:21](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_4Cmms.java#L21) |
| The required encryption context CMM builds itself | [Section1_4Cmms.java:34](before/src/main/java/software/amazon/cryptography/apireview/Section1_4Cmms.java#L34) | [Section1_4Cmms.java:32](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_4Cmms.java#L32) |
| A CMM goes on the ESDK request | [Section1_4Cmms.java:48](before/src/main/java/software/amazon/cryptography/apireview/Section1_4Cmms.java#L48) | [Section1_4Cmms.java:47](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_4Cmms.java#L47) |

### 1.5 Interfaces you implement

| Card | Before | After |
|---|---|---|
| Keyrings take requests and return responses | [Section1_5InterfacesYouImplement.java:45](before/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L45) | [Section1_5InterfacesYouImplement.java:47](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L47) |
| Materials are immutable | [Section1_5InterfacesYouImplement.java:72](before/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L72) | [Section1_5InterfacesYouImplement.java:74](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L74) |
| CMMs take requests, with the suite as algorithmSuite() | [Section1_5InterfacesYouImplement.java:93](before/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L93) | [Section1_5InterfacesYouImplement.java:92](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L92) |
| A cache miss is an empty entry | [Section1_5InterfacesYouImplement.java:114](before/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L114) | [Section1_5InterfacesYouImplement.java:113](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L113) |
| One-method suppliers take lambdas | [Section1_5InterfacesYouImplement.java:143](before/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L143) | [Section1_5InterfacesYouImplement.java:139](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_5InterfacesYouImplement.java#L139) |

### 1.6 ESDK and DB-ESDK calls (proposal)

| Card | Before | After |
|---|---|---|
| The ESDK takes request objects | [Section1_6EsdkAndDbEsdkCalls.java:31](before/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L31) | [Section1_6EsdkAndDbEsdkCalls.java:29](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L29) |
| The suite and frame length go on the request | [Section1_6EsdkAndDbEsdkCalls.java:45](before/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L45) | [Section1_6EsdkAndDbEsdkCalls.java:45](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L45) |
| Streams in two directions | [Section1_6EsdkAndDbEsdkCalls.java:59](before/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L59) | [Section1_6EsdkAndDbEsdkCalls.java:59](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L59) |
| ESDK calls throw ESDK exceptions | [Section1_6EsdkAndDbEsdkCalls.java:76](before/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L76) | [Section1_6EsdkAndDbEsdkCalls.java:76](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L76) |
| The DB-ESDK table config takes MPL types | [Section1_6EsdkAndDbEsdkCalls.java:91](before/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L91) | [Section1_6EsdkAndDbEsdkCalls.java:94](after/sync/src/main/java/software/amazon/cryptography/apireview/Section1_6EsdkAndDbEsdkCalls.java#L94) |

### 2.1 Errors and exceptions

| Card | Before | After |
|---|---|---|
| One root, with a kind and retryability | [Section2_1Errors.java:29](before/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L29) | [Section2_1Errors.java:27](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L27) |
| AWS failures keep the SDK exception as the cause | [Section2_1Errors.java:49](before/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L49) | [Section2_1Errors.java:47](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L47) |
| "No key decrypted" lists each attempt | [Section2_1Errors.java:63](before/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L63) | [Section2_1Errors.java:65](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L65) |
| Your own code's exceptions pass through | [Section2_1Errors.java:88](before/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L88) | [Section2_1Errors.java:90](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L90) |
| More accessors on the root | [Section2_1Errors.java:104](before/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L104) | [Section2_1Errors.java:103](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_1Errors.java#L103) |

### 2.2 Algorithm suites and commitment policies

| Card | Before | After |
|---|---|---|
| One suite enum per message format | [Section2_2AlgorithmSuites.java:24](before/src/main/java/software/amazon/cryptography/apireview/Section2_2AlgorithmSuites.java#L24) | [Section2_2AlgorithmSuites.java:17](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_2AlgorithmSuites.java#L17) |
| Suite properties are methods, and lookup is per format | [Section2_2AlgorithmSuites.java:39](before/src/main/java/software/amazon/cryptography/apireview/Section2_2AlgorithmSuites.java#L39) | [Section2_2AlgorithmSuites.java:30](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_2AlgorithmSuites.java#L30) |
| Commitment policies answer questions | [Section2_2AlgorithmSuites.java:52](before/src/main/java/software/amazon/cryptography/apireview/Section2_2AlgorithmSuites.java#L52) | [Section2_2AlgorithmSuites.java:41](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_2AlgorithmSuites.java#L41) |

### 2.3 Value types and secrets

| Card | Before | After |
|---|---|---|
| The encryption context is its own type | [Section2_3ValueTypesAndSecrets.java:26](before/src/main/java/software/amazon/cryptography/apireview/Section2_3ValueTypesAndSecrets.java#L26) | [Section2_3ValueTypesAndSecrets.java:24](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_3ValueTypesAndSecrets.java#L24) |
| EncryptedDataKey takes byte arrays | [Section2_3ValueTypesAndSecrets.java:40](before/src/main/java/software/amazon/cryptography/apireview/Section2_3ValueTypesAndSecrets.java#L40) | [Section2_3ValueTypesAndSecrets.java:35](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_3ValueTypesAndSecrets.java#L35) |
| SecretBytes for every secret | [Section2_3ValueTypesAndSecrets.java:55](before/src/main/java/software/amazon/cryptography/apireview/Section2_3ValueTypesAndSecrets.java#L55) | [Section2_3ValueTypesAndSecrets.java:48](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_3ValueTypesAndSecrets.java#L48) |
| Secrets as SecretBytes, or bytes copied at once | [Section2_3ValueTypesAndSecrets.java:69](before/src/main/java/software/amazon/cryptography/apireview/Section2_3ValueTypesAndSecrets.java#L69) | [Section2_3ValueTypesAndSecrets.java:60](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_3ValueTypesAndSecrets.java#L60) |

### 2.4 Conventions

| Card | Before | After |
|---|---|---|
| Requests in, responses out, with builders | [Section2_4Conventions.java:36](before/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L36) | [Section2_4Conventions.java:38](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L38) |
| create, defaultXxx, and of | [Section2_4Conventions.java:49](before/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L49) | [Section2_4Conventions.java:51](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L51) |
| The old member names, with acronyms as words | [Section2_4Conventions.java:64](before/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L64) | [Section2_4Conventions.java:63](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L63) |
| Varargs, Duration, and Optional | [Section2_4Conventions.java:82](before/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L82) | [Section2_4Conventions.java:82](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L82) |
| Closing is optional | [Section2_4Conventions.java:96](before/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L96) | [Section2_4Conventions.java:98](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_4Conventions.java#L98) |

### 2.5 Packages and artifact

| Card | Before | After |
|---|---|---|
| The same artifact, a new major version, no Dafny | [dependency.xml:3](before/dependency.xml#L3) | [dependency.xml:4](after/dependency.xml#L4) |
| One subpackage per area | [Section2_5PackagesAndArtifact.java:41](before/src/main/java/software/amazon/cryptography/apireview/Section2_5PackagesAndArtifact.java#L41) | [Section2_5PackagesAndArtifact.java:31](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_5PackagesAndArtifact.java#L31) |
| No factory client | [Section2_5PackagesAndArtifact.java:24](before/src/main/java/software/amazon/cryptography/apireview/Section2_5PackagesAndArtifact.java#L24) | [Section2_5PackagesAndArtifact.java:20](after/sync/src/main/java/software/amazon/cryptography/apireview/Section2_5PackagesAndArtifact.java#L20) |

### 3.1 Why and how

| Card | Before | After |
|---|---|---|
| Two interfaces, one set of requests and responses | [Section3_1WhyAndHow.java:25](before/src/main/java/software/amazon/cryptography/apireview/Section3_1WhyAndHow.java#L25) | [Section3_1WhyAndHow.java:28](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_1WhyAndHow.java#L28) |
| Twins only for what does I/O | [Section3_1WhyAndHow.java:37](before/src/main/java/software/amazon/cryptography/apireview/Section3_1WhyAndHow.java#L37) | [Section3_1WhyAndHow.java:38](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_1WhyAndHow.java#L38) |
| Neither flavor wraps the other | [Section3_1WhyAndHow.java:49](before/src/main/java/software/amazon/cryptography/apireview/Section3_1WhyAndHow.java#L49) | [Section3_1WhyAndHow.java:53](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_1WhyAndHow.java#L53) |
| The rejected shapes: async only, or one type with both | [Section3_1WhyAndHow.java:62](before/src/main/java/software/amazon/cryptography/apireview/Section3_1WhyAndHow.java#L62) | [Section3_1WhyAndHow.java:68](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_1WhyAndHow.java#L68) |

### 3.2 Async keyrings, CMM, and supplier

| Card | Before | After |
|---|---|---|
| Async interfaces, in the same packages | [Section3_2AsyncKeyrings.java:34](before/src/main/java/software/amazon/cryptography/apireview/Section3_2AsyncKeyrings.java#L34) | [Section3_2AsyncKeyrings.java:31](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_2AsyncKeyrings.java#L31) |
| AwsKmsAsyncKeyring takes KmsAsyncClient | [Section3_2AsyncKeyrings.java:48](before/src/main/java/software/amazon/cryptography/apireview/Section3_2AsyncKeyrings.java#L48) | [Section3_2AsyncKeyrings.java:45](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_2AsyncKeyrings.java#L45) |
| Failures arrive through the future | [Section3_2AsyncKeyrings.java:62](before/src/main/java/software/amazon/cryptography/apireview/Section3_2AsyncKeyrings.java#L62) | [Section3_2AsyncKeyrings.java:55](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_2AsyncKeyrings.java#L55) |
| Explicit adapters lift sync keyrings and CMMs | [Section3_2AsyncKeyrings.java:78](before/src/main/java/software/amazon/cryptography/apireview/Section3_2AsyncKeyrings.java#L78) | [Section3_2AsyncKeyrings.java:71](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_2AsyncKeyrings.java#L71) |

### 3.3 Async key store, hierarchical keyring, and cache waits

| Card | Before | After |
|---|---|---|
| An async key store with the same requests | [Section3_3AsyncKeyStore.java:30](before/src/main/java/software/amazon/cryptography/apireview/Section3_3AsyncKeyStore.java#L30) | [Section3_3AsyncKeyStore.java:32](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_3AsyncKeyStore.java#L32) |
| An async hierarchical keyring | [Section3_3AsyncKeyStore.java:60](before/src/main/java/software/amazon/cryptography/apireview/Section3_3AsyncKeyStore.java#L60) | [Section3_3AsyncKeyStore.java:64](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_3AsyncKeyStore.java#L64) |
| Waiting callers are futures, with the same rules | [Section3_3AsyncKeyStore.java:75](before/src/main/java/software/amazon/cryptography/apireview/Section3_3AsyncKeyStore.java#L75) | [Section3_3AsyncKeyStore.java:80](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_3AsyncKeyStore.java#L80) |
| One cache for both flavors | [Section3_3AsyncKeyStore.java:91](before/src/main/java/software/amazon/cryptography/apireview/Section3_3AsyncKeyStore.java#L91) | [Section3_3AsyncKeyStore.java:93](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_3AsyncKeyStore.java#L93) |

### 3.4 ESDK async

| Card | Before | After |
|---|---|---|
| EsdkAsyncClient takes the same requests | [Section3_4EsdkAsync.java:28](before/src/main/java/software/amazon/cryptography/apireview/Section3_4EsdkAsync.java#L28) | [Section3_4EsdkAsync.java:23](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_4EsdkAsync.java#L23) |
| Async materials go only to the async client | [Section3_4EsdkAsync.java:40](before/src/main/java/software/amazon/cryptography/apireview/Section3_4EsdkAsync.java#L40) | [Section3_4EsdkAsync.java:38](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_4EsdkAsync.java#L38) |
| Where the CPU work runs | [Section3_4EsdkAsync.java:53](before/src/main/java/software/amazon/cryptography/apireview/Section3_4EsdkAsync.java#L53) | [Section3_4EsdkAsyncLater.java:24](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_4EsdkAsyncLater.java#L24) |
| Streaming later, with Reactive Streams | [Section3_4EsdkAsync.java:65](before/src/main/java/software/amazon/cryptography/apireview/Section3_4EsdkAsync.java#L65) | [Section3_4EsdkAsyncLater.java:36](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_4EsdkAsyncLater.java#L36) |

### 3.5 What 2.0.0 must lock now

| Card | Before | After |
|---|---|---|
| Split the I/O from the logic | [KmsDataKeys.java](../mpl/src/main/java/software/amazon/cryptography/materialproviders/internal/KmsDataKeys.java) | [SyncKmsShell.java](after/async-proposal/src/main/java/spike/SyncKmsShell.java) |
| Separate the cache's decision from its wait, and keep the caches final | [StormTracker.java](../mpl/src/main/java/software/amazon/cryptography/materialproviders/internal/cache/StormTracker.java) | [AsyncStormTracker.java](after/async-proposal/src/main/java/spike/AsyncStormTracker.java) |
| Keep requests free of threads, and document the contracts | [OnEncryptRequest.java](../mpl/src/main/java/software/amazon/cryptography/materialproviders/OnEncryptRequest.java) | [Section3_5WhatToLockNow.java:47](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_5WhatToLockNow.java#L47) |
| Reserve the async names, in the same packages | [Section3_5WhatToLockNow.java:26](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_5WhatToLockNow.java#L26) | [Section3_5WhatToLockNow.java:36](after/async-proposal/src/main/java/software/amazon/cryptography/apireview/Section3_5WhatToLockNow.java#L36) |
