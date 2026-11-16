// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import software.amazon.cryptography.keystore.BranchKeyMaterials;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.cache.CacheEntry;
import software.amazon.cryptography.materialproviders.cache.CacheKey;
import software.amazon.cryptography.materialproviders.cache.CacheType;
import software.amazon.cryptography.materialproviders.cache.CryptographicMaterialsCache;
import software.amazon.cryptography.materialproviders.cache.GetCacheEntryRequest;
import software.amazon.cryptography.materialproviders.cache.PutCacheEntryRequest;
import software.amazon.cryptography.materialproviders.exceptions.CryptographicException;
import software.amazon.cryptography.materialproviders.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.CanonicalEncryptionContext;
import software.amazon.cryptography.materialproviders.internal.EdkWrapping;
import software.amazon.cryptography.materialproviders.internal.KeyringNames;
import software.amazon.cryptography.materialproviders.internal.MaterialsAccess;
import software.amazon.cryptography.materialproviders.internal.MaterialsRules;
import software.amazon.cryptography.materialproviders.internal.Utf8;
import software.amazon.cryptography.materialproviders.internal.cache.BuiltInCache;
import software.amazon.cryptography.materialproviders.internal.cache.CacheClock;
import software.amazon.cryptography.materialproviders.internal.cache.CacheSpec;
import software.amazon.cryptography.materialproviders.internal.cache.Caches;
import software.amazon.cryptography.materialproviders.internal.cache.StormSettings;
import software.amazon.cryptography.materialproviders.internal.primitives.AesGcm;
import software.amazon.cryptography.materialproviders.internal.primitives.Bytes;
import software.amazon.cryptography.materialproviders.internal.primitives.DigestAlgorithm;
import software.amazon.cryptography.materialproviders.internal.primitives.Digests;
import software.amazon.cryptography.materialproviders.internal.primitives.KdfCounterMode;
import software.amazon.cryptography.materialproviders.internal.primitives.Randoms;

/**
 * Wraps data keys with branch keys from a branch key store, caching branch keys so most operations make no KMS call.
 * Thread-safe when its cache is: not with {@link CacheType#singleThreaded}, nor with a shared cache that is not thread-safe.
 *
 * <p>Each encrypted data key has provider id {@code aws-kms-hierarchy}, provider info = the branch key id as UTF-8,
 * and ciphertext = {@code salt (16) || IV (12) || branch key version as a 16-byte UUID || AES-GCM ciphertext || tag (16)}.
 * The AES key is derived from the branch key and the salt (NIST SP 800-108 counter mode, HMAC-SHA-256);
 * the AAD is {@code "aws-kms-hierarchy" || branch key id || version bytes || canonical encryption context}.
 *
 * <p>A cached branch key is used while it is at most {@code ttl} old, counted in whole seconds, even when another keyring sharing the cache
 * cached it with a longer TTL.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-hierarchical-keyring.md">AWS KMS hierarchical keyring</a>.
 */
//= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
public final class AwsKmsHierarchicalKeyring implements Keyring {

  private static final String PROVIDER_ID = "aws-kms-hierarchy";
  private static final byte[] PROVIDER_ID_BYTES = PROVIDER_ID.getBytes(StandardCharsets.UTF_8);
  private static final int SALT_LENGTH = 16;
  private static final int IV_LENGTH = 12;
  private static final int VERSION_INDEX = SALT_LENGTH + IV_LENGTH;
  private static final int WRAPPED_KEY_INDEX = VERSION_INDEX + 16;
  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
  //= type=implication
  //# MUST use an authentication tag byte of length 16.
  private static final int TAG_LENGTH = 16;
  private static final int DERIVED_KEY_LENGTH = 32;
  // CacheConstants.dfy: the resource id of this keyring and the scope ids that separate encrypt and decrypt entries.
  private static final byte RESOURCE_ID = 0x02;
  private static final byte SCOPE_ENCRYPT = 0x01;
  private static final byte SCOPE_DECRYPT = 0x02;
  // StormTracker.dfy DefaultStorm: the grace period, in seconds, that a keyring without a configured cache is checked against.
  private static final long DEFAULT_GRACE_PERIOD_SECONDS = 10;
  private static final String ENCODE_FAILURE = "Could not encode input to Dafny Bytes.";

  private final String branchKeyId;
  private final BranchKeyIdSupplier branchKeyIdSupplier;
  private final BranchKeyStore keyStore;
  private final long ttlSeconds;
  private final CacheType cacheType;
  private final String partitionId;
  private final CryptographicMaterialsCache cache;
  private final byte[] partitionIdBytes;
  private final byte[] logicalKeyStoreNameBytes;
  private final CacheClock clock;

  private AwsKmsHierarchicalKeyring(
    Builder builder,
    CryptographicMaterialsCache cache,
    byte[] partitionIdBytes,
    byte[] logicalKeyStoreNameBytes
  ) {
    this.branchKeyId = builder.branchKeyId;
    this.branchKeyIdSupplier = builder.branchKeyIdSupplier;
    this.keyStore = builder.keyStore;
    this.ttlSeconds = builder.ttl.getSeconds();
    this.cacheType = builder.cache;
    this.partitionId = builder.partitionId;
    this.cache = cache;
    this.partitionIdBytes = partitionIdBytes;
    this.logicalKeyStoreNameBytes = logicalKeyStoreNameBytes;
    this.clock = builder.clock;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The branch key for every message. Exactly one of this and {@code branchKeyIdSupplier}. */
  public Optional<String> branchKeyId() {
    return Optional.ofNullable(branchKeyId);
  }

  /** Chooses the branch key per message from its encryption context. */
  public Optional<BranchKeyIdSupplier> branchKeyIdSupplier() {
    return Optional.ofNullable(branchKeyIdSupplier);
  }

  /** Where branch keys come from. */
  public BranchKeyStore keyStore() {
    return keyStore;
  }

  /** How long a cached branch key is used: a positive whole number of seconds. See {@link CacheType} for the check against the cache. */
  public Duration ttl() {
    return Duration.ofSeconds(ttlSeconds);
  }

  /** Where branch keys are cached; default {@code CacheType.defaultCache(1000)}. */
  public Optional<CacheType> cache() {
    return Optional.ofNullable(cacheType);
  }

  /** Keyrings sharing a cache share entries only when their partition ids and key stores' logical names are equal; default: a random id, so nothing is shared. */
  public Optional<String> partitionId() {
    return Optional.ofNullable(partitionId);
  }

  @Override
  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=implication
  //# OnEncrypt MUST take [encryption materials]
  //# (../structures.md#encryption-materials) as input.
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    String id = branchKeyIdFor(materials.encryptionContext());
    byte[] idBytes = utf8(id, ENCODE_FAILURE);
    byte[] cacheId = cacheId(SCOPE_ENCRYPT, idBytes, null);
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# the hierarchical keyring MUST attempt to obtain the branch key materials
    //# by querying the backing branch keystore specified in
    //# the [retrieve OnEncrypt branch key materials](#query-branch-keystore-onencrypt) section.
    BranchKeyMaterials branchKey = branchKey(cacheId, () -> keyStore.getActiveBranchKey(b -> b.branchKeyIdentifier(id)).branchKeyMaterials());
    byte[] versionBytes = versionBytes(branchKey);
    EdkWrapping.Wrap<Void> wrap = (plaintext, suite, encryptionContext) ->
      new EdkWrapping.Wrapped<>(wrap(branchKey, idBytes, versionBytes, plaintext, encryptionContext), null);
    EdkWrapping.GenerateAndWrap<Void> generateAndWrap = (suite, encryptionContext) -> {
      byte[] plaintext = Randoms.generate(suite.dataKeyLength());
      try {
        return wrap.wrap(plaintext, suite, encryptionContext).generated(plaintext);
      } catch (RuntimeException e) {
        Bytes.zero(plaintext);
        throw e;
      }
    };
    EdkWrapping.WrapResult<Void> result = EdkWrapping.wrap(materials, wrap, generateAndWrap);
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key)
    //# to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials)
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# [key provider id](../structures.md#key-provider-id): MUST be UTF8 Encoded "aws-kms-hierarchy"
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# [key provider info](../structures.md#key-provider-information): MUST be the UTF8 Encoded AWS DDB response `branch-key-id`
    //
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //# [ciphertext](../structures.md#ciphertext): MUST be serialized as the [hierarchical keyring ciphertext](#ciphertext)
    return OnEncryptResponse.builder().materials(result.addTo(materials, EncryptedDataKey.builder()
        .keyProviderId(PROVIDER_ID)
        .keyProviderInfo(idBytes)
        .ciphertext(result.wrappedMaterial)
        .build())).build();
  }

  @Override
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    MaterialsRules.Decryption fields = MaterialsAccess.fields(materials);
    if (fields.plaintextDataKey != null || !MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Keyring received decryption materials that already contain a plaintext data key.");
    }
    String id = branchKeyIdFor(materials.encryptionContext());
    // Every key is filtered before any is tried; a provider info that is not UTF-8 fails the whole call.
    List<EncryptedDataKey> matching = new ArrayList<>();
    for (EncryptedDataKey edk : encryptedDataKeys) {
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
      //# - Its provider ID MUST match the UTF8 Encoded value of “aws-kms-hierarchy”.
      //
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
      //# -- The deserialized key provider info MUST be UTF8 Decoded
      //
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
      //#  MUST match this keyring's configured `Branch Key Identifier`.
      if (edk.keyProviderId().equals(PROVIDER_ID) && decodeProviderInfo(edk.keyProviderInfo()).equals(id)) {
        matching.add(edk);
      }
    }
    if (matching.isEmpty()) {
      throw new NoMatchingDataKeyException(KeyringNames.incorrectDataKeys(encryptedDataKeys, fields.suite), new ArrayList<>());
    }
    List<Throwable> errors = new ArrayList<>();
    for (EncryptedDataKey edk : matching) {
      try {
        return OnDecryptResponse.builder().materials(decrypt(materials, fields.suite, id, edk)).build();
      } catch (RuntimeException e) {
        errors.add(e);
      }
    }
    //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
    //# If OnDecrypt fails to successfully decrypt any [encrypted data key]
    //# (../structures.md#encrypted-data-key), then it MUST yield an error
    //# that includes all the collected errors.
    throw new NoMatchingDataKeyException(
      "No Configured KMS Key was able to decrypt the Data Key. The list of encountered Exceptions is available via `list`.",
      errors
    );
  }

  private DecryptionMaterials decrypt(DecryptionMaterials materials, AlgorithmSuite suite, String id, EncryptedDataKey edk) {
    byte[] wrapped = EdkWrapping.providerWrappedMaterial(edk.ciphertext(), suite);
    if (wrapped.length < WRAPPED_KEY_INDEX) {
      throw new ValidationException("Received EDK Ciphertext of incorrect length.");
    }
    ByteBuffer versionBuffer = ByteBuffer.wrap(wrapped, VERSION_INDEX, WRAPPED_KEY_INDEX - VERSION_INDEX);
    String version = new UUID(versionBuffer.getLong(), versionBuffer.getLong()).toString();
    byte[] idBytes = edk.keyProviderInfo();
    byte[] cacheId = cacheId(SCOPE_DECRYPT, idBytes, version);
    BranchKeyMaterials branchKey = branchKey(
      cacheId,
      () -> keyStore.getBranchKeyVersion(b -> b.branchKeyIdentifier(id).branchKeyVersion(version)).branchKeyMaterials()
    );
    byte[] versionBytes = versionBytes(branchKey);
    EdkWrapping.UnwrapResult<Void> unwrapped = EdkWrapping.unwrap(
      edk.ciphertext(),
      materials,
      (material, unwrapSuite, encryptionContext) ->
        new EdkWrapping.Unwrapped<>(unwrap(branchKey, idBytes, versionBytes, material, unwrapSuite, encryptionContext), null)
    );
    return unwrapped.addTo(materials);
  }

  private String branchKeyIdFor(EncryptionContext encryptionContext) {
    if (branchKeyId != null) {
      return branchKeyId;
    }
    GetBranchKeyIdRequest request = GetBranchKeyIdRequest.builder().encryptionContext(encryptionContext).build();
    GetBranchKeyIdResponse response = branchKeyIdSupplier.getBranchKeyId(request);
    if (response == null) {
      throw new ValidationException("BranchKeyIdSupplier returned no branch key id.");
    }
    return response.branchKeyId();
  }

  // A string that is not well-formed UTF-16 has no UTF-8 encoding and fails with failureMessage.
  private static byte[] utf8(String value, String failureMessage) {
    try {
      return Utf8.encode(value);
    } catch (IllegalArgumentException e) {
      throw new ValidationException(failureMessage);
    }
  }

  // The Dafny runtime's strict UTF-8 decoder.
  private static String decodeProviderInfo(byte[] info) {
    try {
      return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(info)).toString();
    } catch (CharacterCodingException e) {
      throw new ValidationException("Invalid encoding, provider info is not UTF8.");
    }
  }

  // SHA-384 of: resource id, scope id, partition id, logical key store name, branch key id, and on decrypt the version,
  // separated by single 0x00 bytes.
  private byte[] cacheId(byte scope, byte[] idBytes, String version) {
    ByteArrayOutputStream identifier = new ByteArrayOutputStream();
    identifier.write(RESOURCE_ID);
    identifier.write(0);
    identifier.write(scope);
    identifier.write(0);
    identifier.write(partitionIdBytes, 0, partitionIdBytes.length);
    identifier.write(0);
    identifier.write(logicalKeyStoreNameBytes, 0, logicalKeyStoreNameBytes.length);
    identifier.write(0);
    identifier.write(idBytes, 0, idBytes.length);
    if (version != null) {
      byte[] versionBytes = version.getBytes(StandardCharsets.US_ASCII);
      identifier.write(0);
      identifier.write(versionBytes, 0, versionBytes.length);
    }
    return Digests.digest(DigestAlgorithm.SHA_384, identifier.toByteArray());
  }

  private interface KeyStoreRead {
    BranchKeyMaterials read();
  }

  // The cached branch key, unless it is missing or older than this keyring's TTL; then the key store's, cached.
  private BranchKeyMaterials branchKey(byte[] cacheId, KeyStoreRead read) {
    CacheKey key = CacheKey.of(cacheId);
    Optional<CacheEntry> entry = cache.getCacheEntry(GetCacheEntryRequest.builder().key(key).build()).entry();
    // now - creation <= ttlSeconds, without overflow: now and ttlSeconds are not negative.
    if (entry.isPresent() && entry.get().creationTime().getEpochSecond() >= nowSeconds() - ttlSeconds) {
      return entry.get().branchKeyMaterials().orElseThrow(() -> new InvalidMaterialsException("Invalid Material Type."));
    }
    BranchKeyMaterials materials = read.read();
    long now = nowSeconds();
    // now + ttlSeconds must be below Long.MAX_VALUE, as in Dafny; written as a difference, which cannot overflow.
    if (ttlSeconds >= Long.MAX_VALUE - now) {
      throw new ValidationException("INT64 Overflow when putting cache entry.");
    }
    CacheEntry fresh = CacheEntry.of(materials, Instant.ofEpochSecond(now), expiry(now + ttlSeconds));
    cache.putCacheEntry(PutCacheEntryRequest.builder().key(key).entry(fresh).build());
    return materials;
  }

  private long nowSeconds() {
    return clock.wallMillis() / 1000;
  }

  // An expiry past Instant.MAX (about a billion years away) is stored as Instant.MAX.
  private static Instant expiry(long epochSecond) {
    return epochSecond > Instant.MAX.getEpochSecond() ? Instant.MAX : Instant.ofEpochSecond(epochSecond);
  }

  private static byte[] versionBytes(BranchKeyMaterials materials) {
    UUID version;
    try {
      version = UUID.fromString(materials.branchKeyVersion());
    } catch (IllegalArgumentException e) {
      throw new InvalidMaterialsException("Could not convert UUID to byte array.", e);
    }
    return ByteBuffer.allocate(16).putLong(version.getMostSignificantBits()).putLong(version.getLeastSignificantBits()).array();
  }

  private static byte[] wrap(
    BranchKeyMaterials branchKey,
    byte[] idBytes,
    byte[] versionBytes,
    byte[] plaintext,
    EncryptionContext encryptionContext
  ) {
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
    //# The hierarchical keyring MUST:
    byte[] saltAndIv = Randoms.generate(SALT_LENGTH + IV_LENGTH);
    byte[] salt = Arrays.copyOfRange(saltAndIv, 0, SALT_LENGTH);
    byte[] iv = Arrays.copyOfRange(saltAndIv, SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad
    //# To Encrypt and Decrypt the `wrappedDerivedBranchKey` the keyring MUST include the following values as part of the AAD for
    //# the AES Encrypt/Decrypt calls.
    byte[] aad = aad(idBytes, versionBytes, encryptionContext);
    byte[] derived = deriveKey(branchKey, salt);
    try {
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
      //# 1. Encrypt a plaintext data key with the `derivedBranchKey` using
      //# `AES-GCM-256` with the following inputs:
      //
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
      //# MUST use the derived `IV` as the AES-GCM IV.
      //
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
      //# MUST use the `derivedBranchKey` as the AES-GCM cipher key.
      //
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
      //# MUST use the plain text data key that will be wrapped by the `derivedBranchKey` as the AES-GCM message.
      //
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
      //# - MUST use the serialized [AAD](#branch-key-wrapping-and-unwrapping-aad) as the AES-GCM AAD.
      byte[][] encrypted = AesGcm.encrypt(TAG_LENGTH, derived, iv, plaintext, aad);
      return ByteBuffer
        .allocate(WRAPPED_KEY_INDEX + encrypted[0].length + encrypted[1].length)
        .put(saltAndIv)
        .put(versionBytes)
        .put(encrypted[0])
        .put(encrypted[1])
        .array();
    } catch (GeneralSecurityException e) {
      throw new CryptographicException(e.getMessage(), e);
    } finally {
      Bytes.zero(derived);
    }
  }

  private static byte[] unwrap(
    BranchKeyMaterials branchKey,
    byte[] idBytes,
    byte[] versionBytes,
    byte[] wrapped,
    AlgorithmSuite suite,
    EncryptionContext encryptionContext
  ) {
    int keyLength = suite.dataKeyLength();
    if (wrapped.length != WRAPPED_KEY_INDEX + keyLength + TAG_LENGTH) {
      throw new ValidationException("Received EDK Ciphertext of incorrect length2.");
    }
    byte[] salt = Arrays.copyOfRange(wrapped, 0, SALT_LENGTH);
    byte[] iv = Arrays.copyOfRange(wrapped, SALT_LENGTH, VERSION_INDEX);
    byte[] wrappedKey = Arrays.copyOfRange(wrapped, WRAPPED_KEY_INDEX, WRAPPED_KEY_INDEX + keyLength);
    byte[] tag = Arrays.copyOfRange(wrapped, WRAPPED_KEY_INDEX + keyLength, wrapped.length);
    byte[] aad = aad(idBytes, versionBytes, encryptionContext);
    byte[] derived = deriveKey(branchKey, salt);
    try {
      return AesGcm.decrypt(TAG_LENGTH, derived, iv, wrappedKey, tag, aad);
    } catch (GeneralSecurityException e) {
      throw new CryptographicException(e.getMessage(), e);
    } finally {
      Bytes.zero(derived);
    }
  }

  //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad
  //= type=implication
  //# To construct the AAD, the keyring MUST concatenate the following values
  private static byte[] aad(byte[] idBytes, byte[] versionBytes, EncryptionContext encryptionContext) {
    byte[] serialized = CanonicalEncryptionContext.serialize(encryptionContext);
    return ByteBuffer
      .allocate(PROVIDER_ID_BYTES.length + idBytes.length + versionBytes.length + serialized.length)
      .put(PROVIDER_ID_BYTES)
      .put(idBytes)
      .put(versionBytes)
      .put(serialized)
      .array();
  }

  // KdfCtr.dfy accepts 32-, 48-, and 66-byte keys. The key store returns 32-byte keys; a shared cache may hold any length.
  private static byte[] deriveKey(BranchKeyMaterials branchKey, byte[] salt) {
    int length = branchKey.branchKey().length();
    if (length != 32 && length != 48 && length != 66) {
      throw new InvalidMaterialsException("Kdf in Counter Mode input is invalid.");
    }
    byte[] key = branchKey.branchKey().toByteArray();
    try {
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
      //# 3. Use a [KDF in Counter Mode with a Pseudo Random Function with HMAC SHA 256]
      //# (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf)
      return KdfCounterMode.derive(
        DigestAlgorithm.SHA_256,
//= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
//# - Use the branch key as the `key`.
        key,
        //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
        //# - Use the `salt` as the salt.
        KdfCounterMode.fixedInput(PROVIDER_ID_BYTES, salt, DERIVED_KEY_LENGTH),
//= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping
//# to derive a 32 byte `derivedBranchKey`
        DERIVED_KEY_LENGTH
      );
    } finally {
      Bytes.zero(key);
    }
  }

  /**
   * Not thread-safe.
   * Requires {@code keyStore}, {@code ttl}.
   * {@link #build()} throws {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException} for invalid settings.
   */
  public static final class Builder {

    private String branchKeyId;
    private BranchKeyIdSupplier branchKeyIdSupplier;
    private BranchKeyStore keyStore;
    private Duration ttl;
    private CacheType cache;
    private String partitionId;
    private CacheClock clock = CacheClock.SYSTEM;

    private Builder() {}

    /** The branch key for every message. Exactly one of this and {@code branchKeyIdSupplier}. */
    public Builder branchKeyId(String branchKeyId) {
      this.branchKeyId = branchKeyId;
      return this;
    }

    /** Chooses the branch key per message from its encryption context. */
    public Builder branchKeyIdSupplier(BranchKeyIdSupplier branchKeyIdSupplier) {
      this.branchKeyIdSupplier = branchKeyIdSupplier;
      return this;
    }

    /** Where branch keys come from. */
    public Builder keyStore(BranchKeyStore keyStore) {
      this.keyStore = keyStore;
      return this;
    }

    /**
     * How long a cached branch key is used: a positive whole number of seconds, such as {@code Duration.ofMinutes(10)}.
     * {@link #build()} rejects any other value, including null. See {@link CacheType} for the check against the cache.
     */
    public Builder ttl(Duration ttl) {
      this.ttl = ttl;
      return this;
    }

    /**
     * Where branch keys are cached; default {@code CacheType.defaultCache(1000)}.
     * Without this setting {@link #build()} requires {@code ttl} above the default 10-second grace period;
     * with {@code CacheType.defaultCache} given explicitly it does not (see {@link CacheType}).
     */
    public Builder cache(CacheType cache) {
      this.cache = cache;
      return this;
    }

    /** Keyrings sharing a cache share entries only when their partition ids and key stores' logical names are equal; default: a random id, so nothing is shared. */
    public Builder partitionId(String partitionId) {
      this.partitionId = partitionId;
      return this;
    }

    // The time source of the keyring and of the cache it builds; tests substitute their own.
    Builder clock(CacheClock clock) {
      this.clock = clock;
      return this;
    }

    public AwsKmsHierarchicalKeyring build() {
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
      //= type=implication
      //# - MUST provide a [KeyStore](../branch-key-store.md)
      KeyringNames.requireSet(keyStore, "keyStore");
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
      //= type=implication
      //# - MUST provide a cache limit TTL
      if (ttl == null) {
        throw new ValidationException("Missing value for required field `ttl`");
      }
      if (ttl.isNegative()) {
        throw new ValidationException("`ttl` must be greater than or equal to 0");
      }
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
      //# This value MUST be greater than zero.
      if (ttl.isZero()) {
        throw new ValidationException("`ttl` must be greater than 0");
      }
      // The keyring and the Dafny model count the TTL in whole seconds.
      if (ttl.getNano() != 0) {
        throw new ValidationException("`ttl` must be a whole number of seconds");
      }
      long ttlSeconds = ttl.getSeconds();
      CryptographicMaterialsCache built = cache(ttlSeconds);
      byte[] partitionIdBytes = partitionIdBytes();
      byte[] logicalKeyStoreNameBytes = utf8(
        keyStore.getKeyStoreInfo().logicalKeyStoreName(),
        "Could not UTF-8 Encode Logical Key Store Name: " + ENCODE_FAILURE
      );
      if (branchKeyId != null && branchKeyIdSupplier != null) {
        throw new ValidationException("Cannot initialize keyring with both a branchKeyId and BranchKeyIdSupplier.");
      }
      //= spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
      //= type=implication
      //# - MUST provide either a Branch Key Identifier or a [Branch Key Supplier](#branch-key-supplier)
      if (branchKeyId == null && branchKeyIdSupplier == null) {
        throw new ValidationException("Must initialize keyring with either branchKeyId or BranchKeyIdSupplier.");
      }
      return new AwsKmsHierarchicalKeyring(this, built, partitionIdBytes, logicalKeyStoreNameBytes);
    }

    // CheckCache, then the cache: the shared instance, or a new one of the configured or default type.
    private CryptographicMaterialsCache cache(long ttlSeconds) {
      if (cache == null) {
        checkGracePeriod(ttlSeconds, DEFAULT_GRACE_PERIOD_SECONDS);
        return new BuiltInCache(Caches.engine(CacheType.defaultCache(1000), clock));
      }
      CacheSpec spec = CacheSpec.of(cache);
      if (spec.kind == CacheType.Kind.STORM_TRACKING) {
        checkGracePeriod(ttlSeconds, StormSettings.of(spec.stormTracking).gracePeriodSeconds());
      }
      if (spec.kind == CacheType.Kind.SHARED) {
        return spec.shared;
      }
      return new BuiltInCache(Caches.engine(cache, clock));
    }

    // The message names ttlSeconds, the Dafny field, as the Dafny-based keyring's does.
    private static void checkGracePeriod(long ttlSeconds, long gracePeriod) {
      if (ttlSeconds <= gracePeriod) {
        throw new ValidationException(
          "When creating an AwsKmsHierarchicalKeyring with a StormCache, " +
          "the ttlSeconds of the KeyRing must be greater than the gracePeriod of the StormCache " +
          "yet the ttlSeconds is " + ttlSeconds + " and the gracePeriod is " + gracePeriod + "."
        );
      }
    }

    // The partition id as UTF-8, or a random UUID's 16 bytes.
    private byte[] partitionIdBytes() {
      if (partitionId != null) {
        return utf8(partitionId, "Could not UTF-8 Encode Partition ID: " + ENCODE_FAILURE);
      }
      UUID uuid = UUID.randomUUID();
      return ByteBuffer.allocate(16).putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits()).array();
    }
  }
}
