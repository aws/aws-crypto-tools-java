// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.internal.KeyMaterialsAccess;
import software.amazon.cryptography.materialproviders.internal.KeyringNames;
import software.amazon.cryptography.materialproviders.internal.keystore.KeyStoreOperations;
import software.amazon.cryptography.materialproviders.internal.keystore.UnwrappedKey;
import software.amazon.cryptography.materialproviders.internal.primitives.Bytes;

/**
 * The provided {@link KeyStore}: branch keys, the versioned keys the hierarchical keyring wraps data keys with,
 * stored in a DynamoDB table and protected by a KMS key. Thread-safe.
 * Creating and versioning keys are operations of this class, not of {@code KeyStore}.
 * Clients passed to the builder are not closed; clients the store creates are closed by {@link #close()}.
 *
 * <p>Each operation takes a request object and returns a response object.
 * Every operation also accepts a {@code Consumer} of the request's builder, as the AWS SDK for Java 2.x does:
 * {@code store.createKey(b -> b.branchKeyId(id).encryptionContext(context))}.
 *
 * <p>Reads are eventually consistent, and {@link #versionKey} does not detect a concurrent {@code versionKey}:
 * the last write of the ACTIVE item wins.
 * Failed AWS calls throw the {@link software.amazon.cryptography.materialproviders.exceptions.ErrorKind} subclass that matches
 * the service's error code, with the AWS SDK exception as the cause.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/branch-key-store.md">branch key store</a>.
 */
//= spec/framework/branch-key-store.md#operations
//= type=implication
//# The Keystore MUST support the following operations:
//#
//#- [GetKeyStoreInfo](#getkeystoreinfo)
//#- [CreateKeyStore](#createkeystore)
//#- [CreateKey](#createkey)
//#- [VersionKey](#versionkey)
//#- [GetActiveBranchKey](#getactivebranchkey)
//#- [GetBranchKeyVersion](#getbranchkeyversion)
//#- [GetBeaconKey](#getbeaconkey)
public final class DynamoDbKeyStore implements KeyStore, AutoCloseable {

  private final GetKeyStoreInfoResponse info;
  private final KeyStoreOperations operations;

  private DynamoDbKeyStore(GetKeyStoreInfoResponse info, KeyStoreOperations operations) {
    this.info = info;
    this.operations = operations;
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Creates the table if it does not exist and returns its ARN.
   * Does not wait for a new table to become active; {@link #createKey} can fail until it is.
   * To wait, give the builder a {@code ddbClient} and call its {@code waiter().waitUntilTableExists};
   * a client the store creates is not exposed.
   *
   * @throws software.amazon.cryptography.materialproviders.exceptions.ValidationException
   *   if the table exists without the key store's key schema
   */
  public CreateKeyStoreResponse createKeyStore(CreateKeyStoreRequest request) {
    Objects.requireNonNull(request, "request");
    return CreateKeyStoreResponse.builder().tableArn(operations.createKeyStore()).build();
  }

  /** The same as {@code createKeyStore(CreateKeyStoreRequest.builder().build())}. */
  public CreateKeyStoreResponse createKeyStore() {
    return createKeyStore(CreateKeyStoreRequest.builder().build());
  }

  /** {@link #createKeyStore(CreateKeyStoreRequest)} with a request built by {@code request}. */
  public CreateKeyStoreResponse createKeyStore(Consumer<CreateKeyStoreRequest.Builder> request) {
    CreateKeyStoreRequest.Builder builder = CreateKeyStoreRequest.builder();
    request.accept(builder);
    return createKeyStore(builder.build());
  }

  /**
   * Creates a branch key and returns its id: the request's id, or a random one.
   * The request's encryption context, if any, is bound into the key.
   *
   * @throws software.amazon.cryptography.materialproviders.exceptions.ValidationException
   *   if the request has an id without a non-empty encryption context, or an empty id
   * @throws software.amazon.cryptography.materialproviders.exceptions.ConflictException if the id already exists
   */
  //= spec/framework/branch-key-store.md#createkey
  //= type=implication
  //# The CreateKey caller MUST provide:
  //# - An optional branch key id
  //# - An optional encryption context
  public CreateKeyResponse createKey(CreateKeyRequest request) {
    String id = request.branchKeyId().orElse(null);
    EncryptionContext encryptionContext = request.encryptionContext().orElse(null);
    return CreateKeyResponse.builder().branchKeyId(operations.createKey(id, encryptionContext)).build();
  }

  /** Creates a branch key with a random id and no encryption context of the caller's. */
  public CreateKeyResponse createKey() {
    return createKey(CreateKeyRequest.builder().build());
  }

  /** {@link #createKey(CreateKeyRequest)} with a request built by {@code request}. */
  public CreateKeyResponse createKey(Consumer<CreateKeyRequest.Builder> request) {
    CreateKeyRequest.Builder builder = CreateKeyRequest.builder();
    request.accept(builder);
    return createKey(builder.build());
  }

  /** Makes a new version of the branch key active; earlier versions stay available for decryption. */
  //= spec/framework/branch-key-store.md#versionkey
  //= type=implication
  //# - MUST supply a `branch-key-id`
  public VersionKeyResponse versionKey(VersionKeyRequest request) {
    operations.versionKey(request.branchKeyId());
    return VersionKeyResponse.builder().build();
  }

  /** {@link #versionKey(VersionKeyRequest)} with a request built by {@code request}. */
  public VersionKeyResponse versionKey(Consumer<VersionKeyRequest.Builder> request) {
    VersionKeyRequest.Builder builder = VersionKeyRequest.builder();
    request.accept(builder);
    return versionKey(builder.build());
  }

  //= spec/framework/branch-key-store.md#getactivebranchkey
  //= type=implication
  //# - MUST supply a `branch-key-id`
  @Override
  public GetActiveBranchKeyResponse getActiveBranchKey(GetActiveBranchKeyRequest request) {
    //= spec/framework/branch-key-store.md#getactivebranchkey
    //= type=implication
    //# This GetActiveBranchKey MUST construct [branch key materials](./structures.md#branch-key-materials)
    //# according to [Branch Key Materials From Authenticated Encryption Context](#branch-key-materials-from-authenticated-encryption-context).

    //= spec/framework/branch-key-store.md#getactivebranchkey
    //= type=implication
    //# This operation MUST return the constructed [branch key materials](./structures.md#branch-key-materials).
    return GetActiveBranchKeyResponse.builder()
      .branchKeyMaterials(branchKeyMaterials(operations.getActiveBranchKey(request.branchKeyId())))
      .build();
  }

  //= spec/framework/branch-key-store.md#getbranchkeyversion
  //= type=implication
  //# - MUST supply a `branch-key-id`

  //= spec/framework/branch-key-store.md#getbranchkeyversion
  //= type=implication
  //# - MUST supply a `branchKeyVersion`
  @Override
  public GetBranchKeyVersionResponse getBranchKeyVersion(GetBranchKeyVersionRequest request) {
    //= spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=implication
    //# This GetBranchKeyVersion MUST construct [branch key materials](./structures.md#branch-key-materials)
    //# according to [Branch Key Materials From Authenticated Encryption Context](#branch-key-materials-from-authenticated-encryption-context).

    //= spec/framework/branch-key-store.md#getbranchkeyversion
    //= type=implication
    //# This operation MUST return the constructed [branch key materials](./structures.md#branch-key-materials).
    return GetBranchKeyVersionResponse.builder()
      .branchKeyMaterials(branchKeyMaterials(operations.getBranchKeyVersion(request.branchKeyId(), request.branchKeyVersion())))
      .build();
  }

  //= spec/framework/branch-key-store.md#getbeaconkey
  //= type=implication
  //# - MUST supply a `branch-key-id`
  @Override
  public GetBeaconKeyResponse getBeaconKey(GetBeaconKeyRequest request) {
    UnwrappedKey unwrapped = operations.getBeaconKey(request.branchKeyId());
    try {
      EncryptionContext context = EncryptionContext.copyOf(unwrapped.encryptionContext());
      //= spec/framework/branch-key-store.md#getbeaconkey
      //= type=implication
      //# This GetBeaconKey MUST construct [beacon key materials](./structures.md#beacon-key-materials) from the decrypted branch key material
      //# and the `branchKeyId` from the returned `branch-key-id` field.

      //= spec/framework/branch-key-store.md#getbeaconkey
      //= type=implication
      //# This operation MUST return the constructed [beacon key materials](./structures.md#beacon-key-materials).
      return GetBeaconKeyResponse.builder()
        .beaconKeyMaterials(KeyMaterialsAccess.beaconKey(unwrapped.branchKeyId(), context, SecretBytes.copyOf(unwrapped.key()), Collections.emptyMap()))
        .build();
    } finally {
      Bytes.zero(unwrapped.key());
    }
  }

  //= spec/framework/branch-key-store.md#getkeystoreinfo
  //= type=implication
  //# This operation MUST return the keystore information in this keystore configuration.
  @Override
  public GetKeyStoreInfoResponse getKeyStoreInfo(GetKeyStoreInfoRequest request) {
    Objects.requireNonNull(request, "request");
    return info;
  }

  @Override
  public void close() {
    operations.close();
  }

  private static BranchKeyMaterials branchKeyMaterials(UnwrappedKey unwrapped) {
    try {
      String version = unwrapped.branchKeyVersion();
      EncryptionContext context = EncryptionContext.copyOf(unwrapped.encryptionContext());
      //= spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
      //= type=implication
      //# - [Branch Key](./structures.md#branch-key) MUST be the [decrypted branch key material](#aws-kms-branch-key-decryption)

      //= spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
      //= type=implication
      //# - [Branch Key Id](./structures.md#branch-key-id) MUST be the `branch-key-id`
      return KeyMaterialsAccess.branchKey(unwrapped.branchKeyId(), version, context, SecretBytes.copyOf(unwrapped.key()));
    } finally {
      Bytes.zero(unwrapped.key());
    }
  }

  /**
   * Not thread-safe. Requires {@code ddbTableName}, {@code logicalKeyStoreName}, and {@code kmsConfiguration}.
   * {@link #build()} throws {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException} for invalid settings.
   */
  public static final class Builder {

    private String ddbTableName;
    private KmsConfiguration kmsConfiguration;
    private String logicalKeyStoreName;
    //= spec/framework/branch-key-store.md#initialization
    //= type=implication
    //# The following inputs MAY be specified to create a KeyStore:
    //#
    //# - [ID](#keystore-id)
    //# - [AWS KMS Grant Tokens](#aws-kms-grant-tokens)
    //# - [DynamoDb Client](#dynamodb-client)
    //# - [KMS Client](#kms-client)
    private String id;
    private List<String> grantTokens = Collections.emptyList();
    private DynamoDbClient ddbClient;
    private KmsClient kmsClient;

    private Builder() {}

    /** 3 to 255 characters. */
    public Builder ddbTableName(String ddbTableName) {
      this.ddbTableName = ddbTableName;
      return this;
    }

    public Builder kmsConfiguration(KmsConfiguration kmsConfiguration) {
      this.kmsConfiguration = kmsConfiguration;
      return this;
    }

    /** Bound into every branch key's KMS encryption context; must stay the same for the life of the table. */
    public Builder logicalKeyStoreName(String logicalKeyStoreName) {
      this.logicalKeyStoreName = logicalKeyStoreName;
      return this;
    }

    /** Identifies this store in {@link GetKeyStoreInfoResponse}; default: a random id. */
    public Builder id(String id) {
      this.id = id;
      return this;
    }

    /** At most 10 tokens of 1 to 8192 characters each. Copied. */
    public Builder grantTokens(Collection<String> grantTokens) {
      List<String> copy = new ArrayList<>(grantTokens);
      for (String token : copy) {
        Objects.requireNonNull(token, "grant token");
      }
      this.grantTokens = Collections.unmodifiableList(copy);
      return this;
    }

    /** The same as {@link #grantTokens(Collection)} with these values; a null array is passed on as a null collection. */
    public Builder grantTokens(String... grantTokens) {
      return grantTokens(grantTokens == null ? null : Arrays.asList(grantTokens));
    }

    /**
     * Default: a client the store creates and owns, in the Region of the KMS key ARN or the MR-discovery Region;
     * for discovery, a default-configured client.
     */
    public Builder ddbClient(DynamoDbClient ddbClient) {
      this.ddbClient = ddbClient;
      return this;
    }

    /** Default: chosen as for {@link #ddbClient}. */
    public Builder kmsClient(KmsClient kmsClient) {
      this.kmsClient = kmsClient;
      return this;
    }

    public DynamoDbKeyStore build() {
      //= spec/framework/branch-key-store.md#initialization
      //= type=implication
      //# The following inputs MUST be specified to create a KeyStore:
      //#
      //# - [Table Name](#table-name)
      //# - [AWS KMS Configuration](#aws-kms-configuration)
      //# - [Logical KeyStore Name](#logical-keystore-name)
      KeyringNames.requireSet(ddbTableName, "ddbTableName");
      KeyringNames.requireSet(kmsConfiguration, "kmsConfiguration");
      KeyringNames.requireSet(logicalKeyStoreName, "logicalKeyStoreName");
      KeyStoreOperations operations = KeyStoreOperations.create(
        ddbTableName,
        logicalKeyStoreName,
        kmsConfiguration,
        grantTokens,
        kmsClient,
        ddbClient
      );
      //= spec/framework/branch-key-store.md#keystore-id
      //# If one is not supplied, then a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt) MUST be used.
      String keyStoreId = id == null ? UUID.randomUUID().toString() : id;
      //= spec/framework/branch-key-store.md#getkeystoreinfo
      //= type=implication
      //# This MUST include:
      GetKeyStoreInfoResponse info = GetKeyStoreInfoResponse
        .builder()
        .keyStoreId(keyStoreId)
        .keyStoreName(ddbTableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .grantTokens(grantTokens)
        .kmsConfiguration(kmsConfiguration)
        .build();
      return new DynamoDbKeyStore(info, operations);
    }
  }
}
