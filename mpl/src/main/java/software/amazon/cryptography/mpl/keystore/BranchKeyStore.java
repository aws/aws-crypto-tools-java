// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keystore;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.EncryptionContext;

/**
 * Branch keys, the versioned keys the hierarchical keyring wraps data keys with, stored in a DynamoDB table
 * and protected by a KMS key. Thread-safe.
 * Clients passed to the builder are not closed; clients the store creates are closed by {@link #close()}.
 *
 * <p>Reads are eventually consistent, and {@link #versionKey} does not detect a concurrent {@code versionKey}:
 * the last write of the ACTIVE item wins.
 * Failed AWS calls throw the {@link software.amazon.cryptography.mpl.exceptions.ErrorKind} subclass that matches
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
public final class BranchKeyStore implements AutoCloseable {

  private BranchKeyStore() {
    throw new UnsupportedOperationException("not implemented yet");
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
   * @throws software.amazon.cryptography.mpl.exceptions.ValidationException
   *   if the table exists without the key store's key schema
   */
  public String createKeyStore() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Creates a branch key with a random id and returns the id. */
  public String createKey() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Creates a branch key with a random id and a custom encryption context, and returns the id. */
  public String createKey(EncryptionContext encryptionContext) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Creates a branch key with the caller's id and custom encryption context, and returns the id.
   *
   * @throws software.amazon.cryptography.mpl.exceptions.ValidationException
   *   if the id is empty or the encryption context is empty
   * @throws software.amazon.cryptography.mpl.exceptions.ConflictException if the id already exists
   */
  //= spec/framework/branch-key-store.md#createkey
  //= type=implication
  //# The CreateKey caller MUST provide:
  //# - An optional branch key id
  //# - An optional encryption context
  public String createKey(String branchKeyIdentifier, EncryptionContext encryptionContext) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** Makes a new version of the branch key active; earlier versions stay available for decryption. */
  //= spec/framework/branch-key-store.md#versionkey
  //= type=implication
  //# - MUST supply a `branch-key-id`
  public void versionKey(String branchKeyIdentifier) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  //= spec/framework/branch-key-store.md#getactivebranchkey
  //= type=implication
  //# - MUST supply a `branch-key-id`
  public BranchKeyMaterials getActiveBranchKey(String branchKeyIdentifier) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  //= spec/framework/branch-key-store.md#getbranchkeyversion
  //= type=implication
  //# - MUST supply a `branch-key-id`

  //= spec/framework/branch-key-store.md#getbranchkeyversion
  //= type=implication
  //# - MUST supply a `branchKeyVersion`
  public BranchKeyMaterials getBranchKeyVersion(String branchKeyIdentifier, String branchKeyVersion) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  //= spec/framework/branch-key-store.md#getbeaconkey
  //= type=implication
  //# - MUST supply a `branch-key-id`
  public BeaconKeyMaterials getBeaconKey(String branchKeyIdentifier) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  //= spec/framework/branch-key-store.md#getkeystoreinfo
  //= type=implication
  //# This operation MUST return the keystore information in this keystore configuration.
  public KeyStoreInfo getKeyStoreInfo() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public void close() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe. Requires {@code ddbTableName}, {@code logicalKeyStoreName}, and {@code kmsConfiguration}.
   * {@link #build()} throws {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings.
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

    /** Identifies this store in {@link KeyStoreInfo}; default: a random id. */
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

    public BranchKeyStore build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
