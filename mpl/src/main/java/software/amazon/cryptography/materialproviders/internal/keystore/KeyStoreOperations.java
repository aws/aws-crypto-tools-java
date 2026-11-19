// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.keystore;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.utils.SdkAutoCloseable;
import software.amazon.awssdk.utils.builder.SdkBuilder;
import software.amazon.cryptography.materialproviders.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.materialproviders.exceptions.ServiceException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.AwsArnParsing;
import software.amazon.cryptography.materialproviders.internal.UserAgent;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

/**
 * The key store operations, per AwsCryptographyKeyStoreOperations.dfy, CreateKeys.dfy, and GetKeys.dfy.
 * Thread-safe: it holds immutable settings and thread-safe SDK clients.
 */
public final class KeyStoreOperations implements AutoCloseable {

  // DynamoDB items and KMS encryption contexts carry this exact format: milliseconds padded to six digits.
  private static final String TIMESTAMP_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'";
  private static final int MAX_GRANT_TOKENS = 10;
  private static final int MAX_GRANT_TOKEN_LENGTH = 8192;

  private final String tableName;
  private final String logicalKeyStoreName;
  private final KmsConfiguration kmsConfiguration;
  private final KeyStoreKms kms;
  private final KeyStoreTable table;
  private final List<SdkAutoCloseable> ownedClients;

  private KeyStoreOperations(
    String tableName,
    String logicalKeyStoreName,
    KmsConfiguration kmsConfiguration,
    List<String> grantTokens,
    KmsClient kmsClient,
    DynamoDbClient ddbClient,
    List<SdkAutoCloseable> ownedClients
  ) {
    this.tableName = tableName;
    this.logicalKeyStoreName = logicalKeyStoreName;
    this.kmsConfiguration = kmsConfiguration;
    this.kms = new KeyStoreKms(kmsConfiguration, grantTokens, kmsClient);
    this.table = new KeyStoreTable(tableName, ddbClient);
    this.ownedClients = ownedClients;
  }

  /**
   * Validates the settings in the order Index.dfy does and creates the clients not given.
   * {@code kmsConfiguration} was validated when it was made.
   */
  public static KeyStoreOperations create(
    String tableName,
    String logicalKeyStoreName,
    KmsConfiguration kmsConfiguration,
    List<String> grantTokens,
    KmsClient kmsClient,
    DynamoDbClient ddbClient
  ) {
    //= spec/framework/branch-key-store.md#initialization
    //# The following inputs MAY be specified to create a KeyStore:
    checkGrantTokens(grantTokens);
    String region = inferredRegion(kmsConfiguration);
    List<SdkAutoCloseable> owned = new ArrayList<>();
    try {
      KmsClient kms = kmsClient;
      //= spec/framework/branch-key-store.md#kms-client
      //# If the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
      //# and no KMS Client is provided,
      //# a new KMS Client MUST be created
      //# with the region of the supplied KMS ARN.

      //= spec/framework/branch-key-store.md#kms-client
      //# If the AWS KMS Configuration is MRDiscovery,
      //# and no KMS Client is provided,
      //# a new KMS Client MUST be created
      //# with the region configured in the MRDiscovery.

      //= spec/framework/branch-key-store.md#kms-client
      //# If the AWS KMS Configuration is Discovery,
      //# and no KMS Client is provided,
      //# a new KMS Client MUST be created
      //# with the default configuration.
      if (kms == null) {
        kms = build("KMS", () -> withRegion(KmsClient.builder().overrideConfiguration(UserAgent.overrideConfiguration()), region));
        owned.add(kms);
      }
      DynamoDbClient ddb = ddbClient;
      //= spec/framework/branch-key-store.md#dynamodb-client
      //# If the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
      //# and no DynamoDb Client is provided,
      //# a new DynamoDb Client MUST be created
      //# with the region of the supplied KMS ARN.

      //= spec/framework/branch-key-store.md#dynamodb-client
      //# If the AWS KMS Configuration is MRDiscovery,
      //# and no DynamoDb Client is provided,
      //# a new DynamoDb Client MUST be created
      //# with the region configured in the MRDiscovery.

      //= spec/framework/branch-key-store.md#dynamodb-client
      //# If the AWS KMS Configuration is Discovery,
      //# and no DynamoDb Client is provided,
      //# a new DynamoDb Client MUST be created
      //# with the default configuration.
      if (ddb == null) {
        ddb = build("DynamoDB", () -> withRegion(DynamoDbClient.builder(), region));
        owned.add(ddb);
      }
      //= spec/framework/branch-key-store.md#initialization
      //# The following inputs MUST be specified to create a KeyStore:
      if (!KeyStoreItems.isValidTableName(tableName)) {
        throw new ValidationException(KeyStoreMessages.INVALID_TABLE_NAME);
      }
      return new KeyStoreOperations(tableName, logicalKeyStoreName, kmsConfiguration, grantTokens, kms, ddb, owned);
    } catch (RuntimeException e) {
      closeAll(owned);
      throw e;
    }
  }

  // Building fails when the SDK cannot find a Region (discovery without a default Region) or the Region is not valid.
  private static <T> T build(String service, java.util.function.Supplier<SdkBuilder<?, T>> builder) {
    try {
      return builder.get().build();
    } catch (SdkException | IllegalArgumentException e) {
      throw new ValidationException("Could not create the key store's " + service + " client: " + e.getMessage(), e);
    }
  }

  private static <B extends software.amazon.awssdk.awscore.client.builder.AwsClientBuilder<B, ?>> B withRegion(B builder, String region) {
    return region == null ? builder : builder.region(Region.of(region));
  }

  // The Region of the KMS key ARN, or of the MR-discovery configuration; null for discovery.
  private static String inferredRegion(KmsConfiguration kmsConfiguration) {
    if (kmsConfiguration.arn().isPresent()) {
      return Arns.parseKmsArn(kmsConfiguration.arn().get()).region();
    }
    return kmsConfiguration.region().orElse(null);
  }

  private static void checkGrantTokens(List<String> grantTokens) {
    boolean valid = grantTokens.size() <= MAX_GRANT_TOKENS;
    for (String token : grantTokens) {
      valid &= !token.isEmpty() && token.length() <= MAX_GRANT_TOKEN_LENGTH;
    }
    if (!valid) {
      throw new ValidationException(KeyStoreMessages.INVALID_GRANT_TOKENS);
    }
  }

  /** Creates the table if it does not exist and returns its ARN. */
  public String createKeyStore() {
    String tableArn = table.createIfMissing();
    if (!tableName.equals(AwsArnParsing.dynamoDbTableName(tableArn))) {
      throw new ServiceException(KeyStoreMessages.TABLE_ARN_MISMATCH);
    }
    return tableArn;
  }

  /**
   * Creates a branch key: its first version, DECRYPT_ONLY and ACTIVE, and its beacon key.
   *
   * @param branchKeyId the caller's id, or null for a random one
   * @param encryptionContext the caller's encryption context, or null for none; an id without a non-empty one fails
   */
  //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
  //= type=implication
  //# To create a branch key, this operation MUST take the following:
  //#
  //# - `branchKeyId`: The identifier
  //# - `encryptionContext`: Additional encryption context to bind to the created keys
  public String createKey(String branchKeyId, Map<String, String> encryptionContext) {
    //= spec/framework/branch-key-store.md#createkey
    //= type=implication
    //# If an optional branch key id is provided
    //# and no encryption context is provided this operation MUST fail.
    if (branchKeyId != null && (encryptionContext == null || encryptionContext.isEmpty())) {
      throw new ValidationException(KeyStoreMessages.CUSTOM_BRANCH_KEY_ID_NEED_EC);
    }
    if (!kmsConfiguration.arn().isPresent()) {
      //= spec/framework/branch-key-store.md#createkey
      //= type=implication
      //# If the Keystore's KMS Configuration is `Discovery` or `MRDiscovery`,
      //# this operation MUST fail.
      throw new ValidationException(KeyStoreMessages.DISCOVERY_CREATE_KEY_NOT_SUPPORTED);
    }
    String id = branchKeyId;
    if (id == null) {
      //= spec/framework/branch-key-store.md#createkey
      //# If no branch key id is provided,
      //# then this operation MUST create a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt)
      //# to be used as the branch key id.
      id = UUID.randomUUID().toString();
    } else if (id.isEmpty()) {
      throw new ValidationException(KeyStoreMessages.CUSTOM_BRANCH_KEY_ID_EMPTY);
    }
    //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //# - `timestamp`: a timestamp for the current time.
    //
    //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=exception
    //= reason=The fraction is the millisecond count zero-padded to six digits (SimpleDateFormat "SSSSSS"), as the Dafny MPL for Java writes it.
    //# This timestamp MUST be in ISO8601 format in UTC, to microsecond precision (e.g. “YYYY-MM-DDTHH:mm:ss.ssssssZ“)
    String timestamp = timestamp();
    //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //# - `version`: a new guid. This guid MUST be [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt)
    String version = UUID.randomUUID().toString();
    Map<String, String> custom = encryptionContext == null ? Collections.emptyMap() : encryptionContext;
    for (String key : custom.keySet()) {
      if (!KeyStoreItems.isValidCustomKey(key)) {
        throw new ValidationException(KeyStoreMessages.UTF8_ENCODING_ENCRYPTION_CONTEXT_ERROR);
      }
    }

    //= spec/framework/branch-key-store.md#createkey
    //= type=implication
    //# This operation MUST create a [branch key](structures.md#branch-key) and a [beacon key](structures.md#beacon-key) according to
    //# the [Branch Key and Beacon Key Creation](#branch-key-and-beacon-key-creation) section.
    Map<String, String> decryptOnly = KeyStoreItems.decryptOnlyContext(
      id,
      version,
      timestamp,
      logicalKeyStoreName,
      kmsConfiguration.arn().get(),
      custom
    );
    Map<String, String> active = KeyStoreItems.activeContext(decryptOnly);
    Map<String, String> beacon = KeyStoreItems.beaconContext(decryptOnly);
    //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=implication
    //# The wrapped Branch Keys, DECRYPT_ONLY and ACTIVE, MUST be created according to [Wrapped Branch Key Creation](#wrapped-branch-key-creation).

    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=implication
    //# - `EncryptionContext` MUST be the [DECRYPT_ONLY encryption context for branch keys](#decrypt_only-encryption-context).
    byte[] wrappedDecryptOnly = kms.generateKey(decryptOnly);
    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=implication
    //# - `CiphertextBlob` MUST be the wrapped DECRYPT_ONLY Branch Key.

    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=implication
    //# - `SourceEncryptionContext` MUST be the [DECRYPT_ONLY encryption context for branch keys](#decrypt_only-encryption-context).

    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=implication
    //# - `DestinationEncryptionContext` MUST be the [ACTIVE encryption context for branch keys](#active-encryption-context).
    byte[] wrappedActive = kms.reEncrypt(wrappedDecryptOnly, decryptOnly, active);
    //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=implication
    //# - `EncryptionContext` MUST be the [encryption context for beacon keys](#beacon-key-encryption-context).
    byte[] wrappedBeacon = kms.generateKey(beacon);
    //= spec/framework/branch-key-store.md#createkey
    //= type=implication
    //# If creation of the keys are successful,
    //# the operation MUST call Amazon DynamoDB TransactWriteItems according to the [write key material](#writing-branch-key-and-beacon-key-to-key-store) section.

    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=implication
    //# If the call to AWS KMS GenerateDataKeyWithoutPlaintext succeeds,
    //# the operation MUST use the GenerateDataKeyWithoutPlaintext result `CiphertextBlob`
    //# as the wrapped DECRYPT_ONLY Branch Key.

    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=implication
    //# If the call to AWS KMS ReEncrypt succeeds,
    //# the operation MUST use the ReEncrypt result `CiphertextBlob`
    //# as the wrapped ACTIVE Branch Key.

    //= spec/framework/branch-key-store.md#branch-key-and-beacon-key-creation
    //= type=implication
    //# If the call to AWS KMS GenerateDataKeyWithoutPlaintext succeeds,
    //# the operation MUST use the `CiphertextBlob` as the wrapped Beacon Key.
    table.writeNewKey(
      KeyStoreItems.toItem(decryptOnly, wrappedDecryptOnly),
      KeyStoreItems.toItem(active, wrappedActive),
      KeyStoreItems.toItem(beacon, wrappedBeacon)
    );
    //= spec/framework/branch-key-store.md#createkey
    //= type=implication
    //# If writing to the keystore succeeds,
    //# the operation MUST return the branch-key-id that maps to both
    //# the branch key and the beacon key.

    //= spec/framework/branch-key-store.md#createkey
    //= type=implication
    //# Otherwise, this operation MUST yield an error.
    return id;
  }

  /**
   * Makes a new ACTIVE version, after KMS authenticates the current ACTIVE item.
   * The new version keeps every other attribute of that item, including the caller's encryption context.
   */
  public void versionKey(String branchKeyId) {
    //= spec/framework/branch-key-store.md#versionkey
    //= type=implication
    //# If the Keystore's KMS Configuration is `Discovery` or `MRDiscovery`,
    //# this operation MUST immediately fail.
    if (!kmsConfiguration.arn().isPresent()) {
      throw new ValidationException(KeyStoreMessages.DISCOVERY_VERSION_KEY_NOT_SUPPORTED);
    }
    if (branchKeyId.isEmpty()) {
      throw new ValidationException(KeyStoreMessages.BRANCH_KEY_ID_NEEDED);
    }
    String timestamp = timestamp();
    String version = UUID.randomUUID().toString();

    //= spec/framework/branch-key-store.md#versionkey
    //= type=implication
    //# VersionKey MUST first get the active version for the branch key from the keystore
    //# by calling AWS DDB `GetItem`
    //# using the `branch-key-id` as the Partition Key and `"branch:ACTIVE"` value as the Sort Key.
    Map<String, AttributeValue> oldActiveItem = table.get(
      branchKeyId,
      KeyStoreItems.BRANCH_KEY_ACTIVE_TYPE,
      KeyStoreMessages.INVALID_ACTIVE_ITEM
    );
    Map<String, String> oldActive = KeyStoreItems.toContext(oldActiveItem, logicalKeyStoreName);
    //= spec/framework/branch-key-store.md#versionkey
    //= type=implication
    //# The `kms-arn` field of DDB response item MUST be [compatible with](#aws-key-arn-compatibility)
    //# the configured `KMS ARN` in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
    if (!kms.mayUse(oldActive)) {
      throw new ValidationException(KeyStoreMessages.VERSION_KEY_KMS_KEY_ARN_DISAGREEMENT);
    }
    //= spec/framework/branch-key-store.md#versionkey
    //= type=implication
    //# The values on the AWS DDB response item
    //# MUST be authenticated according to [authenticating a keystore item](#authenticating-a-keystore-item).

    //= spec/framework/branch-key-store.md#versionkey
    //= type=implication
    //# If the item fails to authenticate this operation MUST fail.

    //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
    //= type=implication
    //# The operation MUST call [AWS KMS API ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)
    //# with a request constructed as follows:

    //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
    //= type=implication
    //# - `SourceEncryptionContext` MUST be the [encryption context](#encryption-context) constructed above

    //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
    //= type=implication
    //# - `CiphertextBlob` MUST be the `enc` attribute value on the AWS DDB response item

    //= spec/framework/branch-key-store.md#authenticating-a-keystore-item
    //= type=implication
    //# - `DestinationEncryptionContext` MUST be the [encryption context](#encryption-context) constructed above
    kms.reEncrypt(KeyStoreItems.wrappedKey(oldActiveItem), oldActive, oldActive);

    Map<String, String> decryptOnly = KeyStoreItems.newVersionContext(oldActive, version, timestamp);
    Map<String, String> active = KeyStoreItems.activeContext(decryptOnly);
    //= spec/framework/branch-key-store.md#versionkey
    //= type=implication
    //# The wrapped Branch Keys, DECRYPT_ONLY and ACTIVE, MUST be created according to [Wrapped Branch Key Creation](#wrapped-branch-key-creation).
    byte[] wrappedDecryptOnly = kms.generateKey(decryptOnly);
    byte[] wrappedActive = kms.reEncrypt(wrappedDecryptOnly, decryptOnly, active);
    //= spec/framework/branch-key-store.md#versionkey
    //= type=implication
    //# To add the new branch key to the keystore,
    //# the operation MUST call [Amazon DynamoDB API TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html).

    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=implication
    //# If the call to AWS KMS GenerateDataKeyWithoutPlaintext succeeds,
    //# the operation MUST use the GenerateDataKeyWithoutPlaintext result `CiphertextBlob`
    //# as the wrapped DECRYPT_ONLY Branch Key.

    //= spec/framework/branch-key-store.md#wrapped-branch-key-creation
    //= type=implication
    //# If the call to AWS KMS ReEncrypt succeeds,
    //# the operation MUST use the ReEncrypt result `CiphertextBlob`
    //# as the wrapped ACTIVE Branch Key.

    //= spec/framework/branch-key-store.md#versionkey
    //= type=implication
    //# If DDB TransactWriteItems is successful, this operation MUST return a successful response containing no additional data.

    //= spec/framework/branch-key-store.md#versionkey
    //= type=implication
    //# Otherwise, this operation MUST yield an error.
    table.writeNewVersion(KeyStoreItems.toItem(decryptOnly, wrappedDecryptOnly), KeyStoreItems.toItem(active, wrappedActive));
  }

  //= spec/framework/branch-key-store.md#getactivebranchkey
  //= type=implication
  //# To get the active version for the branch key id from the keystore
  //# this operation MUST call AWS DDB `GetItem`
  //# using the `branch-key-id` as the Partition Key and `"branch:ACTIVE"` value as the Sort Key.

  //= spec/framework/branch-key-store.md#getactivebranchkey
  //= type=implication
  //# The operation MUST decrypt the branch key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.

  //= spec/framework/branch-key-store.md#getactivebranchkey
  //= type=implication
  //# If the branch key fails to decrypt, GetActiveBranchKey MUST fail.
  public UnwrappedKey getActiveBranchKey(String branchKeyId) {
    return unwrap(
      branchKeyId,
      KeyStoreItems.BRANCH_KEY_ACTIVE_TYPE,
      KeyStoreMessages.INVALID_ACTIVE_ITEM,
      KeyStoreMessages.GET_KEY_ARN_DISAGREEMENT
    );
  }

  //= spec/framework/branch-key-store.md#getbranchkeyversion
  //= type=implication
  //# To get a branch key from the keystore this operation MUST call AWS DDB `GetItem`
  //# using the `branch-key-id` as the Partition Key and "branch:version:" + `branchKeyVersion` value as the Sort Key.

  //= spec/framework/branch-key-store.md#getbranchkeyversion
  //= type=implication
  //# The operation MUST decrypt the branch key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.

  //= spec/framework/branch-key-store.md#getbranchkeyversion
  //= type=implication
  //# If the branch key fails to decrypt, this operation MUST fail.
  public UnwrappedKey getBranchKeyVersion(String branchKeyId, String branchKeyVersion) {
    return unwrap(
      branchKeyId,
      KeyStoreItems.BRANCH_KEY_TYPE_PREFIX + branchKeyVersion,
      KeyStoreMessages.INVALID_VERSION_ITEM,
      KeyStoreMessages.GET_KEY_VERSION_ARN_DISAGREEMENT
    );
  }

  //= spec/framework/branch-key-store.md#getbeaconkey
  //= type=implication
  //# To get a branch key from the keystore this operation MUST call AWS DDB `GetItem`
  //# using the `branch-key-id` as the Partition Key and "beacon:ACTIVE" value as the Sort Key.

  //= spec/framework/branch-key-store.md#getbeaconkey
  //= type=implication
  //# The operation MUST decrypt the beacon key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.

  //= spec/framework/branch-key-store.md#getbeaconkey
  //= type=implication
  //# If the beacon key fails to decrypt, this operation MUST fail.
  public UnwrappedKey getBeaconKey(String branchKeyId) {
    return unwrap(
      branchKeyId,
      KeyStoreItems.BEACON_KEY_TYPE_VALUE,
      KeyStoreMessages.INVALID_BEACON_ITEM,
      KeyStoreMessages.GET_KEY_VERSION_ARN_DISAGREEMENT
    );
  }

  private UnwrappedKey unwrap(String branchKeyId, String type, String invalidItem, String disagreement) {
    Map<String, AttributeValue> item = table.get(branchKeyId, type, invalidItem);
    Map<String, String> context = KeyStoreItems.toContext(item, logicalKeyStoreName);
    //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //= type=implication
    //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `Discovery` or `MRDiscovery`,
    //# the `kms-arn` field of DDB response item MUST NOT be an Alias
    //# or the operation MUST fail.
    if (!Arns.isValidKeyArn(context.get(KeyStoreItems.KMS_FIELD))) {
      throw new InvalidMaterialsException(KeyStoreMessages.RETRIEVED_KEYSTORE_ITEM_INVALID_KMS_ARN);
    }
    //= spec/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //= type=implication
    //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `KMS Key ARN` or `KMS MRKey ARN`,
    //# the `kms-arn` field of the DDB response item MUST be
    //# [compatible with](#aws-key-arn-compatibility) the configured KMS Key in
    //# the [AWS KMS Configuration](#aws-kms-configuration) for this keystore,
    //# or the operation MUST fail.
    if (!kms.mayUse(context)) {
      throw new ValidationException(disagreement);
    }
    return new UnwrappedKey(context, kms.decrypt(KeyStoreItems.wrappedKey(item), context));
  }

  // SimpleDateFormat is not thread-safe, so each call makes its own.
  private static String timestamp() {
    SimpleDateFormat format = new SimpleDateFormat(TIMESTAMP_FORMAT);
    format.setTimeZone(TimeZone.getTimeZone("UTC"));
    return format.format(new Date());
  }

  /** Closes the clients this store created; clients the caller passed stay open. */
  @Override
  public void close() {
    closeAll(ownedClients);
  }

  private static void closeAll(List<SdkAutoCloseable> clients) {
    for (SdkAutoCloseable client : clients) {
      client.close();
    }
  }
}
