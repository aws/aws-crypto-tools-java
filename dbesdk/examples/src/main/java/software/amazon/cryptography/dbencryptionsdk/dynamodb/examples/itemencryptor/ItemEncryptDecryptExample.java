package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.itemencryptor;

import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/**
 * This example sets up a DynamoDB Item Encryptor and uses the EncryptItem and DecryptItem APIs to
 * directly encrypt and decrypt an existing DynamoDB item. You should use the DynamoDB Item Encryptor
 * if you already have a DynamoDB Item to encrypt or decrypt, and do not need to make a Put or Get
 * call to DynamoDB. For example, if you are using DynamoDB Streams, you may already be working with
 * an encrypted item obtained from DynamoDB, and want to directly decrypt the item.
 *
 * <p>This example does not call DynamoDB, so it needs no table access. The table name provided in CLI
 * arguments is used only as the logical table name in the item encryptor's configuration; decrypting
 * an item requires a configuration with the same logical table name. The example item uses this
 * primary key:
 *   - Partition key is named "partition_key" with type (S)
 *   - Sort key is named "sort_key" with type (N)
 */
public class ItemEncryptDecryptExample {

  public static void encryptAndDecrypt(String kmsKeyId, String tableName) {
    // 1. Create a Keyring. This Keyring will be responsible for protecting the data keys that
    // protect your data. For this example, we will create a AWS KMS Keyring with the AWS KMS Key we
    // want to use. We will use the AWS KMS MRK Multi Keyring, as it will correctly handle both
    // single region and Multi-Region KMS Keys.
    Keyring kmsKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(kmsKeyId)
      .build();

    // 2. Decide how each attribute of your items is protected. BasicPutGetExample
    //    explains each action (encryptAndSign, signOnly, signAndIncludeInEncryptionContext,
    //    doNothing), and why the partition and sort keys get none.
    //    Every attribute you write must either have an action or start with the prefix set in the
    //    next step; writing an item with any other attribute fails.

    // 3. Decide which attributes are left out of the signature. Two separate settings do this. They
    //    do different jobs, and you can use either one, both, or neither:
    //
    //    - doNothingPrefix(":") is a naming rule. Every attribute whose name starts with this text
    //      is treated as doNothing, without being listed anywhere. It lets you add new unsigned
    //      attributes later just by naming them with the prefix, with no configuration change. Pick
    //      the prefix before you write any items, and do not change it afterwards.
    //
    //    - doNothing("name", ...) lists specific attributes by name, for unsigned attributes whose
    //      names do not start with the prefix. Never remove a name from this list while items that
    //      have that attribute may still be in the table, or reading those items fails. To add a
    //      name, first update the configuration on every reader, and only then start writing the
    //      new attribute.
    //
    //    This example sets the prefix ":". The item it writes has one such attribute,
    //    ":attribute3", so that attribute is not signed and does not need to be listed.

    // Build the schema from the choices above.
    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("attribute1")
      .signOnly("attribute2")
      .doNothingPrefix(":")
      .build();

    // 4. Create the DynamoDB Item Encryptor. Its builder takes the encryption settings directly:
    //    the logical table name, the schema from step 3, and the keyring from step 1.
    //    Unlike a table configuration, the item encryptor has no table name to default it from,
    //    so the logical table name is required here.
    DynamoDbItemEncryptor itemEncryptor = DynamoDbItemEncryptor
      .builder()
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(kmsKeyring)
      // Specifying an algorithm suite is not required,
      // but is done here to demonstrate how to do so.
      // We suggest using the
      // `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384` suite,
      // which includes AES-GCM with key derivation, signing, and key commitment.
      // This is also the default algorithm suite if one is not specified.
      // For more information on supported algorithm suites, see:
      //   https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/supported-algorithms.html
      .algorithmSuite(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384
      )
      .build();

    // 5. Directly encrypt a DynamoDB item using the DynamoDB Item Encryptor
    Map<String, AttributeValue> originalItem = Map.of(
      "partition_key",
      AttributeValue.fromS("ItemEncryptDecryptExample"),
      "sort_key",
      AttributeValue.fromN("0"),
      "attribute1",
      AttributeValue.fromS("encrypt and sign me!"),
      "attribute2",
      AttributeValue.fromS("sign me!"),
      ":attribute3",
      AttributeValue.fromS("ignore me!")
    );
    Map<String, AttributeValue> encryptedItem = itemEncryptor
      .encryptItem(originalItem)
      .encryptedItem();

    // Demonstrate that the item has been encrypted
    assert encryptedItem
      .get("partition_key")
      .s()
      .equals("ItemEncryptDecryptExample");
    assert encryptedItem.get("sort_key").n().equals("0");
    assert encryptedItem.get("attribute1").b() != null;

    // 6. Directly decrypt the encrypted item using the DynamoDB Item Encryptor
    Map<String, AttributeValue> decryptedItem = itemEncryptor
      .decryptItem(encryptedItem)
      .plaintextItem();

    // Demonstrate that the item was decrypted successfully
    assert decryptedItem
      .get("partition_key")
      .s()
      .equals("ItemEncryptDecryptExample");
    assert decryptedItem.get("sort_key").n().equals("0");
    assert decryptedItem.get("attribute1").s().equals("encrypt and sign me!");
  }

  public static void main(String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException(
        "To run this example, include the kmsKeyId as args[0] and tableName as args[1]"
      );
    }
    String kmsKeyId = args[0];
    String tableName = args[1];
    encryptAndDecrypt(kmsKeyId, tableName);
  }
}
