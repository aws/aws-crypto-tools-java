package software.amazon.cryptography.dbesdk.examples.itemencryptor;

import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptorConfig;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;

/*
 This example sets up a DynamoDB Item Encryptor and uses the EncryptItem and DecryptItem APIs to
 directly encrypt and decrypt an existing DynamoDB item. You should use the DynamoDB Item Encryptor
 if you already have a DynamoDB Item to encrypt or decrypt, and do not need to make a Put or Get
 call to DynamoDB. For example, if you are using DynamoDB Streams, you may already be working with
 an encrypted item obtained from DynamoDB, and want to directly decrypt the item.

 Running this example requires access to the DynamoDB Table whose name is provided in CLI arguments. This
 table must be configured with the following primary key configuration:
   - Partition key is named "partition_key" with type (S)
   - Sort key is named "sort_key" with type (N)
*/
public class ItemEncryptDecryptExample {

  public static void encryptAndDecrypt(String kmsKeyId, String tableName) {
    // 1. Create a Keyring. This Keyring will be responsible for protecting the data keys that
    // protect your data. For this example, we will create a AWS KMS Keyring with the AWS KMS Key we
    // want to use. We will use the AWS KMS MRK Multi Keyring, as it will correctly handle both
    // single region and Multi-Region KMS Keys.
    final Keyring kmsKeyring = AwsKmsMrkMultiKeyring
      .builder()
      .generator(kmsKeyId)
      .build();

    // 2. Decide how each attribute of your items is protected. Give each attribute one of these
    //    actions:
    //    - encryptAndSign: the value is encrypted, so it cannot be read without the keys your
    //      keyring uses, and it is covered by the item's signature, so any change to it is detected
    //      when the item is read.
    //    - signOnly: the value is stored as plain, readable text, but it is covered by the
    //      signature, so any change to it is detected.
    //    - signAndIncludeInEncryptionContext: like signOnly, and the value is also handed to your
    //      keyring each time the item is encrypted or decrypted, for example so that a branch key
    //      ID supplier can pick a different key for each tenant. Using this action also requires
    //      signAndIncludePrimaryKeysInEncryptionContext(true) (see below).
    //    - doNothing: the value is stored as plain text and is not covered by the signature, so a
    //      change to it is NOT detected.
    //    Every attribute you write must either have an action or start with the prefix set in the
    //    next step; writing an item with any other attribute fails.
    //
    //    Do not give the partition key or the sort key (together, the table's primary key) an
    //    action. DynamoDB needs to read them to find the item, so they can never be encrypted, and
    //    the library always signs them for you. By default they are signed like signOnly, and their
    //    values are still handed to your keyring, in an encoded form. If you call
    //    signAndIncludePrimaryKeysInEncryptionContext(true), they are signed like
    //    signAndIncludeInEncryptionContext instead: their values are handed to your keyring as
    //    plain text, and you can give other attributes the signAndIncludeInEncryptionContext
    //    action.

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
    final ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName("partition_key")
      .sortKeyName("sort_key")
      .encryptAndSign("attribute1")
      .signOnly("attribute2")
      .doNothingPrefix(":")
      .build();

    // 4. Create the configuration for the DynamoDB Item Encryptor
    final DynamoDbItemEncryptorConfig config = DynamoDbItemEncryptorConfig
      .builder()
      .logicalTableName(tableName)
      .schema(schema)
      .keyring(kmsKeyring)
      // Specifying an algorithm suite is not required,
      // but is done here to demonstrate how to do so.
      // We suggest using the
      // `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384` suite,
      // which includes AES-GCM with key derivation, signing, and key commitment.
      // This is also the default algorithm suite if one is not specified in this config.
      // For more information on supported algorithm suites, see:
      //   https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/supported-algorithms.html
      .algorithmSuiteId(
        AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384
      )
      .build();

    // 5. Create the DynamoDB Item Encryptor
    final DynamoDbItemEncryptor itemEncryptor = DynamoDbItemEncryptor
      .builder()
      .config(config)
      .build();

    // 6. Directly encrypt a DynamoDB item using the DynamoDB Item Encryptor
    final Map<String, AttributeValue> originalItem = new HashMap<>();
    originalItem.put(
      "partition_key",
      AttributeValue.builder().s("ItemEncryptDecryptExample").build()
    );
    originalItem.put("sort_key", AttributeValue.builder().n("0").build());
    originalItem.put(
      "attribute1",
      AttributeValue.builder().s("encrypt and sign me!").build()
    );
    originalItem.put(
      "attribute2",
      AttributeValue.builder().s("sign me!").build()
    );
    originalItem.put(
      ":attribute3",
      AttributeValue.builder().s("ignore me!").build()
    );
    final Map<String, AttributeValue> encryptedItem = itemEncryptor
      .encryptItem(originalItem)
      .encryptedItem();

    // Demonstrate that the item has been encrypted
    assert encryptedItem.get("partition_key").s().equals("ItemEncryptDecryptExample");
    assert encryptedItem.get("sort_key").n().equals("0");
    assert encryptedItem.get("attribute1").b() != null;

    // 7. Directly decrypt the encrypted item using the DynamoDB Item Encryptor
    final Map<String, AttributeValue> decryptedItem = itemEncryptor
      .decryptItem(encryptedItem)
      .plaintextItem();

    // Demonstrate that the item was decrypted successfully
    assert decryptedItem.get("partition_key").s().equals("ItemEncryptDecryptExample");
    assert decryptedItem.get("sort_key").n().equals("0");
    assert decryptedItem.get("attribute1").s().equals("encrypt and sign me!");
  }

  public static void main(final String[] args) {
    if (args.length < 2) {
      throw new IllegalArgumentException(
        "To run this example, include the kmsKeyId as args[0] and tableName as args[1]"
      );
    }
    final String kmsKeyId = args[0];
    final String tableName = args[1];
    encryptAndDecrypt(kmsKeyId, tableName);
  }
}
