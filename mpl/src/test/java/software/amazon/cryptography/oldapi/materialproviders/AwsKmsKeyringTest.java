// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;
import static software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.*;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.FakeKms;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsMrkKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;

// Differential tests of the AWS KMS keyring and the AWS KMS MRK keyring against the published Dafny-based MPL.
// Both sides call the same fake KMS; outcomes and the KMS requests sent are compared.
class AwsKmsKeyringTest {

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();
  private final FakeAws aws = FakeAws.start();
  private final KmsClient kms = ReferenceAws.kms(aws, REGION);

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
  //= type=test
  //# The AWS KMS key identifier MUST NOT be null or empty.
  //= spec/framework/aws-kms/aws-kms-keyring.md#initialization
  //= type=test
  //# The AWS KMS
  //# key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-
  //# valid-aws-kms-identifier).
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#initialization
  //= type=test
  //# The AWS KMS key identifier MUST NOT be null or empty.
  //# The AWS KMS
  //# key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-
  //# valid-aws-kms-identifier).
  //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
  //= type=test
  //# MUST start with string `arn`
  //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
  //= type=test
  //# The partition MUST be a non-empty
  //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
  //= type=test
  //# The service MUST be the string `kms`
  //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
  //= type=test
  //# The region MUST be a non-empty string
  //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
  //= type=test
  //# The account MUST be a non-empty string
  //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
  //= type=test
  //# The resource type MUST be either `alias` or `key`
  //= spec/framework/aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn
  //= type=test
  //# The resource id MUST be a non-empty string
  void create() {
    String arn = aws.kms().createSymmetricKey(REGION);
    List<String> keyIds = keyIdentifiers(arn);
    for (String keyId : keyIds) {
      for (List<String> grantTokens : grantTokenLists()) {
        CreateAwsKmsKeyringInput input = CreateAwsKmsKeyringInput.builder().kmsKeyId(keyId).kmsClient(kms).grantTokens(grantTokens).build();
        assertSame(
          aws,
          outcomes,
          "CreateAwsKmsKeyring",
          () -> created(ReferenceMpl.call(reference, "CreateAwsKmsKeyring", input)),
          () -> created(MPL.CreateAwsKmsKeyring(input)),
          keyId + " " + grantTokens
        );
        CreateAwsKmsMrkKeyringInput mrkInput = CreateAwsKmsMrkKeyringInput.builder().kmsKeyId(keyId).kmsClient(kms).grantTokens(grantTokens).build();
        assertSame(
          aws,
          outcomes,
          "CreateAwsKmsMrkKeyring",
          () -> created(ReferenceMpl.call(reference, "CreateAwsKmsMrkKeyring", mrkInput)),
          () -> created(MPL.CreateAwsKmsMrkKeyring(mrkInput)),
          keyId + " " + grantTokens
        );
      }
    }
    outcomes.assertBothSeen("CreateAwsKmsKeyring");
    outcomes.assertBothSeen("CreateAwsKmsMrkKeyring");
  }

  @Test
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# If the input [encryption materials](../structures.md#encryption-materials)
  //# do not contain a plaintext data key OnEncrypt MUST attempt
  //# to generate a new plaintext data key by calling [AWS KMS
  //# GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/
  //# API_GenerateDataKey.html).
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# If the input [encryption materials](../structures.md#encryption-
  //# materials) do contain a plaintext data key, OnEncrypt MUST attempt to
  //# encrypt the plaintext data key using the configured AWS KMS key
  //# identifier.
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# - the [key provider id](../structures.md#key-provider-id) MUST be
  //# "aws-kms".
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# - the [key provider information](../structures.md#key-provider-
  //# information) MUST be the response `KeyId`.
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# - the [ciphertext](../structures.md#ciphertext) MUST be the
  //# response `CiphertextBlob`.
  //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
  //= type=test
  //# - MUST set the plaintext data key on the [decryption materials]
  //# (../structures.md#decryption-materials) as the response
  //# `Plaintext`.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
  //= type=test
  //# If the input [encryption materials](../structures.md#encryption-
  //# materials) do not contain a plaintext data key OnEncrypt MUST attempt
  //# to generate a new plaintext data key by calling [AWS KMS
  //# GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/
  //# API_GenerateDataKey.html).
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
  //= type=test
  //# If the input [encryption materials](../structures.md#encryption-
  //# materials) do contain a plaintext data key, OnEncrypt MUST attempt to
  //# encrypt the plaintext data key using the configured AWS KMS key
  //# identifier.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
  //= type=test
  //# -  The the function [AWS KMS MRK Match for Decrypt](aws-kms-mrk-match-
  //# for-decrypt.md#implementation) called with the configured AWS KMS
  //# key identifier and the provider info MUST return `true`.
  void eachSideDecryptsTheOther() {
    String arn = aws.kms().createSymmetricKey(REGION);
    List<String> replicas = aws.kms().createMultiRegionKey(REGION, OTHER_REGION);
    aws.kms().createAlias("alias/named", arn);
    String keyId = arn.substring(arn.indexOf("key/") + 4);
    KmsClient otherKms = ReferenceAws.kms(aws, OTHER_REGION);
    List<String> grantTokens = Arrays.asList("token1", "token2");
    Pair byArn = keyring(false, arn, kms, grantTokens);
    Pair mrkByArn = keyring(true, replicas.get(0), kms, null);
    Pair mrkReplica = keyring(true, replicas.get(1), otherKms, null);
    Map<String, Pair> encryptors = new LinkedHashMap<>();
    encryptors.put("key ARN", byArn);
    encryptors.put("key id", keyring(false, keyId, kms, null));
    encryptors.put("alias", keyring(false, "alias/named", kms, null));
    encryptors.put("alias ARN", keyring(false, arn.replace("key/" + keyId, "alias/named"), kms, null));
    encryptors.put("MRK keyring, key ARN", keyring(true, arn, kms, grantTokens));
    encryptors.put("MRK keyring, multi-Region key", mrkByArn);
    for (Map.Entry<String, Pair> encryptor : encryptors.entrySet()) {
      boolean multiRegion = encryptor.getValue() == mrkByArn;
      List<Pair> decryptors = multiRegion ? Arrays.asList(mrkByArn, mrkReplica) : Arrays.asList(byArn, keyring(true, arn, kms, null));
      for (AlgorithmSuiteId suite : allSuites()) {
        for (Map<String, String> encryptionContext : Arrays.asList(map(), map("a", "b", "\u00fc", "\ud83d\ude00"))) {
          for (boolean withDataKey : new boolean[] { false, true }) {
            EncryptionMaterials start = encryptionMaterials(suite, encryptionContext, withDataKey);
            String context = encryptor.getKey() + " " + ReferenceMpl.describe(suite) + " " + encryptionContext + " data key " + withDataKey;
            assertSameEncrypt(aws, outcomes, encryptor.getValue(), start, context);
            for (EncryptionMaterials result : Arrays.asList(encryptor.getValue().nativeEncrypt(start), encryptor.getValue().referenceEncrypt(start))) {
              for (Pair decryptor : decryptors) {
                String decrypted = assertSameDecrypt(aws, outcomes, decryptor, decryptionMaterials(result), result.encryptedDataKeys(), context);
                assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context);
              }
            }
          }
        }
      }
    }
  }

  @Test
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# If the call to [AWS KMS GenerateDataKey]
  //# (https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)
  //# does not succeed, OnEncrypt MUST NOT modify
  //# the [encryption materials](../structures.md#encryption-materials) and
  //# MUST fail.
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# The Generate Data Key response’s `KeyId` MUST be [a
  //# valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that
  //# the response `Plaintext` length matches the specification of the
  //# [algorithm suite](../algorithm-suites.md)'s Key Derivation Input
  //# Length field.
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# If the call to [AWS KMS Encrypt]
  //# (https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html)
  //# does not succeed, OnEncrypt MUST fail.
  //= spec/framework/aws-kms/aws-kms-keyring.md#onencrypt
  //= type=test
  //# If the Encrypt call succeeds the response’s `KeyId` MUST be
  //# [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
  //= type=test
  //# If the call to [AWS KMS GenerateDataKey]
  //# (https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) does not succeed,
  //# OnEncrypt MUST NOT modify the [encryption materials]
  //# (../structures.md#encryption-materials) and MUST fail.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
  //= type=test
  //# The Generate Data Key response’s `KeyId` MUST be [A valid AWS
  //# KMS key ARN](aws-kms-key-arn.md#identifying-an-aws-kms-
  //# multi-region-key).
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
  //= type=test
  //# If the Generate Data Key call succeeds, OnEncrypt MUST
  //# verify that the response `Plaintext` length matches the specification
  //# of the [algorithm suite](../algorithm-suites.md)'s Key Derivation Input Length field.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
  //= type=test
  //# If the call to [AWS KMS Encrypt]
  //# (https://docs.aws.amazon.com/kms/latest/APIReference/
  //# API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#onencrypt
  //= type=test
  //# If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid
  //# AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn).
  void encryptFailures() {
    String arn = aws.kms().createSymmetricKey(REGION);
    String prefix = arn.substring(0, arn.indexOf("key/"));
    Map<String, ServiceError> errors = serviceErrors();
    Map<String, UnaryOperator<ObjectNode>> generateEdits = new LinkedHashMap<>();
    generateEdits.put("no KeyId", r -> remove(r, "KeyId"));
    generateEdits.put("KeyId not an identifier", r -> r.put("KeyId", "foo/bar"));
    generateEdits.put("KeyId an alias", r -> r.put("KeyId", "alias/other"));
    generateEdits.put("KeyId non-ASCII", r -> r.put("KeyId", prefix + "key/\u00e9"));
    generateEdits.put("KeyId not UTF-16", r -> r.put("KeyId", prefix + "key/a\uD800b"));
    generateEdits.put("KeyId 65535 bytes", r -> r.put("KeyId", prefix + "key/" + repeat('a', 65535 - prefix.length() - 4)));
    generateEdits.put("KeyId 65536 bytes", r -> r.put("KeyId", prefix + "key/" + repeat('a', 65536 - prefix.length() - 4)));
    generateEdits.put("no Plaintext", r -> remove(r, "Plaintext"));
    generateEdits.put("empty Plaintext", r -> r.put("Plaintext", ""));
    generateEdits.put("short Plaintext", r -> r.put("Plaintext", base64(Arrays.copyOf(decode(r, "Plaintext"), decode(r, "Plaintext").length - 1))));
    generateEdits.put("long Plaintext", r -> r.put("Plaintext", base64(Arrays.copyOf(decode(r, "Plaintext"), decode(r, "Plaintext").length + 1))));
    generateEdits.put("no CiphertextBlob", r -> remove(r, "CiphertextBlob"));
    generateEdits.put("empty CiphertextBlob", r -> r.put("CiphertextBlob", ""));
    generateEdits.put("CiphertextBlob 6144 bytes", r -> r.put("CiphertextBlob", base64(new byte[6144])));
    generateEdits.put("CiphertextBlob 6145 bytes", r -> r.put("CiphertextBlob", base64(new byte[6145])));
    generateEdits.put("CiphertextForRecipient", r -> r.put("CiphertextForRecipient", base64(new byte[3])));
    Map<String, UnaryOperator<ObjectNode>> encryptEdits = new LinkedHashMap<>();
    encryptEdits.put("no KeyId", r -> remove(r, "KeyId"));
    encryptEdits.put("KeyId not an identifier", r -> r.put("KeyId", "arn:aws:kms"));
    encryptEdits.put("KeyId a key id", r -> r.put("KeyId", "1234"));
    encryptEdits.put("KeyId 65536 bytes", r -> r.put("KeyId", prefix + "key/" + repeat('a', 65536 - prefix.length() - 4)));
    encryptEdits.put("no CiphertextBlob", r -> remove(r, "CiphertextBlob"));
    encryptEdits.put("empty CiphertextBlob", r -> r.put("CiphertextBlob", ""));

    for (boolean mrk : new boolean[] { false, true }) {
      Pair keyrings = keyring(mrk, arn, kms, Collections.singletonList("token"));
      Pair missing = keyring(mrk, prefix + "key/no-such-key", kms, null);
      for (AlgorithmSuiteId suite : allSuites()) {
        for (boolean withDataKey : new boolean[] { false, true }) {
          EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), withDataKey);
          String context = "mrk " + mrk + " " + ReferenceMpl.describe(suite) + " data key " + withDataKey;
          assertSameEncrypt(aws, outcomes, missing, start, context + " missing key");
          for (String operation : Arrays.asList("GenerateDataKey", "Encrypt")) {
            for (Map.Entry<String, ServiceError> error : errors.entrySet()) {
              aws.kms().fail(operation, null, error.getValue());
              assertSameEncrypt(aws, outcomes, keyrings, start, context + " " + operation + " " + error.getKey());
              aws.kms().clearFailures();
            }
            for (Map.Entry<String, UnaryOperator<ObjectNode>> edit : (operation.equals("Encrypt") ? encryptEdits : generateEdits).entrySet()) {
              aws.kms().editResponses(operation, edit.getValue());
              assertSameEncrypt(aws, outcomes, keyrings, start, context + " " + operation + " " + edit.getKey());
              aws.kms().clearFailures();
            }
          }
        }
        assertSameEncrypt(aws, outcomes, keyrings, encryptionMaterials(suite, map(), false), "empty context");
        for (EncryptionMaterials materials : invalidEncryptionMaterials(suite)) {
          assertSameEncrypt(aws, outcomes, keyrings, materials, "invalid materials");
        }
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  @Test
  //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
  //= type=test
  //# If the [decryption materials](../structures.md#decryption-materials)
  //# already contained a valid plaintext data key OnDecrypt MUST return an
  //# error.
  //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
  //= type=test
  //# - Its provider ID MUST exactly match the value “aws-kms”.
  //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
  //= type=test
  //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-
  //# arn.md#a-valid-aws-kms-arn) with a resource type of `key` or
  //# OnDecrypt MUST fail.
  //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
  //= type=test
  //# - The provider info MUST match the configured AWS KMS key
  //# identifier.
  //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
  //= type=test
  //# If the response does not satisfies these requirements then an error
  //# MUST be collected and the next encrypted data key in the filtered set
  //# MUST be attempted.
  //= spec/framework/aws-kms/aws-kms-keyring.md#ondecrypt
  //= type=test
  //# If OnDecrypt fails to successfully decrypt any [encrypted data key]
  //# (../structures.md#encrypted-data-key), then it MUST yield an error
  //# that includes all the collected errors.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
  //= type=test
  //# -  Its provider ID MUST exactly match the value “aws-kms”.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
  //= type=test
  //# -  The provider info MUST be a [valid AWS KMS ARN](aws-kms-key-
  //# arn.md#a-valid-aws-kms-arn) with a resource type of `key` or
  //# OnDecrypt MUST fail.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
  //= type=test
  //# -  The the function [AWS KMS MRK Match for Decrypt](aws-kms-mrk-match-
  //# for-decrypt.md#implementation) called with the configured AWS KMS
  //# key identifier and the provider info MUST return `true`.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
  //= type=test
  //# If the response does not satisfies these requirements then an error
  //# MUST be collected and the next encrypted data key in the filtered set
  //# MUST be attempted.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
  //= type=test
  //# - The `KeyId` field in the response MUST equal the configured AWS
  //# KMS key identifier.
  //= spec/framework/aws-kms/aws-kms-mrk-keyring.md#ondecrypt
  //= type=test
  //# - The length of the response’s `Plaintext` MUST equal the [key
  //# derivation input length](../algorithm-suites.md#key-derivation-
  //# input-length) specified by the [algorithm suite](../algorithm-
  //# suites.md) included in the input [decryption materials]
  //# (../structures.md#decryption-materials).
  void decryptFailures() {
    String arn = aws.kms().createSymmetricKey(REGION);
    String otherArn = aws.kms().createSymmetricKey(REGION);
    List<String> replicas = aws.kms().createMultiRegionKey(REGION, OTHER_REGION);
    aws.kms().createAlias("alias/named", arn);
    String prefix = arn.substring(0, arn.indexOf("key/"));
    KmsClient otherKms = ReferenceAws.kms(aws, OTHER_REGION);
    Map<String, Pair> keyrings = new LinkedHashMap<>();
    keyrings.put("key", keyring(false, arn, kms, Collections.singletonList("token")));
    keyrings.put("MRK keyring, key", keyring(true, arn, kms, null));
    keyrings.put("multi-Region key", keyring(false, replicas.get(0), kms, null));
    keyrings.put("MRK keyring, multi-Region key", keyring(true, replicas.get(0), kms, null));
    keyrings.put("key id", keyring(false, arn.substring(arn.indexOf("key/") + 4), kms, null));
    keyrings.put("MRK keyring, multi-Region key id", keyring(true, replicas.get(0).substring(arn.indexOf("key/") + 4), kms, null));
    keyrings.put("alias", keyring(false, "alias/named", kms, null));
    keyrings.put("alias ARN", keyring(true, prefix + "alias/named", kms, null));
    Pair encryptor = keyring(false, arn, kms, null);
    Pair otherEncryptor = keyring(false, otherArn, kms, null);
    Pair replicaEncryptor = keyring(true, replicas.get(1), otherKms, null);
    for (AlgorithmSuiteId suite : allSuites()) {
      EncryptionMaterials encrypted = encryptor.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false).toBuilder().plaintextDataKey(encrypted.plaintextDataKey()).build();
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      EncryptedDataKey other = otherEncryptor.nativeEncrypt(start).encryptedDataKeys().get(0);
      EncryptedDataKey replica = replicaEncryptor.nativeEncrypt(start).encryptedDataKeys().get(0);
      byte[] ciphertext = array(good.ciphertext());
      byte[] info = array(good.keyProviderInfo());
      DecryptionMaterials materials = decryptionMaterials(encrypted);

      List<List<EncryptedDataKey>> edkLists = new ArrayList<>();
      edkLists.add(Collections.emptyList());
      edkLists.add(Collections.singletonList(good));
      edkLists.add(Collections.singletonList(other));
      edkLists.add(Collections.singletonList(replica));
      edkLists.add(Arrays.asList(other, good));
      edkLists.add(Arrays.asList(good, other));
      edkLists.add(Arrays.asList(replica, good));
      edkLists.add(Collections.singletonList(edk("other", info, ciphertext)));
      edkLists.add(Collections.singletonList(edk("aws-kms-x", info, ciphertext)));
      edkLists.add(Arrays.asList(edk("raw", new byte[] { (byte) 0xff }, ciphertext), good));
      edkLists.add(Collections.singletonList(edk("raw", new byte[] { (byte) 0xff }, ciphertext)));
      // Encoded surrogate: not UTF-8.
      edkLists.add(Collections.singletonList(edk("raw", new byte[] { (byte) 0xed, (byte) 0xa0, (byte) 0x80 }, ciphertext)));
      edkLists.add(Arrays.asList(good, edk("aws-kms", new byte[] { (byte) 0xff }, ciphertext)));
      edkLists.add(Collections.singletonList(edk("aws-kms", new byte[] { (byte) 0xff }, ciphertext)));
      for (String providerInfo : Arrays.asList("not an arn", "arm" + arn.substring(3), prefix + "alias/named", "key/abc", prefix + "key/", "arn:aws:kms:" + REGION + ":x:key/a:b", prefix.replace("arn:aws", "arn:aws-cn") + arn.substring(prefix.length()))) {
        edkLists.add(Arrays.asList(edk("aws-kms", providerInfo.getBytes(StandardCharsets.UTF_8), ciphertext), good));
      }
      // Near matches: same key id elsewhere; a multi-Region key in another account, partition, or region.
      String replicaArn = replicas.get(0);
      for (String providerInfo : Arrays.asList(
        arn.replace(REGION, OTHER_REGION),
        replicaArn.replace(FakeKms.ACCOUNT, "444455556666"),
        replicaArn.replace("arn:aws:", "arn:aws-cn:"),
        replicaArn.replace(REGION, "ap-south-2"),
        replicaArn.replace("key/mrk-", "key/mrk-1")
      )) {
        edkLists.add(Collections.singletonList(edk("aws-kms", providerInfo.getBytes(StandardCharsets.UTF_8), ciphertext)));
      }
      // Hierarchical keyring keys only show in the message listing the keys that did not match.
      for (int length : new int[] { 0, 47, 48, 48 + 43, 48 + 44, 100 }) {
        edkLists.add(Collections.singletonList(edk("aws-kms-hierarchy", "branch".getBytes(StandardCharsets.UTF_8), bytes(length, 7))));
      }
      // The ciphertext: wrong key, tampered, empty, too long, too short for intermediate wrapping.
      edkLists.add(Collections.singletonList(edk("aws-kms", info, array(other.ciphertext()))));
      edkLists.add(Collections.singletonList(edk("aws-kms", info, flip(ciphertext, ciphertext.length - 1))));
      edkLists.add(Arrays.asList(edk("aws-kms", info, flip(ciphertext, ciphertext.length - 1)), good));
      for (int length : new int[] { 0, 1, 47, 48, 49 }) {
        edkLists.add(Collections.singletonList(edk("aws-kms", info, Arrays.copyOf(ciphertext, Math.min(length, ciphertext.length)))));
      }
      edkLists.add(Collections.singletonList(edk("aws-kms", info, new byte[6145])));
      edkLists.add(Collections.singletonList(edk("aws-kms", info, Arrays.copyOf(ciphertext, 48 + 6144))));
      edkLists.add(Collections.singletonList(edk("aws-kms", info, Arrays.copyOf(ciphertext, 48 + 6145))));

      for (Map.Entry<String, Pair> keyring : keyrings.entrySet()) {
        String context = keyring.getKey() + " " + ReferenceMpl.describe(suite);
        for (List<EncryptedDataKey> edks : edkLists) {
          assertSameDecrypt(aws, outcomes, keyring.getValue(), materials, edks, context);
        }
      }
      Pair keyring = keyrings.get("MRK keyring, key");
      String context = ReferenceMpl.describe(suite);
      List<EncryptedDataKey> goodOnly = Collections.singletonList(good);
      for (Map.Entry<String, ServiceError> error : serviceErrors().entrySet()) {
        aws.kms().fail("Decrypt", null, error.getValue());
        assertSameDecrypt(aws, outcomes, keyring, materials, goodOnly, context + " " + error.getKey());
        assertSameDecrypt(aws, outcomes, keyring, materials, Arrays.asList(good, good), context + " twice " + error.getKey());
        aws.kms().clearFailures();
      }
      Map<String, UnaryOperator<ObjectNode>> edits = new LinkedHashMap<>();
      edits.put("no KeyId", r -> remove(r, "KeyId"));
      edits.put("other KeyId", r -> r.put("KeyId", otherArn));
      edits.put("KeyId of another region", r -> r.put("KeyId", arn.replace(REGION, OTHER_REGION)));
      edits.put("no Plaintext", r -> remove(r, "Plaintext"));
      edits.put("short Plaintext", r -> r.put("Plaintext", base64(Arrays.copyOf(decode(r, "Plaintext"), decode(r, "Plaintext").length - 1))));
      edits.put("long Plaintext", r -> r.put("Plaintext", base64(Arrays.copyOf(decode(r, "Plaintext"), decode(r, "Plaintext").length + 1))));
      for (Map.Entry<String, UnaryOperator<ObjectNode>> edit : edits.entrySet()) {
        aws.kms().editResponses("Decrypt", edit.getValue());
        assertSameDecrypt(aws, outcomes, keyring, materials, goodOnly, context + " " + edit.getKey());
        aws.kms().clearFailures();
      }
      // The encryption context is sent to KMS.
      assertSameDecrypt(aws, outcomes, keyring, decryptionMaterials(encrypted, map("a", "c")), goodOnly, context + " other context");
      // Materials that are not valid, or already hold a data key.
      DecryptionMaterials missingRequired = materials.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build();
      assertSameDecrypt(aws, outcomes, keyring, missingRequired, goodOnly, context + " invalid");
      DecryptionMaterials decrypted = keyring.nativeDecrypt(materials, goodOnly);
      assertSameDecrypt(aws, outcomes, keyring, decrypted, goodOnly, context + " has data key");
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  /** Materials a keyring must reject, and some it must accept, for {@code suite}. */
  static List<EncryptionMaterials> invalidEncryptionMaterials(AlgorithmSuiteId suite) {
    EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
    EncryptionMaterials withKey = encryptionMaterials(suite, map("a", "b"), true);
    int dataKeyLength = array(withKey.plaintextDataKey()).length;
    List<EncryptionMaterials> pool = new ArrayList<>();
    pool.add(start.toBuilder().plaintextDataKey(ByteBuffer.wrap(bytes(dataKeyLength + 1, 3))).build());
    pool.add(start.toBuilder().plaintextDataKey(ByteBuffer.wrap(bytes(dataKeyLength - 1, 3))).build());
    pool.add(start.toBuilder().encryptionContext(map()).build());
    pool.add(start.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build());
    pool.add(start.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("a")).build());
    pool.add(start.toBuilder().encryptedDataKeys(Collections.singletonList(edk("x", new byte[0], new byte[0]))).build());
    pool.add(start.toBuilder().signingKey(start.signingKey() == null ? ByteBuffer.wrap(bytes(48, 1)) : null).build());
    pool.add(withKey.toBuilder().encryptedDataKeys(Collections.singletonList(edk("x", new byte[0], new byte[0]))).build());
    pool.add(start.toBuilder().symmetricSigningKeys(Collections.singletonList(ByteBuffer.wrap(bytes(32, 1)))).build());
    return pool;
  }

  /** KMS errors to inject: modeled and unmodeled, retryable and not. */
  static Map<String, ServiceError> serviceErrors() {
    Map<String, ServiceError> errors = new LinkedHashMap<>();
    errors.put("not found", ServiceError.of("NotFoundException", "no such key"));
    errors.put("access denied", ServiceError.accessDenied("not allowed"));
    errors.put("throttling", ServiceError.throttling("slow down"));
    errors.put("limit exceeded", ServiceError.of("LimitExceededException", "too many"));
    errors.put("disabled", ServiceError.of("DisabledException", "disabled"));
    errors.put("invalid state", ServiceError.of("KMSInvalidStateException", "pending deletion"));
    errors.put("internal", ServiceError.of("KMSInternalException", "internal"));
    errors.put("invalid grant token", ServiceError.of("InvalidGrantTokenException", "bad token"));
    errors.put("invalid ciphertext", ServiceError.of("InvalidCiphertextException", null));
    errors.put("unmodeled", ServiceError.of("SomethingNewException", "new"));
    return errors;
  }

  static ObjectNode remove(ObjectNode response, String field) {
    response.remove(field);
    return response;
  }

  static byte[] decode(ObjectNode response, String field) {
    return Base64.getDecoder().decode(response.get(field).asText());
  }

  static String base64(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  private Pair keyring(boolean mrk, String keyId, KmsClient client, List<String> grantTokens) {
    if (mrk) {
      CreateAwsKmsMrkKeyringInput input = CreateAwsKmsMrkKeyringInput.builder().kmsKeyId(keyId).kmsClient(client).grantTokens(grantTokens).build();
      return new Pair(MPL.CreateAwsKmsMrkKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMrkKeyring", input));
    }
    CreateAwsKmsKeyringInput input = CreateAwsKmsKeyringInput.builder().kmsKeyId(keyId).kmsClient(client).grantTokens(grantTokens).build();
    return new Pair(MPL.CreateAwsKmsKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsKeyring", input));
  }

  /** Valid and invalid key identifiers: every ARN-parsing and length branch. */
  static List<String> keyIdentifiers(String arn) {
    String prefix = "arn:aws:kms:" + REGION + ":" + FakeKms.ACCOUNT + ":";
    return Arrays.asList(
      arn,
      prefix + "alias/name",
      prefix + "key/mrk-1234",
      prefix + "key/a/b",
      prefix + "key/",
      prefix + "key",
      prefix + "other/a",
      prefix + "key/a:b",
      "arn:aws:kms:" + REGION + ":" + FakeKms.ACCOUNT,
      "arn:",
      "arn::kms:" + REGION + ":" + FakeKms.ACCOUNT + ":key/a",
      "arn:aws:s3:" + REGION + ":" + FakeKms.ACCOUNT + ":key/a",
      "arn:aws:kms::" + FakeKms.ACCOUNT + ":key/a",
      "arn:aws:kms:" + REGION + "::key/a",
      "ARN:aws:kms:" + REGION + ":" + FakeKms.ACCOUNT + ":key/a",
      "arnx:aws:kms",
      "00000000-0000-4000-8000-000000000001",
      "mrk-1234",
      "alias/name",
      "alias/",
      "alias",
      "key/abc",
      "foo/bar",
      "",
      "/",
      "alias/é",
      "alias/a\uD800b",
      // Parse failure and non-ASCII: ValidateKmsKeyId reports the parse failure first.
      "key/\u00e9",
      "\u00e9/x",
      "alias/" + repeat('a', 2042),
      "alias/" + repeat('a', 2043),
      prefix + "key/" + repeat('a', 4000)
    );
  }

  static List<List<String>> grantTokenLists() {
    List<String> ten = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      ten.add("token" + i);
    }
    List<String> eleven = new ArrayList<>(ten);
    eleven.add("token10");
    return Arrays.asList(
      null,
      Collections.<String>emptyList(),
      Collections.singletonList("token"),
      ten,
      eleven,
      Collections.singletonList(""),
      Collections.singletonList(repeat('t', 8192)),
      Arrays.asList("token", repeat('t', 8193))
    );
  }

  static String created(Object keyring) {
    return keyring == null ? "null" : "keyring";
  }
}
