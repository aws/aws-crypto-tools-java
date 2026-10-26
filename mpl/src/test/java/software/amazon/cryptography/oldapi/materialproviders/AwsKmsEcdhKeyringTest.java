// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.base64;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.decode;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.grantTokenLists;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.invalidEncryptionMaterials;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.remove;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.serviceErrors;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;
import static software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.*;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.compressed;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.compressedLength;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.concat;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.curveOf;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.generatePublicKey;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.namedCurve;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.pem;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.providerInfo;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.spki;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.withUint32;
import static software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.zeroXKey;

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
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.RawEcdhKeyringTest.Keys;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.RecordedRequest;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.oldapi.materialproviders.internal.Convert;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsEcdhKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRawEcdhKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EphemeralPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.oldapi.materialproviders.model.KmsEcdhStaticConfigurations;
import software.amazon.cryptography.oldapi.materialproviders.model.KmsPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.oldapi.materialproviders.model.KmsPublicKeyDiscoveryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.PublicKeyDiscoveryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.RawEcdhStaticConfigurations;
import software.amazon.cryptography.oldapi.materialproviders.model.RawPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.ECDHCurveSpec;

// Differential tests of the AWS KMS ECDH keyring against the published Dafny-based MPL.
// Both sides call the same fake KMS (GetPublicKey, DeriveSharedSecret); outcomes and the KMS requests sent are compared.
// Encryption is randomized (salt, data key), so each side decrypts both sides' encrypted data keys,
// also with raw ECDH keyrings holding the local half of a key pair.
class AwsKmsEcdhKeyringTest {

  private static final List<ECDHCurveSpec> NIST = Arrays.asList(ECDHCurveSpec.ECC_NIST_P256, ECDHCurveSpec.ECC_NIST_P384, ECDHCurveSpec.ECC_NIST_P521);

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();
  private final FakeAws aws = FakeAws.start();
  private final KmsClient kms = ReferenceAws.kms(aws, REGION);

  @AfterEach
  void close() {
    aws.close();
  }

  //= spec/framework/key-agreement-schemas.md#kmspublickeydiscovery
  //= type=test
  //# the keyring MUST call
  //# `kms:GetPublicKey` on the recipient's configured KMS key ID.

  //= spec/framework/key-agreement-schemas.md#kmspublickeydiscovery
  //= type=test
  //# If the keyring fails to retrieve the public key, the keyring MUST fail.

  //= spec/framework/key-agreement-schemas.md#kmsprivatekeytostaticpublickey
  //= type=test
  //# On initialization, if the keyring is not configured with
  //# a sender public key, the keyring MUST call
  //# `kms:GetPublicKey` on the sender's configured KMS key ID.

  //= spec/framework/key-agreement-schemas.md#kmsprivatekeytostaticpublickey
  //= type=test
  //# If the keyring fails to retrieve the public key, the keyring MUST fail.
  @Test
  void create() {
    for (ECDHCurveSpec curve : NIST) {
      String sender = eccKey(curve);
      String recipient = eccKey(curve);
      String prefix = sender.substring(0, sender.indexOf("key/"));
      aws.kms().createAlias("alias/ecdh-" + curve, sender);
      ECDHCurveSpec otherCurve = NIST.get((NIST.indexOf(curve) + 1) % NIST.size());
      List<String> identifiers = Arrays.asList(
        sender,
        sender.substring(sender.indexOf("key/") + 4),
        "alias/ecdh-" + curve,
        prefix + "alias/ecdh-" + curve,
        "",
        prefix + "key/\u00e9",
        "arn:aws:kms",
        prefix + "key/no-such-key",
        aws.kms().createSymmetricKey(REGION),
        aws.kms().createRsaKey(REGION, "RSA_2048"),
        eccKey(otherCurve),
        prefix + "key/" + repeat('a', 2048)
      );
      List<byte[]> publicKeys = publicKeyVariants(curve, publicKey(recipient));
      List<byte[]> senderKeys = Arrays.asList(publicKey(sender), publicKey(recipient), new byte[0], bytes(20, 0x41), publicKey(eccKey(otherCurve)), new byte[8193]);
      List<KmsEcdhStaticConfigurations> schemes = new ArrayList<>();
      for (String identifier : identifiers) {
        schemes.add(discovery(identifier));
        for (byte[] publicKey : Arrays.asList(publicKey(recipient), new byte[0], bytes(20, 0x41))) {
          schemes.add(kmsPrivate(identifier, null, publicKey));
        }
        schemes.add(kmsPrivate(identifier, publicKey(sender), publicKey(recipient)));
        schemes.add(kmsPrivate(identifier, new byte[0], new byte[0]));
      }
      for (byte[] publicKey : publicKeys) {
        schemes.add(kmsPrivate(sender, null, publicKey));
        for (byte[] senderKey : senderKeys) {
          schemes.add(kmsPrivate(sender, senderKey, publicKey));
        }
      }
      for (KmsEcdhStaticConfigurations scheme : schemes) {
        for (ECDHCurveSpec configured : Arrays.asList(curve, otherCurve, ECDHCurveSpec.SM2)) {
          assertSameCreate(input(configured, scheme, null), curve + " " + configured);
        }
      }
      for (List<String> tokens : grantTokenLists()) {
        assertSameCreate(input(curve, discovery(recipient), tokens), curve + " tokens " + tokens);
        assertSameCreate(input(curve, kmsPrivate(sender, null, publicKey(recipient)), tokens), curve + " tokens " + tokens);
      }
      // GetPublicKey failures and malformed responses, for discovery and for a sender without its public key.
      List<KmsEcdhStaticConfigurations> fetching = Arrays.asList(discovery(recipient), kmsPrivate(sender, null, publicKey(recipient)));
      for (Map.Entry<String, ServiceError> error : serviceErrors().entrySet()) {
        aws.kms().fail("GetPublicKey", null, error.getValue());
        for (KmsEcdhStaticConfigurations scheme : fetching) {
          assertSameCreate(input(curve, scheme, null), curve + " " + error.getKey());
        }
        aws.kms().clearFailures();
      }
      for (Map.Entry<String, UnaryOperator<ObjectNode>> edit : getPublicKeyEdits(curve, otherCurve, recipient).entrySet()) {
        aws.kms().editResponses("GetPublicKey", edit.getValue());
        for (KmsEcdhStaticConfigurations scheme : fetching) {
          assertSameCreate(input(curve, scheme, null), curve + " " + edit.getKey());
        }
        aws.kms().clearFailures();
      }
    }
    outcomes.assertBothSeen("CreateAwsKmsEcdhKeyring");
  }

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
  //= type=test
  //# The keyring MUST perform data key wrapping according to the [Data Key Wrapping section](../raw-ecdh-keyring.md#data-key-wrapping).

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
  //= type=test
  //# - The [key provider id](../structures.md#key-provider-id) MUST be the UTF8 encoded string "aws-kms-ecdh".

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
  //= type=test
  //# The keyring MUST derive the shared secret
  //# by calling [AWS KMS DeriveSharedSecret]()

  //= spec/framework/key-agreement-schemas.md#kmsprivatekeytostaticpublickey
  //= type=test
  //# - MUST verify that both the configured sender's and recipient's
  //#   public keys match the public keys stored on the message ciphertext.

  //= spec/framework/key-agreement-schemas.md#kmspublickeydiscovery
  //= type=test
  //# - MUST verify that the configured recipient's public key
  //#   matches the public key stored on the message ciphertext.
  @Test
  void eachSideDecryptsTheOther() {
    for (ECDHCurveSpec curve : NIST) {
      String a = eccKey(curve);
      String b = eccKey(curve);
      Keys local = Keys.of("testVectorKeys", curve);
      List<String> tokens = Arrays.asList("token1", "token2");
      Pair aToB = kmsEcdh(input(curve, kmsPrivate(a, null, publicKey(b)), tokens));
      Pair aToBWithKey = kmsEcdh(input(curve, kmsPrivate(a, publicKey(a), publicKey(b)), null));
      Pair bToA = kmsEcdh(input(curve, kmsPrivate(b, null, publicKey(a)), null));
      Pair discoveryA = kmsEcdh(input(curve, discovery(a), null));
      Pair discoveryB = kmsEcdh(input(curve, discovery(b), tokens));
      Pair aToLocal = kmsEcdh(input(curve, kmsPrivate(a, null, local.senderPublic), null));
      Pair localToA = rawEcdh(curve, RawEcdhStaticConfigurations.builder().RawPrivateKeyToStaticPublicKey(
        RawPrivateKeyToStaticPublicKeyInput.builder().senderStaticPrivateKey(ByteBuffer.wrap(local.senderPrivate)).recipientPublicKey(ByteBuffer.wrap(publicKey(a))).build()
      ).build());
      Pair ephemeralToA = rawEcdh(curve, RawEcdhStaticConfigurations.builder().EphemeralPrivateKeyToStaticPublicKey(
        EphemeralPrivateKeyToStaticPublicKeyInput.builder().recipientPublicKey(ByteBuffer.wrap(publicKey(a))).build()
      ).build());
      Pair localDiscovery = rawEcdh(curve, RawEcdhStaticConfigurations.builder().PublicKeyDiscovery(
        PublicKeyDiscoveryInput.builder().recipientStaticPrivateKey(ByteBuffer.wrap(local.senderPrivate)).build()
      ).build());
      // Encryptor -> {decryptors that must succeed, decryptors that must fail}.
      Map<Pair, List<List<Pair>>> cases = new LinkedHashMap<>();
      cases.put(aToB, Arrays.asList(Arrays.asList(aToB, aToBWithKey, bToA, discoveryB), Arrays.asList(discoveryA, aToLocal)));
      cases.put(aToBWithKey, Arrays.asList(Arrays.asList(aToB, bToA, discoveryB), Collections.singletonList(discoveryA)));
      cases.put(aToLocal, Arrays.asList(Arrays.asList(aToLocal, localToA, localDiscovery), Arrays.asList(discoveryA, aToB)));
      cases.put(localToA, Arrays.asList(Arrays.asList(aToLocal, discoveryA), Collections.singletonList(discoveryB)));
      cases.put(ephemeralToA, Arrays.asList(Collections.singletonList(discoveryA), Arrays.asList(aToLocal, discoveryB)));
      for (AlgorithmSuiteId suite : allSuites()) {
        for (Map<String, String> encryptionContext : Arrays.asList(map(), map("a", "b", "\u00fc", "\ud83d\ude00"))) {
          for (boolean withDataKey : new boolean[] { false, true }) {
            EncryptionMaterials start = encryptionMaterials(suite, encryptionContext, withDataKey);
            String context = curve + " " + ReferenceMpl.describe(suite) + " " + encryptionContext + " data key " + withDataKey;
            for (Map.Entry<Pair, List<List<Pair>>> entry : cases.entrySet()) {
              Pair encryptor = entry.getKey();
              int random = encryptor == ephemeralToA ? compressedLength(curve) : 0;
              assertSameEcdhEncrypt(encryptor, start, context, random);
              for (EncryptionMaterials result : Arrays.asList(encryptor.nativeEncrypt(start), encryptor.referenceEncrypt(start))) {
                DecryptionMaterials materials = decryptionMaterials(result);
                for (Pair decryptor : entry.getValue().get(0)) {
                  String decrypted = assertSameDecrypt(aws, outcomes, decryptor, materials, result.encryptedDataKeys(), context);
                  assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context);
                }
                for (Pair decryptor : entry.getValue().get(1)) {
                  assertTrue(assertSameDecrypt(aws, outcomes, decryptor, materials, result.encryptedDataKeys(), context).startsWith("throws"), context);
                }
              }
            }
          }
        }
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  //= spec/framework/key-agreement-schemas.md#key-derivation
  //= type=test
  //# Before deriving a shared wrapping key, the keyring MUST generate a 32 byte random salt value.
  // The IV is zero and a static keyring's shared secret is fixed: only the salt (and the data key) make each encryption new.
  @Test
  void everyEncryptionIsFresh() {
    for (ECDHCurveSpec curve : NIST) {
      String a = eccKey(curve);
      Pair keyring = kmsEcdh(input(curve, kmsPrivate(a, null, publicKey(eccKey(curve))), null));
      for (AlgorithmSuiteId suite : failureSuites()) {
        EncryptionMaterials withKey = encryptionMaterials(suite, map("a", "b"), true);
        int saltStart = Convert.suite(suite).usesIntermediateKeyWrapping() ? array(withKey.plaintextDataKey()).length + 16 : 0;
        byte[] first = array(keyring.nativeEncrypt(withKey).encryptedDataKeys().get(0).ciphertext());
        byte[] second = array(keyring.nativeEncrypt(withKey).encryptedDataKeys().get(0).ciphertext());
        assertFalse(Arrays.equals(Arrays.copyOfRange(first, saltStart, saltStart + 32), Arrays.copyOfRange(second, saltStart, saltStart + 32)), "salt repeated");
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
        assertFalse(Arrays.equals(array(keyring.nativeEncrypt(start).plaintextDataKey()), array(keyring.nativeEncrypt(start).plaintextDataKey())), "data key repeated");
      }
    }
  }

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
  //= type=test
  //# OnEncrypt MUST fail if configured with a
  //# [KmsPublicKeyDiscovery Key Agreement Configuration](../key-agreement-schemas.md#kmspublickeydiscovery)

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
  //= type=test
  //# If the keyring cannot serialize
  //# the encryption context, OnEncrypt MUST fail.

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#onencrypt
  //= type=test
  //# If the call to KMS DeriveSharedSecret fails, the keyring MUST fail.
  @Test
  void encryptFailures() {
    ECDHCurveSpec curve = ECDHCurveSpec.ECC_NIST_P256;
    String a = eccKey(curve);
    String b = eccKey(curve);
    Pair keyring = kmsEcdh(input(curve, kmsPrivate(a, null, publicKey(b)), Collections.singletonList("token")));
    List<Pair> keyrings = Arrays.asList(
      keyring,
      kmsEcdh(input(curve, discovery(b), null)),
      // Other encodings of a valid recipient key build (no DER length check), and go to KMS as given.
      kmsEcdh(input(curve, kmsPrivate(a, null, compressedSpki(curve, publicKey(b))), null)),
      kmsEcdh(input(curve, kmsPrivate(a, null, explicitParameters(curve, publicKey(b), 0)), null))
    );
    for (AlgorithmSuiteId suite : allSuites()) {
      List<EncryptionMaterials> inputs = new ArrayList<>(invalidEncryptionMaterials(suite));
      inputs.add(encryptionMaterials(suite, map("a", "b"), false));
      inputs.add(encryptionMaterials(suite, map(repeat('k', 65536), "v"), false));
      // Both an unserializable context and invalid materials: pins which check runs first.
      inputs.add(encryptionMaterials(suite, map(repeat('k', 65536), "v"), false).toBuilder().plaintextDataKey(ByteBuffer.wrap(new byte[3])).build());
      inputs.add(keyring.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false)));
      for (Pair each : keyrings) {
        for (int i = 0; i < inputs.size(); i++) {
          assertSameEcdhEncrypt(each, inputs.get(i), ReferenceMpl.describe(suite) + " input " + i, 0);
        }
      }
    }
    for (AlgorithmSuiteId suite : failureSuites()) {
      for (boolean withDataKey : new boolean[] { false, true }) {
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), withDataKey);
        String context = ReferenceMpl.describe(suite) + " data key " + withDataKey;
        for (Map.Entry<String, ServiceError> error : serviceErrors().entrySet()) {
          aws.kms().fail("DeriveSharedSecret", null, error.getValue());
          assertSameEcdhEncrypt(keyring, start, context + " " + error.getKey(), 0);
          aws.kms().clearFailures();
        }
        for (Map.Entry<String, UnaryOperator<ObjectNode>> edit : deriveSharedSecretEdits(b).entrySet()) {
          aws.kms().editResponses("DeriveSharedSecret", edit.getValue());
          assertSameEcdhEncrypt(keyring, start, context + " " + edit.getKey(), 0);
          aws.kms().clearFailures();
        }
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
  //= type=test
  //# If the decryption materials already contain a plaintext data key,
  //# OnDecrypt MUST fail
  //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
  //= type=test
  //# - The key provider ID of the encrypted data key MUST have a value equal to the UTF8 encoded strings `raw-ecdh` OR `aws-kms-ecdh`.

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
  //= type=test
  //# For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.
  //# If this attempt results in an error, then these errors MUST be collected.

  //= spec/framework/aws-kms/aws-kms-ecdh-keyring.md#ondecrypt
  //= type=test
  //# If OnDecrypt fails to successfully decrypt any encrypted data key,
  //# then it MUST yield an error that includes all the collected errors.
  // Malformed provider info, ciphertexts, and keys, keys for other keyrings, and KMS failures, against each kind of decrypting keyring.
  @Test
  void decryptFailures() {
    for (ECDHCurveSpec curve : NIST) {
      String a = eccKey(curve);
      String b = eccKey(curve);
      Pair sender = kmsEcdh(input(curve, kmsPrivate(a, null, publicKey(b)), Collections.singletonList("token")));
      List<Pair> decryptors = new ArrayList<>(Arrays.asList(
        sender,
        kmsEcdh(input(curve, kmsPrivate(b, null, publicKey(a)), null)),
        kmsEcdh(input(curve, discovery(b), null)),
        kmsEcdh(input(curve, discovery(a), null))
      ));
      for (ECDHCurveSpec other : NIST) {
        if (other != curve) {
          decryptors.add(kmsEcdh(input(other, discovery(eccKey(other)), null)));
        }
      }
      for (AlgorithmSuiteId suite : failureSuites()) {
        EncryptionMaterials encrypted = sender.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
        DecryptionMaterials materials = decryptionMaterials(encrypted);
        String context = curve + " " + ReferenceMpl.describe(suite);
        for (List<EncryptedDataKey> edks : edkLists(curve, encrypted)) {
          for (Pair decryptor : decryptors) {
            assertSameDecrypt(aws, outcomes, decryptor, materials, edks, context);
          }
        }
        List<EncryptedDataKey> good = encrypted.encryptedDataKeys();
        List<DecryptionMaterials> otherMaterials = Arrays.asList(
          decryptionMaterials(encrypted, map("a", "c")),
          decryptionMaterials(encrypted, map(repeat('k', 65536), "v")),
          materials.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build(),
          sender.nativeDecrypt(materials, good)
        );
        for (DecryptionMaterials other : otherMaterials) {
          for (Pair decryptor : decryptors) {
            assertSameDecrypt(aws, outcomes, decryptor, other, good, context);
          }
        }
        // A too-short ciphertext under an unserializable context: pins the length checks before serialization.
        byte[] ciphertext = array(good.get(0).ciphertext());
        List<EncryptedDataKey> shortKey = Collections.singletonList(edk("aws-kms-ecdh", array(good.get(0).keyProviderInfo()), Arrays.copyOf(ciphertext, ciphertext.length < 68 ? 47 : 68)));
        for (Pair decryptor : decryptors) {
          assertSameDecrypt(aws, outcomes, decryptor, decryptionMaterials(encrypted, map(repeat('k', 65536), "v")), shortKey, context);
        }
        // KMS failures and malformed responses are collected; the next key is tried.
        for (Pair decryptor : decryptors.subList(0, 3)) {
          for (Map.Entry<String, ServiceError> error : serviceErrors().entrySet()) {
            aws.kms().fail("DeriveSharedSecret", null, error.getValue());
            assertSameDecrypt(aws, outcomes, decryptor, materials, good, context + " " + error.getKey());
            assertSameDecrypt(aws, outcomes, decryptor, materials, Arrays.asList(good.get(0), good.get(0)), context + " twice " + error.getKey());
            aws.kms().clearFailures();
          }
          for (Map.Entry<String, UnaryOperator<ObjectNode>> edit : deriveSharedSecretEdits(b).entrySet()) {
            aws.kms().editResponses("DeriveSharedSecret", edit.getValue());
            assertSameDecrypt(aws, outcomes, decryptor, materials, good, context + " " + edit.getKey());
            aws.kms().clearFailures();
          }
        }
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  // Known difference R44: a static keyring whose recipient key is configured in another encoding (compressed point, explicit parameters)
  // decrypts its own messages. The reference picked the other party's key by comparing the configured DER with the decompressed one,
  // so it derived with the keyring's own key and failed; native always derives with the configured recipient's point.
  // Every other decryption is alike on both sides, including the KMS requests: a keyring with the roles swapped (also configured
  // in the other encoding), the recipient's discovery keyring, and a keyring whose recipient is its own KMS key's public key.
  @Test
  void knownDifferenceR44StaticKeyringWithAnotherRecipientEncoding() {
    for (ECDHCurveSpec curve : NIST) {
      String a = eccKey(curve);
      String b = eccKey(curve);
      Pair bToA = kmsEcdh(input(curve, kmsPrivate(b, null, publicKey(a)), null));
      Pair discoveryB = kmsEcdh(input(curve, discovery(b), null));
      List<UnaryOperator<byte[]>> encodings = Arrays.asList(key -> compressedSpki(curve, key), key -> explicitParameters(curve, key, 0));
      for (UnaryOperator<byte[]> encoding : encodings) {
        Pair keyring = kmsEcdh(input(curve, kmsPrivate(a, null, encoding.apply(publicKey(b))), null));
        Pair swapped = kmsEcdh(input(curve, kmsPrivate(b, null, encoding.apply(publicKey(a))), null));
        Pair toSelf = kmsEcdh(input(curve, kmsPrivate(a, null, encoding.apply(publicKey(a))), null));
        for (AlgorithmSuiteId suite : failureSuites()) {
          EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
          String context = curve + " " + ReferenceMpl.describe(suite);
          assertSameEcdhEncrypt(keyring, start, context, 0);
          for (EncryptionMaterials result : Arrays.asList(keyring.nativeEncrypt(start), keyring.referenceEncrypt(start))) {
            DecryptionMaterials materials = decryptionMaterials(result);
            Object own = decryptInput(materials, result.encryptedDataKeys());
            String reference = ReferenceMpl.outcome(() -> ReferenceMpl.call(keyring.referenceKeyring, "OnDecrypt", own));
            assertTrue(reference.startsWith("throws software.amazon.cryptography.materialproviders.model.CollectionOfErrors"), reference);
            aws.clearRequests();
            String actual = ReferenceMpl.outcome(() -> keyring.nativeKeyring.OnDecrypt(decryptInput(materials, result.encryptedDataKeys())));
            assertEquals(ReferenceMpl.describe(expectedDecryption(result)), actual, context + " own");
            // The recipient key goes to KMS in the standard encoding, as the reference sends a key it decompressed from a message.
            List<RecordedRequest> requests = aws.requests(ReferenceAws.NATIVE);
            assertEquals(1, requests.size(), context + " own requests");
            assertEquals(base64(publicKey(b)), requests.get(0).body().get("PublicKey").asText(), context + " own request");
            for (Pair decryptor : Arrays.asList(bToA, swapped, discoveryB)) {
              String decrypted = assertSameDecrypt(aws, outcomes, decryptor, materials, result.encryptedDataKeys(), context + " recipient");
              assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context + " recipient");
            }
          }
          assertSameEcdhEncrypt(toSelf, start, context + " to self", 0);
          for (EncryptionMaterials result : Arrays.asList(toSelf.nativeEncrypt(start), toSelf.referenceEncrypt(start))) {
            String decrypted = assertSameDecrypt(aws, outcomes, toSelf, decryptionMaterials(result), result.encryptedDataKeys(), context + " to self");
            assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context + " to self");
          }
        }
      }
    }
  }

  // Known difference R11: a curve point with x = 0 passes the curve checks, but ValidatePublicKey reports it invalid.
  // The Dafny-based MPL ignored that result and used the key; native rejects it, as a configured or fetched key at creation,
  // and on decrypt as a message's sender key, before calling KMS.
  @Test
  void knownDifferenceR11ZeroXKeys() {
    String prefix = "throws software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException: ";
    for (ECDHCurveSpec curve : NIST) {
      String a = eccKey(curve);
      String b = eccKey(curve);
      byte[] zeroX = zeroXKey(curve);
      Map<String, CreateAwsKmsEcdhKeyringInput> configured = new LinkedHashMap<>();
      configured.put(RawEcdhKeyringTest.ZERO_X_RECIPIENT, input(curve, kmsPrivate(a, null, zeroX), null));
      configured.put(ZERO_X_SUPPLIED_SENDER, input(curve, kmsPrivate(a, zeroX, publicKey(b)), null));
      for (Map.Entry<String, CreateAwsKmsEcdhKeyringInput> entry : configured.entrySet()) {
        CreateAwsKmsEcdhKeyringInput input = entry.getValue();
        assertEquals(prefix + entry.getKey(), ReferenceMpl.outcome(() -> MPL.CreateAwsKmsEcdhKeyring(input)), curve + " native");
        Object keyring = ReferenceMpl.call(reference, "CreateAwsKmsEcdhKeyring", input);
        // The fake KMS, like the reference, accepts the key: the reference encrypts to it.
        EncryptionMaterials start = encryptionMaterials(failureSuites().get(0), map("a", "b"), false);
        Object encrypted = ReferenceMpl.call(keyring, "OnEncrypt", OnEncryptInput.builder().materials(start).build());
        assertEquals(1, ((OnEncryptOutput) ReferenceMpl.fromReference(encrypted)).materials().encryptedDataKeys().size(), curve + " reference");
      }
      Map<String, CreateAwsKmsEcdhKeyringInput> fetched = new LinkedHashMap<>();
      fetched.put(RawEcdhKeyringTest.ZERO_X_RECIPIENT, input(curve, discovery(b), null));
      fetched.put(ZERO_X_SUPPLIED_SENDER, input(curve, kmsPrivate(a, null, publicKey(b)), null));
      aws.kms().editResponses("GetPublicKey", r -> r.put("PublicKey", base64(zeroX)));
      for (Map.Entry<String, CreateAwsKmsEcdhKeyringInput> entry : fetched.entrySet()) {
        CreateAwsKmsEcdhKeyringInput input = entry.getValue();
        assertEquals(prefix + entry.getKey(), ReferenceMpl.outcome(() -> MPL.CreateAwsKmsEcdhKeyring(input)), curve + " native, fetched");
        assertEquals("\"keyring\"", ReferenceMpl.outcome(() -> AwsKmsKeyringTest.created(ReferenceMpl.call(reference, "CreateAwsKmsEcdhKeyring", input))), curve + " reference, fetched");
      }
      aws.kms().clearFailures();
      // An invalid identifier is reported first, alike on both sides.
      for (String identifier : Arrays.asList("", "arn:aws:kms", a.substring(0, a.indexOf("key/")) + "key/" + repeat('a', 2048))) {
        assertSameCreate(input(curve, kmsPrivate(identifier, zeroX, publicKey(b)), null), curve + " " + identifier);
        assertSameCreate(input(curve, kmsPrivate(identifier, publicKey(a), zeroX), null), curve + " " + identifier);
      }

      Pair discoveryB = kmsEcdh(input(curve, discovery(b), null));
      Pair aToB = kmsEcdh(input(curve, kmsPrivate(a, null, publicKey(b)), null));
      for (AlgorithmSuiteId suite : failureSuites()) {
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), true);
        String context = curve + " " + ReferenceMpl.describe(suite);
        EncryptionMaterials attack = RawEcdhKeyringTest.wrapped(curve, "aws-kms-ecdh", zeroX, publicKey(b), kmsSharedSecret(b, zeroX), start);
        Object decrypt = decryptInput(decryptionMaterials(attack), attack.encryptedDataKeys());
        aws.clearRequests();
        assertEquals(
          ReferenceMpl.describe(expectedDecryption(attack)),
          ReferenceMpl.outcome(() -> ReferenceMpl.call(discoveryB.referenceKeyring, "OnDecrypt", decrypt)),
          context + " reference"
        );
        assertEquals(
          "throws software.amazon.cryptography.materialproviders.model.CollectionOfErrors: " +
          "No Configured KMS Key was able to decrypt the Data Key. The list of encountered Exceptions is available via `list`. " +
          "String representation of Exceptions in list.\nAwsCryptographicMaterialProvidersException: " + RawEcdhKeyringTest.ZERO_X_SENDER +
          " [" + prefix + RawEcdhKeyringTest.ZERO_X_SENDER + "]",
          ReferenceMpl.outcome(() -> discoveryB.nativeKeyring.OnDecrypt(decryptInput(decryptionMaterials(attack), attack.encryptedDataKeys()))),
          context + " native"
        );
        assertEquals(1, aws.requests(ReferenceAws.REFERENCE).size(), context + " reference requests");
        assertTrue(aws.requests(ReferenceAws.NATIVE).isEmpty(), context + " native requests");
        // A static keyring does not match the x = 0 sender: alike on both sides.
        assertTrue(assertSameDecrypt(aws, outcomes, aToB, decryptionMaterials(attack), attack.encryptedDataKeys(), context).startsWith("throws"), context);
      }
    }
  }

  private static final String ZERO_X_SUPPLIED_SENDER = "Invalid sender public key: a point with x coordinate 0 is not accepted.";

  // The shared secret of the KMS key and a public key, from the fake KMS.
  private byte[] kmsSharedSecret(String keyArn, byte[] publicKey) {
    return kms
      .deriveSharedSecret(r -> r.keyId(keyArn).keyAgreementAlgorithm("ECDH").publicKey(software.amazon.awssdk.core.SdkBytes.fromByteArray(publicKey)))
      .sharedSecret()
      .asByteArray();
  }

  // A discovery keyring takes its recipient key from GetPublicKey with no length check: a key over KMS's 8192-byte limit
  // (an explicit-parameters encoding with a long seed) builds, and decrypts.
  @Test
  void discoveryKeyOverTheKmsLengthLimit() {
    ECDHCurveSpec curve = ECDHCurveSpec.ECC_NIST_P256;
    String a = eccKey(curve);
    String b = eccKey(curve);
    Pair sender = kmsEcdh(input(curve, kmsPrivate(a, null, publicKey(b)), null));
    EncryptionMaterials encrypted = sender.nativeEncrypt(encryptionMaterials(allSuites().get(0), map("a", "b"), false));
    byte[] longKey = explicitParameters(curve, publicKey(b), 8200);
    assertTrue(longKey.length > 8192, "key length " + longKey.length);
    aws.kms().editResponses("GetPublicKey", r -> r.put("PublicKey", base64(longKey)));
    Pair discovery = kmsEcdh(input(curve, discovery(b), null));
    aws.kms().clearFailures();
    String decrypted = assertSameDecrypt(aws, outcomes, discovery, decryptionMaterials(encrypted), encrypted.encryptedDataKeys(), "long key");
    assertEquals(ReferenceMpl.describe(expectedDecryption(encrypted)), decrypted);
  }

  // The Dafny-based MPL converted each KMS response field to its own types; a value the SDK did not know failed that conversion,
  // even in a field the keyring never reads. The native keyring reads the SDK response: an unknown value fails only a checked field.
  @Test
  void unknownEnumValuesInKmsResponses() {
    ECDHCurveSpec curve = ECDHCurveSpec.ECC_NIST_P256;
    String a = eccKey(curve);
    String b = eccKey(curve);
    Pair keyring = kmsEcdh(input(curve, kmsPrivate(a, null, publicKey(b)), null));
    EncryptionMaterials start = encryptionMaterials(allSuites().get(0), map("a", "b"), false);
    Map<String, String> fields = new LinkedHashMap<>();
    fields.put("KeyAgreementAlgorithm", "throws software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException: Invalid response from KMS DeriveSharedSecret");
    fields.put("KeyOrigin", "returns");
    for (Map.Entry<String, String> field : fields.entrySet()) {
      aws.kms().editResponses("DeriveSharedSecret", r -> r.put(field.getKey(), "SOMETHING_NEW"));
      String expected = ReferenceMpl.outcome(() -> masked(keyring.referenceEncrypt(start), false, 0));
      String actual = ReferenceMpl.outcome(() -> masked(keyring.nativeEncrypt(start), false, 0));
      aws.kms().clearFailures();
      assertEquals("throws java.lang.RuntimeException: Cannot convert null to software.amazon.cryptography.services.kms.internaldafny.types." +
        (field.getKey().equals("KeyOrigin") ? "OriginType." : "KeyAgreementAlgorithmSpec."), expected, field.getKey());
      assertTrue(field.getValue().equals("returns") ? !actual.startsWith("throws") : actual.equals(field.getValue()), field.getKey() + ": " + actual);
    }
    for (String field : Arrays.asList("KeyUsage", "KeySpec")) {
      aws.kms().editResponses("GetPublicKey", r -> r.put(field, "SOMETHING_NEW"));
      CreateAwsKmsEcdhKeyringInput input = input(curve, discovery(b), null);
      String expected = ReferenceMpl.outcome(() -> AwsKmsKeyringTest.created(ReferenceMpl.call(reference, "CreateAwsKmsEcdhKeyring", input)));
      String actual = ReferenceMpl.outcome(() -> AwsKmsKeyringTest.created(MPL.CreateAwsKmsEcdhKeyring(input)));
      aws.kms().clearFailures();
      assertTrue(expected.startsWith("throws java.lang.RuntimeException: Cannot convert null to"), field + ": " + expected);
      assertEquals(field.equals("KeyUsage") ? "throws software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException: Invalid response from KMS GetPublicKey" : "\"keyring\"", actual, field);
    }
  }

  private List<List<EncryptedDataKey>> edkLists(ECDHCurveSpec curve, EncryptionMaterials encrypted) {
    EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
    byte[] info = array(good.keyProviderInfo());
    byte[] ciphertext = array(good.ciphertext());
    int keyLength = compressedLength(curve);
    byte[] senderKey = Arrays.copyOfRange(info, 1 + 4 + keyLength + 4, info.length);
    byte[] recipientKey = Arrays.copyOfRange(info, 1 + 4, 1 + 4 + keyLength);
    byte[] strangerKey = compressed(curve, generatePublicKey(curve));
    int prefix = encrypted.algorithmSuite().edkWrapping().IntermediateKeyWrapping() != null ? 32 + 16 : 0;
    int dataKeyLength = encrypted.algorithmSuite().encrypt().AES_GCM().keyLength();
    int tagStart = prefix + 64 + dataKeyLength;

    List<byte[]> infos = new ArrayList<>(Arrays.asList(
      new byte[0],
      Arrays.copyOf(info, info.length - 1),
      concat(info, new byte[] { 0 }),
      concat(new byte[] { 2 }, Arrays.copyOfRange(info, 1, info.length)),
      withUint32(info, 1, 0xFFFFFFFFL),
      withUint32(info, 1, info.length - 5 - 4),
      withUint32(info, 1, info.length - 5 - 3),
      withUint32(info, 1, keyLength - 1),
      withUint32(info, 1 + 4 + keyLength, 7),
      providerInfo(recipientKey, senderKey),
      providerInfo(strangerKey, recipientKey),
      providerInfo(senderKey, strangerKey),
      providerInfo(flip(senderKey, 0), recipientKey),
      providerInfo(flip(senderKey, 5), recipientKey)
    ));
    for (ECDHCurveSpec other : NIST) {
      if (other != curve) {
        byte[] otherKey = compressed(other, generatePublicKey(other));
        infos.add(Arrays.copyOf(providerInfo(otherKey, otherKey), info.length));
      }
    }
    List<byte[]> ciphertexts = Arrays.asList(
      new byte[0],
      Arrays.copyOf(ciphertext, 47),
      Arrays.copyOf(ciphertext, prefix + 68),
      Arrays.copyOf(ciphertext, prefix + 69),
      Arrays.copyOf(ciphertext, prefix + 64 + dataKeyLength),
      Arrays.copyOf(ciphertext, tagStart + 1),
      Arrays.copyOf(ciphertext, ciphertext.length - 1),
      concat(ciphertext, new byte[] { 0 }),
      flip(ciphertext, prefix),
      flip(ciphertext, prefix + 40),
      flip(ciphertext, prefix + 64),
      flip(ciphertext, ciphertext.length - 1),
      flip(ciphertext, 0)
    );

    List<List<EncryptedDataKey>> lists = new ArrayList<>();
    lists.add(Collections.emptyList());
    lists.add(Collections.singletonList(good));
    lists.add(Collections.singletonList(edk("raw-ecdh", info, ciphertext)));
    lists.add(Collections.singletonList(edk("other", "utf-8 info".getBytes(StandardCharsets.UTF_8), ciphertext)));
    lists.add(Collections.singletonList(edk("aws-kms-ecdh ", info, ciphertext)));
    for (byte[] hierarchy : Arrays.asList(new byte[0], bytes(43, 1), bytes(44, 1), bytes(48 + 44, 1))) {
      lists.add(Arrays.asList(edk("other", new byte[0], ciphertext), edk("aws-kms-hierarchy", "branch".getBytes(StandardCharsets.UTF_8), hierarchy)));
    }
    for (byte[] badInfo : infos) {
      lists.add(Collections.singletonList(edk("aws-kms-ecdh", badInfo, ciphertext)));
    }
    for (byte[] badCiphertext : ciphertexts) {
      lists.add(Collections.singletonList(edk("aws-kms-ecdh", info, badCiphertext)));
    }
    // Two faults at once, to pin which check runs first.
    lists.add(Collections.singletonList(edk("aws-kms-ecdh", info, Arrays.copyOf(flip(ciphertext, prefix + 40), ciphertext.length - 1))));
    byte[] badSender = senderKey.clone();
    badSender[0] = 5;
    lists.add(Collections.singletonList(edk("aws-kms-ecdh", providerInfo(badSender, recipientKey), Arrays.copyOf(ciphertext, 47))));
    lists.add(Collections.singletonList(edk("aws-kms-ecdh", providerInfo(senderKey, badSender), ciphertext)));
    // Binary provider info (as a Raw AES key has) in the no-match message (B11).
    EncryptedDataKey binary = edk("aes-namespace", new byte[] { 'k', (byte) 0x80, 0, 0, 0, 12 }, ciphertext);
    lists.add(Collections.singletonList(binary));
    lists.add(Arrays.asList(binary, edk("aws-kms-hierarchy", "branch".getBytes(StandardCharsets.UTF_8), bytes(43, 1))));
    // Filtering fails before any key is tried; decryption failures are collected and the next key tried.
    lists.add(Arrays.asList(good, edk("aws-kms-ecdh", new byte[3], ciphertext)));
    lists.add(Arrays.asList(edk("aws-kms-ecdh", info, flip(ciphertext, prefix + 64)), edk("other", info, ciphertext), good));
    lists.add(Arrays.asList(edk("aws-kms-ecdh", info, flip(ciphertext, prefix + 40)), edk("raw-ecdh", info, new byte[0])));
    return lists;
  }

  private Map<String, UnaryOperator<ObjectNode>> getPublicKeyEdits(ECDHCurveSpec curve, ECDHCurveSpec otherCurve, String recipient) {
    Map<String, UnaryOperator<ObjectNode>> edits = new LinkedHashMap<>();
    edits.put("no KeyId", r -> remove(r, "KeyId"));
    edits.put("other KeyId", r -> r.put("KeyId", r.get("KeyId").asText() + "0"));
    edits.put("no KeyUsage", r -> remove(r, "KeyUsage"));
    edits.put("KeyUsage ENCRYPT_DECRYPT", r -> r.put("KeyUsage", "ENCRYPT_DECRYPT"));
    edits.put("no PublicKey", r -> remove(r, "PublicKey"));
    edits.put("empty PublicKey", r -> r.put("PublicKey", ""));
    edits.put("junk PublicKey", r -> r.put("PublicKey", base64(bytes(20, 0x41))));
    edits.put("PublicKey of another curve", r -> r.put("PublicKey", base64(generatePublicKey(otherCurve))));
    edits.put("compressed PublicKey", r -> r.put("PublicKey", base64(compressedSpki(curve, decode(r, "PublicKey")))));
    return edits;
  }

  private static Map<String, UnaryOperator<ObjectNode>> deriveSharedSecretEdits(String otherArn) {
    Map<String, UnaryOperator<ObjectNode>> edits = new LinkedHashMap<>();
    edits.put("no KeyId", r -> remove(r, "KeyId"));
    edits.put("other KeyId", r -> r.put("KeyId", otherArn));
    edits.put("no SharedSecret", r -> remove(r, "SharedSecret"));
    edits.put("no KeyAgreementAlgorithm", r -> remove(r, "KeyAgreementAlgorithm"));
    for (int length : new int[] { 0, 1, 31, 32, 33, 47, 48, 49, 65, 66, 67 }) {
      edits.put("SharedSecret of " + length + " bytes", r -> r.put("SharedSecret", base64(Arrays.copyOf(decode(r, "SharedSecret"), length))));
    }
    edits.put("SharedSecret flipped", r -> r.put("SharedSecret", base64(flip(decode(r, "SharedSecret"), 0))));
    return edits;
  }

  private void assertSameEcdhEncrypt(Pair keyring, EncryptionMaterials materials, String context, int randomInfo) {
    boolean dataKeyGiven = materials.plaintextDataKey() != null;
    assertSame(
      aws,
      outcomes,
      "OnEncrypt",
      () -> masked(keyring.referenceEncrypt(materials), dataKeyGiven, randomInfo),
      () -> masked(keyring.nativeEncrypt(materials), dataKeyGiven, randomInfo),
      context + " " + ReferenceMpl.describe(materials)
    );
  }

  private void assertSameCreate(CreateAwsKmsEcdhKeyringInput input, String context) {
    assertSame(
      aws,
      outcomes,
      "CreateAwsKmsEcdhKeyring",
      () -> AwsKmsKeyringTest.created(ReferenceMpl.call(reference, "CreateAwsKmsEcdhKeyring", input)),
      () -> AwsKmsKeyringTest.created(MPL.CreateAwsKmsEcdhKeyring(input)),
      context + " " + ReferenceMpl.describe(input)
    );
  }

  private Pair kmsEcdh(CreateAwsKmsEcdhKeyringInput input) {
    return new Pair(MPL.CreateAwsKmsEcdhKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsEcdhKeyring", input));
  }

  private Pair rawEcdh(ECDHCurveSpec curve, RawEcdhStaticConfigurations scheme) {
    CreateRawEcdhKeyringInput input = CreateRawEcdhKeyringInput.builder().curveSpec(curve).KeyAgreementScheme(scheme).build();
    return new Pair(MPL.CreateRawEcdhKeyring(input), ReferenceMpl.call(reference, "CreateRawEcdhKeyring", input));
  }

  private CreateAwsKmsEcdhKeyringInput input(ECDHCurveSpec curve, KmsEcdhStaticConfigurations scheme, List<String> grantTokens) {
    return CreateAwsKmsEcdhKeyringInput.builder().curveSpec(curve).KeyAgreementScheme(scheme).kmsClient(kms).grantTokens(grantTokens).build();
  }

  private static KmsEcdhStaticConfigurations discovery(String recipient) {
    return KmsEcdhStaticConfigurations.builder().KmsPublicKeyDiscovery(KmsPublicKeyDiscoveryInput.builder().recipientKmsIdentifier(recipient).build()).build();
  }

  private static KmsEcdhStaticConfigurations kmsPrivate(String sender, byte[] senderPublicKey, byte[] recipientPublicKey) {
    return KmsEcdhStaticConfigurations
      .builder()
      .KmsPrivateKeyToStaticPublicKey(
        KmsPrivateKeyToStaticPublicKeyInput
          .builder()
          .senderKmsIdentifier(sender)
          .senderPublicKey(senderPublicKey == null ? null : ByteBuffer.wrap(senderPublicKey))
          .recipientPublicKey(ByteBuffer.wrap(recipientPublicKey))
          .build()
      )
      .build();
  }

  private String eccKey(ECDHCurveSpec curve) {
    return aws.kms().createEccKeyAgreementKey(REGION, curve.name());
  }

  private byte[] publicKey(String arn) {
    return Base64.getMimeDecoder().decode(aws.kms().publicKeyPem(arn).replaceAll("-----[A-Z ]*-----", ""));
  }

  // Recipient keys: valid, other curves, other encodings of a valid key, invalid points, malformed, and over the KMS length limit.
  // A point with x = 0 is a known difference: see knownDifferenceR11ZeroXKeys.
  private static List<byte[]> publicKeyVariants(ECDHCurveSpec curve, byte[] valid) {
    List<byte[]> variants = new ArrayList<>(Arrays.asList(
      valid,
      new byte[0],
      bytes(20, 0x41),
      Arrays.copyOf(valid, valid.length - 1),
      concat(valid, new byte[] { 0 }),
      flip(valid, valid.length - 1),
      compressedSpki(curve, valid),
      explicitParameters(curve, valid, 0),
      pem("PUBLIC KEY", valid),
      new byte[8192],
      new byte[8193],
      explicitParameters(curve, valid, 8200)
    ));
    for (ECDHCurveSpec other : NIST) {
      if (other != curve) {
        variants.add(generatePublicKey(other));
      }
    }
    return variants;
  }

  private static byte[] compressedSpki(ECDHCurveSpec curve, byte[] publicKeyDer) {
    return spki(namedCurve(curve), compressed(curve, publicKeyDer));
  }

  // The key with explicit curve parameters, and a seed of {@code seedLength} bytes when not 0.
  private static byte[] explicitParameters(ECDHCurveSpec curve, byte[] publicKeyDer, int seedLength) {
    ECNamedCurveParameterSpec spec = curveOf(curve);
    ECPoint point = spec.getCurve().decodePoint(compressed(curve, publicKeyDer));
    X9ECParameters parameters = new X9ECParameters(
      spec.getCurve(),
      new X9ECPoint(spec.getG(), false),
      spec.getN(),
      spec.getH(),
      seedLength == 0 ? null : bytes(seedLength, 3)
    );
    return spki(new X962Parameters(parameters), point.getEncoded(false));
  }

  // One suite per wrapped key length and kind of wrapping.
  private static List<AlgorithmSuiteId> failureSuites() {
    return Arrays.asList(
      AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF).build(),
      AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).build(),
      AlgorithmSuiteId.builder().DBE(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384).build()
    );
  }
}
