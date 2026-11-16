// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.internal.EcdhEdkWrapping;
import software.amazon.cryptography.materialproviders.internal.EdkWrapping;
import software.amazon.cryptography.materialproviders.internal.MaterialsAccess;
import software.amazon.cryptography.materialproviders.internal.primitives.Ecdh;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.internal.Convert;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRawEcdhKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EphemeralPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.PublicKeyDiscoveryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.RawEcdhStaticConfigurations;
import software.amazon.cryptography.oldapi.materialproviders.model.RawPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.oldapi.primitives.model.ECDHCurveSpec;

// Differential tests of the raw ECDH keyring against the published Dafny-based MPL.
// Encryption is randomized (salt, data key, ephemeral key), so each side decrypts both sides' encrypted data keys;
// creation, decryption, and every failure are deterministic and compared exactly.
// Keys: TestUtils.dfy's (TesRawECDHKeyring.dfy) and keys.json's raw ECDH keys from the MPL test vectors, plus generated ones.
class RawEcdhKeyringTest {

  private static final List<ECDHCurveSpec> NIST = Arrays.asList(ECDHCurveSpec.ECC_NIST_P256, ECDHCurveSpec.ECC_NIST_P384, ECDHCurveSpec.ECC_NIST_P521);
  private static final JsonNode VECTORS = read("/vectors/ecdh-keyring.json");
  private static final JsonNode ASYMMETRIC = read("/vectors/asymmetric.json");

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();

  //= spec/framework/raw-ecdh-keyring.md#initialization
  //= type=test
  //# On initialization, the keyring MUST assert that the recipient's public key
  //# and the sender's private key belong to the same ECC Curve, and that
  //# the public key's ECC points are not the "points at infinity".
  @Test
  void create() {
    for (ECDHCurveSpec curve : ECDHCurveSpec.values()) {
      ECDHCurveSpec keyCurve = curve == ECDHCurveSpec.SM2 ? ECDHCurveSpec.ECC_NIST_P256 : curve;
      Keys keys = Keys.of("testUtils", keyCurve);
      List<byte[]> privateKeys = privateKeyVariants(keyCurve, keys);
      List<byte[]> publicKeys = publicKeyVariants(keyCurve, keys);
      List<RawEcdhStaticConfigurations> schemes = new ArrayList<>();
      for (byte[] privateKey : privateKeys) {
        schemes.add(rawPrivate(privateKey, keys.recipientPublic));
        schemes.add(discovery(privateKey));
      }
      for (byte[] publicKey : publicKeys) {
        schemes.add(rawPrivate(keys.senderPrivate, publicKey));
        schemes.add(ephemeral(publicKey));
      }
      for (RawEcdhStaticConfigurations scheme : schemes) {
        // TesRawECDHKeyring.dfy: keys of one curve fail under every other curve.
        for (ECDHCurveSpec configured : ECDHCurveSpec.values()) {
          if (configured == curve || curve == ECDHCurveSpec.SM2 || configured == ECDHCurveSpec.SM2) {
            assertSameCreate(input(configured, scheme));
          }
        }
      }
    }
    outcomes.assertBothSeen("Create");
  }

  //= spec/framework/raw-ecdh-keyring.md#onencrypt
  //= type=test
  //# The keyring MUST derive the shared secret
  //# according to the configured [Key Agreement Schema](#key-agreement-procedure).

  //= spec/framework/raw-ecdh-keyring.md#onencrypt
  //= type=test
  //# The keyring MUST perform data key wrapping according to the [Data Key Wrapping section](#data-key-wrapping).

  //= spec/framework/raw-ecdh-keyring.md#onencrypt
  //= type=test
  //# - The [key provider id](../structures.md#key-provider-id) MUST be the UTF8 encoded string "raw-ecdh".

  //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
  //= type=test
  //# If the [encryption materials](structures.md#encryption-materials) do not contain a plaintext data key,
  //# OnEncrypt MUST generate a random plaintext data key.

  //= spec/framework/raw-ecdh-keyring.md#ondecrypt
  //= type=test
  //# The keyring MUST perform data key unwrapping according to the [Data Key Unwrapping section](#data-key-unwrapping).

  //= spec/framework/key-agreement-schemas.md#rawprivatekeytostaticpublickey
  //= type=test
  //# - MUST verify that both the configured sender's and recipient's
  //#   public keys match the public keys stored on the message ciphertext.

  //= spec/framework/key-agreement-schemas.md#publickeydiscovery
  //= type=test
  //# - MUST verify that the recipient public key stored on
  //# the message ciphertext matches the configured recipient's
  //# public key.
  // Each side decrypts what either side encrypted, with every decrypting configuration:
  // the sender's own keyring, the recipient's static keyring (roles swapped), and the recipient's discovery keyring.
// Only discovery can decrypt for an ephemeral sender; for the others both sides' outcomes are compared.
  @Test
  void eachSideDecryptsTheOther() {
    for (String source : Arrays.asList("testVectorKeys", "testUtils")) {
      for (ECDHCurveSpec curve : NIST) {
        Keys keys = Keys.of(source, curve);
        Pair sender = ecdh(input(curve, rawPrivate(keys.senderPrivate, keys.recipientPublic)));
        Pair ephemeral = ecdh(input(curve, ephemeral(keys.recipientPublic)));
        List<Pair> decryptors = Arrays.asList(
          sender,
          ecdh(input(curve, rawPrivate(keys.recipientPrivate, keys.senderPublic))),
          ecdh(input(curve, discovery(keys.recipientPrivate)))
        );
        for (AlgorithmSuiteId suite : allSuites()) {
          for (boolean withDataKey : new boolean[] { false, true }) {
            EncryptionMaterials start = encryptionMaterials(suite, map("a", "b", "c", "d"), withDataKey);
            String context = source + " " + curve + " " + ReferenceMpl.describe(suite) + " data key " + withDataKey;
            sender.assertSameEncrypt(outcomes, start, context, 0);
            ephemeral.assertSameEncrypt(outcomes, start, context, compressedLength(curve));
            List<EncryptionMaterials> results = Arrays.asList(
              sender.nativeEncrypt(start),
              sender.referenceEncrypt(start),
              ephemeral.nativeEncrypt(start),
              ephemeral.referenceEncrypt(start)
            );
            for (int i = 0; i < results.size(); i++) {
              EncryptionMaterials result = results.get(i);
              for (int j = 0; j < decryptors.size(); j++) {
                String decrypted = decryptors.get(j).assertSameDecrypt(outcomes, decryptionMaterials(result), result.encryptedDataKeys(), context);
                // Only discovery decrypts for an ephemeral sender: the static keyrings also match the sender's key.
                if (i < 2 || j == 2) {
                  assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context + " result " + i + " decryptor " + j);
                }
              }
            }
          }
        }
      }
    }
  }

  //= spec/framework/key-agreement-schemas.md#key-derivation
  //= type=test
  //# Before deriving a shared wrapping key, the keyring MUST generate a 32 byte random salt value.
  // A zero IV is safe only because every encryption draws a fresh salt (and data key, and ephemeral key).
  @Test
  void everyEncryptionIsFresh() {
    for (ECDHCurveSpec curve : NIST) {
      Keys keys = Keys.of("testUtils", curve);
      Pair sender = ecdh(input(curve, rawPrivate(keys.senderPrivate, keys.recipientPublic)));
      Pair ephemeral = ecdh(input(curve, ephemeral(keys.recipientPublic)));
      for (AlgorithmSuiteId suite : failureSuites()) {
        for (Pair keyring : Arrays.asList(sender, ephemeral)) {
          EncryptionMaterials withKey = encryptionMaterials(suite, map("a", "b"), true);
          EncryptedDataKey first = keyring.nativeEncrypt(withKey).encryptedDataKeys().get(0);
          EncryptedDataKey second = keyring.nativeEncrypt(withKey).encryptedDataKeys().get(0);
          assertFalse(Arrays.equals(array(first.ciphertext()), array(second.ciphertext())), "ciphertext repeated");
          if (keyring == ephemeral) {
            assertFalse(Arrays.equals(array(first.keyProviderInfo()), array(second.keyProviderInfo())), "ephemeral key repeated");
          }
          EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
          assertFalse(
            Arrays.equals(array(keyring.nativeEncrypt(start).plaintextDataKey()), array(keyring.nativeEncrypt(start).plaintextDataKey())),
            "data key repeated"
          );
        }
      }
    }
  }

  //= spec/framework/raw-ecdh-keyring.md#onencrypt
  //= type=test
  //# OnEncrypt MUST fail if configured with a
  //# [PublicKeyDiscovery Key Agreement Configuration](./key-agreement-schemas.md#publickeydiscovery)

  //= spec/framework/raw-ecdh-keyring.md#onencrypt
  //= type=test
  //# If the keyring cannot serialize
  //# the encryption context, OnEncrypt MUST fail.
  @Test
  void encryptFailures() {
    Keys keys = Keys.of("testVectorKeys", ECDHCurveSpec.ECC_NIST_P256);
    List<Pair> keyrings = Arrays.asList(
      ecdh(input(ECDHCurveSpec.ECC_NIST_P256, discovery(keys.recipientPrivate))),
      ecdh(input(ECDHCurveSpec.ECC_NIST_P256, rawPrivate(keys.senderPrivate, keys.recipientPublic))),
      ecdh(input(ECDHCurveSpec.ECC_NIST_P256, ephemeral(keys.recipientPublic)))
    );
    for (Pair keyring : keyrings) {
      for (AlgorithmSuiteId suite : allSuites()) {
        EncryptionMaterials valid = encryptionMaterials(suite, map("a", "b"), false);
        List<EncryptionMaterials> inputs = new ArrayList<>(Arrays.asList(
          valid,
          encryptionMaterials(suite, map(repeat('k', 65536), "v"), false),
          valid.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build(),
          valid.toBuilder().plaintextDataKey(ByteBuffer.wrap(new byte[3])).build(),
          // Both an unserializable context and invalid materials: pins which check runs first.
          encryptionMaterials(suite, map(repeat('k', 65536), "v"), false).toBuilder().plaintextDataKey(ByteBuffer.wrap(new byte[3])).build()
        ));
        // Materials that already have a data key and an encrypted data key.
        if (keyring != keyrings.get(0)) {
          inputs.add(keyring.nativeEncrypt(valid));
        }
        for (int i = 0; i < inputs.size(); i++) {
          int random = keyring == keyrings.get(1) ? 0 : compressedLength(ECDHCurveSpec.ECC_NIST_P256);
          keyring.assertSameEncrypt(outcomes, inputs.get(i), ReferenceMpl.describe(suite) + " input " + i, random);
        }
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  //= spec/framework/raw-ecdh-keyring.md#ondecrypt
  //= type=test
  //# OnDecrypt MUST fail if configured with a
  //# [EphemeralPrivateKeyToStaticPublicKey Key Agreement Configuration](./key-agreement-schemas.md#ephemeralprivatekeytostaticpublickey)

  //= spec/framework/raw-ecdh-keyring.md#ondecrypt
  //= type=test
  //# If the decryption materials already contain a plaintext data key,
  //# the keyring MUST fail
  //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).

  //= spec/framework/raw-ecdh-keyring.md#ondecrypt
  //= type=test
  //# If the keyring cannot
  //# serialize the encryption context, OnDecrypt MUST fail.

  //= spec/framework/raw-ecdh-keyring.md#ondecrypt
  //= type=test
  //# - The deserialized version value in the [key provider information](#key-provider-information) MUST match `0x01`.

  //= spec/framework/raw-ecdh-keyring.md#ondecrypt
  //= type=test
  //# - The key provider ID of the encrypted data key MUST have a value equal to the UTF8 encoded strings `raw-ecdh` OR `aws-kms-ecdh`.

  //= spec/framework/raw-ecdh-keyring.md#ondecrypt
  //= type=test
  //# The keyring MUST check that the calculated Commitment Key
  //# from the key derivation step is equal to the deserialized commitment key
  //# found in the encrypted data key.
  // Malformed provider info, ciphertexts, and keys, and keys for other keyrings, against each kind of decrypting keyring.
  @Test
  void decryptFailures() {
    for (ECDHCurveSpec curve : NIST) {
      Keys keys = Keys.of("testVectorKeys", curve);
      Pair sender = ecdh(input(curve, rawPrivate(keys.senderPrivate, keys.recipientPublic)));
      List<Pair> decryptors = new ArrayList<>(Arrays.asList(
        sender,
        ecdh(input(curve, rawPrivate(keys.recipientPrivate, keys.senderPublic))),
        ecdh(input(curve, discovery(keys.recipientPrivate))),
        ecdh(input(curve, discovery(keys.senderPrivate))),
        ecdh(input(curve, ephemeral(keys.recipientPublic)))
      ));
      for (ECDHCurveSpec other : NIST) {
        if (other != curve) {
          decryptors.add(ecdh(input(other, discovery(Keys.of("testVectorKeys", other).recipientPrivate))));
        }
      }
      for (AlgorithmSuiteId suite : failureSuites()) {
        EncryptionMaterials encrypted = sender.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
        DecryptionMaterials materials = decryptionMaterials(encrypted);
        String context = curve + " " + ReferenceMpl.describe(suite);
        for (List<EncryptedDataKey> edks : edkLists(curve, keys, encrypted)) {
          for (Pair decryptor : decryptors) {
            decryptor.assertSameDecrypt(outcomes, materials, edks, context);
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
            decryptor.assertSameDecrypt(outcomes, other, good, context);
          }
        }
        // A too-short ciphertext under an unserializable context: pins the length checks before serialization.
        byte[] ciphertext = array(good.get(0).ciphertext());
        List<EncryptedDataKey> shortKey = Collections.singletonList(edk("raw-ecdh", array(good.get(0).keyProviderInfo()), Arrays.copyOf(ciphertext, ciphertext.length < 68 ? 47 : 68)));
        for (Pair decryptor : decryptors) {
          decryptor.assertSameDecrypt(outcomes, decryptionMaterials(encrypted, map(repeat('k', 65536), "v")), shortKey, context);
        }
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  // Known difference R11: a curve point with x = 0 passes the curve checks, but ValidatePublicKey reports it invalid.
  // The Dafny-based MPL ignored that result and used the key; native rejects it.
  // No private key for such a point is known, so the decrypt cases wrap under the secret the recipient's own private key derives.
  @Test
  void knownDifferenceR11ZeroXKeys() {
    for (ECDHCurveSpec curve : NIST) {
      Keys keys = Keys.of("testVectorKeys", curve);
      byte[] zeroX = zeroXKey(curve);
      for (RawEcdhStaticConfigurations scheme : Arrays.asList(rawPrivate(keys.senderPrivate, zeroX), ephemeral(zeroX))) {
        CreateRawEcdhKeyringInput input = input(curve, scheme);
        assertEquals(
          "throws software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException: " + ZERO_X_RECIPIENT,
          ReferenceMpl.outcome(() -> MPL.CreateRawEcdhKeyring(input)),
          curve + " native"
        );
        Object keyring = ReferenceMpl.call(reference, "CreateRawEcdhKeyring", input);
        EncryptionMaterials start = encryptionMaterials(failureSuites().get(0), map("a", "b"), false);
        Object encrypted = ReferenceMpl.call(keyring, "OnEncrypt", OnEncryptInput.builder().materials(start).build());
        assertEquals(1, ((OnEncryptOutput) ReferenceMpl.fromReference(encrypted)).materials().encryptedDataKeys().size(), curve + " reference");
      }
      Pair discovery = ecdh(input(curve, discovery(keys.recipientPrivate)));
      List<Pair> statics = Arrays.asList(
        ecdh(input(curve, rawPrivate(keys.senderPrivate, keys.recipientPublic))),
        ecdh(input(curve, rawPrivate(keys.recipientPrivate, keys.senderPublic)))
      );
      for (AlgorithmSuiteId suite : failureSuites()) {
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), true);
        String context = curve + " " + ReferenceMpl.describe(suite);
        byte[] controlSecret = Ecdh.deriveSharedSecret(EcdhCurveSpec.valueOf(curve.name()), keys.recipientPrivate, keys.senderPublic);
        EncryptionMaterials control = wrapped(curve, "raw-ecdh", keys.senderPublic, keys.recipientPublic, controlSecret, start);
        assertEquals(ReferenceMpl.describe(expectedDecryption(control)), discovery.assertSameDecrypt(outcomes, decryptionMaterials(control), control.encryptedDataKeys(), context), context);
        byte[] zeroXSecret = Ecdh.deriveSharedSecret(EcdhCurveSpec.valueOf(curve.name()), keys.recipientPrivate, zeroX);
        for (String providerId : Arrays.asList("raw-ecdh", "aws-kms-ecdh")) {
          EncryptionMaterials attack = wrapped(curve, providerId, zeroX, keys.recipientPublic, zeroXSecret, start);
          OnDecryptInput decrypt = decryptInput(decryptionMaterials(attack), attack.encryptedDataKeys());
          assertEquals(
            ReferenceMpl.describe(expectedDecryption(attack)),
            ReferenceMpl.outcome(() -> ReferenceMpl.call(discovery.referenceKeyring, "OnDecrypt", decrypt)),
            context + " reference"
          );
          assertEquals(
            "throws software.amazon.cryptography.materialproviders.model.CollectionOfErrors: " +
            "No Configured Key was able to decrypt the Data Key. The list of encountered Exceptions is available via `list`. " +
            "String representation of Exceptions in list.\nAwsCryptographicMaterialProvidersException: " + ZERO_X_SENDER +
            " [throws software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException: " + ZERO_X_SENDER + "]",
            ReferenceMpl.outcome(() -> discovery.nativeKeyring.OnDecrypt(decrypt)),
            context + " native"
          );
          // The static keyrings do not match the x = 0 sender: alike on both sides.
          for (Pair keyring : statics) {
            assertTrue(keyring.assertSameDecrypt(outcomes, decryptionMaterials(attack), attack.encryptedDataKeys(), context).startsWith("throws"), context);
          }
        }
      }
    }
  }

  // Known difference R44: a static keyring whose recipient key is configured in the hybrid encoding (point prefix 0x06 or 0x07,
  // which has the standard length and builds) decrypts its own messages. The reference picked the other party's key by comparing
  // the configured DER with the one decompressed from the message, so it derived with the keyring's own key and failed;
  // native always derives with the configured recipient key. Compared with the reference: keyrings with the roles swapped
  // (standard and hybrid recipient), the recipient's discovery keyring, an ephemeral sender to the hybrid key,
  // and a keyring whose recipient is its own public key in the hybrid encoding (same point).
  @Test
  void knownDifferenceR44StaticKeyringWithAnotherRecipientEncoding() {
    List<Byte> prefixes = new ArrayList<>();
    for (ECDHCurveSpec curve : NIST) {
      Keys keys = Keys.of("testVectorKeys", curve);
      byte[] hybridRecipient = hybrid(curve, keys.recipientPublic);
      byte[] hybridSender = hybrid(curve, keys.senderPublic);
      prefixes.add(hybridRecipient[hybridRecipient.length - 2 * (compressedLength(curve) - 1) - 1]);
      prefixes.add(hybridSender[hybridSender.length - 2 * (compressedLength(curve) - 1) - 1]);
      Pair keyring = ecdh(input(curve, rawPrivate(keys.senderPrivate, hybridRecipient)));
      Pair ephemeral = ecdh(input(curve, ephemeral(hybridRecipient)));
      Pair toSelf = ecdh(input(curve, rawPrivate(keys.senderPrivate, hybridSender)));
      Pair discovery = ecdh(input(curve, discovery(keys.recipientPrivate)));
      List<Pair> recipients = Arrays.asList(
        ecdh(input(curve, rawPrivate(keys.recipientPrivate, keys.senderPublic))),
        ecdh(input(curve, rawPrivate(keys.recipientPrivate, hybridSender))),
        discovery
      );
      for (AlgorithmSuiteId suite : failureSuites()) {
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
        String context = curve + " " + ReferenceMpl.describe(suite);
        keyring.assertSameEncrypt(outcomes, start, context, 0);
        for (EncryptionMaterials result : Arrays.asList(keyring.nativeEncrypt(start), keyring.referenceEncrypt(start))) {
          DecryptionMaterials materials = decryptionMaterials(result);
          OnDecryptInput own = decryptInput(materials, result.encryptedDataKeys());
          String reference = ReferenceMpl.outcome(() -> ReferenceMpl.call(keyring.referenceKeyring, "OnDecrypt", own));
          assertTrue(reference.startsWith("throws software.amazon.cryptography.materialproviders.model.CollectionOfErrors"), reference);
          String actual = ReferenceMpl.outcome(() -> keyring.nativeKeyring.OnDecrypt(decryptInput(materials, result.encryptedDataKeys())));
          assertEquals(ReferenceMpl.describe(expectedDecryption(result)), actual, context + " own");
          for (Pair decryptor : recipients) {
            String decrypted = decryptor.assertSameDecrypt(outcomes, materials, result.encryptedDataKeys(), context + " recipient");
            assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context + " recipient");
          }
        }
        ephemeral.assertSameEncrypt(outcomes, start, context + " ephemeral", compressedLength(curve));
        for (EncryptionMaterials result : Arrays.asList(ephemeral.nativeEncrypt(start), ephemeral.referenceEncrypt(start))) {
          String decrypted = discovery.assertSameDecrypt(outcomes, decryptionMaterials(result), result.encryptedDataKeys(), context + " ephemeral");
          assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context + " ephemeral");
        }
        toSelf.assertSameEncrypt(outcomes, start, context + " to self", 0);
        for (EncryptionMaterials result : Arrays.asList(toSelf.nativeEncrypt(start), toSelf.referenceEncrypt(start))) {
          String decrypted = toSelf.assertSameDecrypt(outcomes, decryptionMaterials(result), result.encryptedDataKeys(), context + " to self");
          assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context + " to self");
        }
      }
    }
    assertTrue(prefixes.contains((byte) 6) && prefixes.contains((byte) 7), "both hybrid prefixes: " + prefixes);
  }

  static final String ZERO_X_RECIPIENT = "Invalid recipient public key: a point with x coordinate 0 is not accepted.";
  static final String ZERO_X_SENDER = "Invalid sender public key in the provider info: a point with x coordinate 0 is not accepted.";

  /**
   * {@code start} (with a data key) plus an ECDH encrypted data key from {@code senderPublicKey} to {@code recipientPublicKey},
   * wrapped under {@code sharedSecret} by the native wrapping, which the reference decrypts like its own.
   */
  static EncryptionMaterials wrapped(
    ECDHCurveSpec curve,
    String providerId,
    byte[] senderPublicKey,
    byte[] recipientPublicKey,
    byte[] sharedSecret,
    EncryptionMaterials start
  ) {
    software.amazon.cryptography.materialproviders.EncryptionMaterials materials = MaterialsAccess.encryption(Convert.fields(start));
    byte[] sender = Ecdh.compressPublicKey(senderPublicKey);
    byte[] recipient = Ecdh.compressPublicKey(recipientPublicKey);
    byte[] fixedInfo = EcdhEdkWrapping.fixedInfo(EcdhCurveSpec.valueOf(curve.name()), sender, recipient, materials.encryptionContext());
    EdkWrapping.WrapResult<Void> result = EdkWrapping.wrap(
      materials,
      EcdhEdkWrapping.wrap(sharedSecret, fixedInfo),
      EcdhEdkWrapping.generateAndWrap(sharedSecret, fixedInfo)
    );
    software.amazon.cryptography.materialproviders.EncryptedDataKey edk = software.amazon.cryptography.materialproviders.EncryptedDataKey.builder()
        .keyProviderId(providerId)
        .keyProviderInfo(EcdhEdkWrapping.providerInfo(sender, recipient))
        .ciphertext(result.wrappedMaterial)
        .build();
    return Convert.materials(result.addTo(materials, edk));
  }

  // One suite per wrapped key length and kind of wrapping.
  private static List<AlgorithmSuiteId> failureSuites() {
    return Arrays.asList(
      AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF).build(),
      AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).build(),
      AlgorithmSuiteId.builder().DBE(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384).build()
    );
  }

  private List<List<EncryptedDataKey>> edkLists(ECDHCurveSpec curve, Keys keys, EncryptionMaterials encrypted) {
    EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
    byte[] info = array(good.keyProviderInfo());
    byte[] ciphertext = array(good.ciphertext());
    int keyLength = compressedLength(curve);
    byte[] senderKey = Arrays.copyOfRange(info, 1 + 4 + keyLength + 4, info.length);
    byte[] recipientKey = Arrays.copyOfRange(info, 1 + 4, 1 + 4 + keyLength);
    byte[] strangerKey = compressed(curve, generatePublicKey(curve));
    // The wrapped key material: for DBE suites it follows the encrypted data key and its tag.
    int prefix = encrypted.algorithmSuite().edkWrapping().IntermediateKeyWrapping() != null ? 32 + 16 : 0;
    int dataKeyLength = encrypted.algorithmSuite().encrypt().AES_GCM().keyLength();
    int tagStart = prefix + 64 + dataKeyLength;

    List<byte[]> infos = new ArrayList<>(Arrays.asList(
      new byte[0],
      Arrays.copyOf(info, 10),
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
    // Another curve's keys, padded or cut to this curve's provider info length.
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
    lists.add(Collections.singletonList(edk("aws-kms-ecdh", info, ciphertext)));
    lists.add(Collections.singletonList(edk("other", "utf-8 info".getBytes(StandardCharsets.UTF_8), ciphertext)));
    lists.add(Collections.singletonList(edk("other", info, ciphertext)));
    lists.add(Collections.singletonList(edk("raw-ecdh ", info, ciphertext)));
    for (byte[] hierarchy : Arrays.asList(new byte[0], bytes(43, 1), bytes(44, 1), bytes(47, 1), bytes(48, 1), bytes(48 + 43, 1), bytes(48 + 44, 1))) {
      lists.add(Arrays.asList(edk("other", new byte[0], ciphertext), edk("aws-kms-hierarchy", "branch".getBytes(StandardCharsets.UTF_8), hierarchy)));
    }
    for (byte[] badInfo : infos) {
      lists.add(Collections.singletonList(edk("raw-ecdh", badInfo, ciphertext)));
    }
    for (byte[] badCiphertext : ciphertexts) {
      lists.add(Collections.singletonList(edk("raw-ecdh", info, badCiphertext)));
    }
    // Two faults at once, to pin which check runs first: a commitment mismatch and a short tag;
    // a short ciphertext and an undecodable sender key.
    lists.add(Collections.singletonList(edk("raw-ecdh", info, Arrays.copyOf(flip(ciphertext, prefix + 40), ciphertext.length - 1))));
    lists.add(Collections.singletonList(edk("raw-ecdh", info, Arrays.copyOf(flip(ciphertext, prefix + 64), ciphertext.length - 1))));
    byte[] badSender = senderKey.clone();
    badSender[0] = 5;
    lists.add(Collections.singletonList(edk("raw-ecdh", providerInfo(badSender, recipientKey), Arrays.copyOf(ciphertext, 47))));
    // Binary provider info (as a Raw AES key has) in the no-match message (bug B11), alone and around a hierarchy key.
    EncryptedDataKey binary = edk("aes-namespace", new byte[] { 'k', (byte) 0x80, 0, 0, 0, 12 }, ciphertext);
    EncryptedDataKey shortHierarchy = edk("aws-kms-hierarchy", "branch".getBytes(StandardCharsets.UTF_8), bytes(43, 1));
    EncryptedDataKey fullHierarchy = edk("aws-kms-hierarchy", "branch".getBytes(StandardCharsets.UTF_8), bytes(48 + 44, 1));
    lists.add(Collections.singletonList(binary));
    lists.add(Arrays.asList(binary, shortHierarchy));
    lists.add(Arrays.asList(shortHierarchy, binary));
    lists.add(Arrays.asList(fullHierarchy, binary));
    // Filtering fails before any key is tried; decryption failures are collected and the next key tried.
    lists.add(Arrays.asList(good, edk("raw-ecdh", new byte[3], ciphertext)));
    lists.add(Arrays.asList(edk("raw-ecdh", info, flip(ciphertext, prefix + 64)), edk("other", info, ciphertext), good));
    lists.add(Arrays.asList(edk("raw-ecdh", info, flip(ciphertext, prefix + 40)), edk("raw-ecdh", info, new byte[0])));
    return lists;
  }

  private void assertSameCreate(CreateRawEcdhKeyringInput input) {
    String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, "CreateRawEcdhKeyring", input) == null ? "null" : "keyring");
    String actual = ReferenceMpl.outcome(() -> MPL.CreateRawEcdhKeyring(input) == null ? "null" : "keyring");
    assertEquals(expected, actual, ReferenceMpl.describe(input));
    outcomes.record("Create", actual);
  }

  private Pair ecdh(CreateRawEcdhKeyringInput input) {
    return new Pair(MPL.CreateRawEcdhKeyring(input), ReferenceMpl.call(reference, "CreateRawEcdhKeyring", input));
  }

  // Private keys: valid, other curves, malformed, and not EC.
  private static List<byte[]> privateKeyVariants(ECDHCurveSpec curve, Keys keys) {
    List<byte[]> variants = new ArrayList<>(Arrays.asList(
      keys.senderPrivate,
      keys.recipientPrivate,
      new byte[0],
      "not a key".getBytes(StandardCharsets.US_ASCII),
      pem("PUBLIC KEY", keys.senderPublic),
      pem("PRIVATE KEY", new byte[] { 0x30, 0 }),
      Arrays.copyOf(keys.senderPrivate, keys.senderPrivate.length - 30),
      rsaPrivateKey()
    ));
    for (ECDHCurveSpec other : NIST) {
      if (other != curve) {
        variants.add(Keys.of("testVectorKeys", other).senderPrivate);
      }
    }
    return variants;
  }

  // Public keys: valid, other curves, other encodings of a valid key, invalid points, and malformed.
  // A point with x = 0 is a known difference: see knownDifferenceR11ZeroXKeys.
  private static List<byte[]> publicKeyVariants(ECDHCurveSpec curve, Keys keys) {
    ECNamedCurveParameterSpec spec = curveOf(curve);
    ECPoint point = spec.getCurve().decodePoint(compressed(curve, keys.recipientPublic));
    List<byte[]> variants = new ArrayList<>(Arrays.asList(
      keys.recipientPublic,
      keys.senderPublic,
      new byte[0],
      bytes(20, 0x41),
      Arrays.copyOf(keys.recipientPublic, keys.recipientPublic.length - 1),
      concat(keys.recipientPublic, new byte[] { 0 }),
      flip(keys.recipientPublic, keys.recipientPublic.length - 1),
      spki(namedCurve(curve), point.getEncoded(true)),
      spki(new X962Parameters(new X9ECParameters(spec.getCurve(), new org.bouncycastle.asn1.x9.X9ECPoint(spec.getG(), false), spec.getN(), spec.getH())), point.getEncoded(false)),
      // Builds on both sides; decrypting with it is known difference R44.
      hybrid(curve, keys.recipientPublic),
      // A point with x = 0 in a non-standard encoding fails the length check first, alike on both sides.
      spki(namedCurve(curve), compressed(curve, zeroXKey(curve))),
      pem("PUBLIC KEY", keys.recipientPublic)
    ));
    for (ECDHCurveSpec other : NIST) {
      if (other != curve) {
        variants.add(Keys.of("testVectorKeys", other).recipientPublic);
      }
    }
    for (JsonNode invalid : ASYMMETRIC.get("ecdhInvalidPublicKeys")) {
      if (invalid.get("curve").asText().equals(curve.name())) {
        variants.add(hex(invalid.get("der").asText()));
      }
    }
    return variants;
  }

  private static CreateRawEcdhKeyringInput input(ECDHCurveSpec curve, RawEcdhStaticConfigurations scheme) {
    return CreateRawEcdhKeyringInput.builder().curveSpec(curve).KeyAgreementScheme(scheme).build();
  }

  private static RawEcdhStaticConfigurations rawPrivate(byte[] senderPrivate, byte[] recipientPublic) {
    return RawEcdhStaticConfigurations
      .builder()
      .RawPrivateKeyToStaticPublicKey(
        RawPrivateKeyToStaticPublicKeyInput.builder().senderStaticPrivateKey(ByteBuffer.wrap(senderPrivate)).recipientPublicKey(ByteBuffer.wrap(recipientPublic)).build()
      )
      .build();
  }

  private static RawEcdhStaticConfigurations ephemeral(byte[] recipientPublic) {
    return RawEcdhStaticConfigurations
      .builder()
      .EphemeralPrivateKeyToStaticPublicKey(EphemeralPrivateKeyToStaticPublicKeyInput.builder().recipientPublicKey(ByteBuffer.wrap(recipientPublic)).build())
      .build();
  }

  private static RawEcdhStaticConfigurations discovery(byte[] recipientPrivate) {
    return RawEcdhStaticConfigurations
      .builder()
      .PublicKeyDiscovery(PublicKeyDiscoveryInput.builder().recipientStaticPrivateKey(ByteBuffer.wrap(recipientPrivate)).build())
      .build();
  }

  /** A sender and a recipient key pair on one curve. */
  static final class Keys {

    final byte[] senderPrivate;
    final byte[] senderPublic;
    final byte[] recipientPrivate;
    final byte[] recipientPublic;

    private Keys(JsonNode node) {
      senderPrivate = node.get("senderPrivatePem").asText().getBytes(StandardCharsets.UTF_8);
      senderPublic = hex(node.get("senderPublicDer").asText());
      recipientPrivate = node.get("recipientPrivatePem").asText().getBytes(StandardCharsets.UTF_8);
      recipientPublic = hex(node.get("recipientPublicDer").asText());
    }

    static Keys of(String source, ECDHCurveSpec curve) {
      for (JsonNode node : VECTORS.get(source)) {
        if (node.get("curve").asText().equals(curve.name())) {
          return new Keys(node);
        }
      }
      throw new IllegalArgumentException(source + " has no " + curve);
    }
  }

  static int compressedLength(ECDHCurveSpec curve) {
    return curve == ECDHCurveSpec.ECC_NIST_P256 ? 33 : curve == ECDHCurveSpec.ECC_NIST_P384 ? 49 : 67;
  }

  static byte[] providerInfo(byte[] senderKey, byte[] recipientKey) {
    return ByteBuffer
      .allocate(1 + 4 + recipientKey.length + 4 + senderKey.length)
      .put((byte) 1)
      .putInt(recipientKey.length)
      .put(recipientKey)
      .putInt(senderKey.length)
      .put(senderKey)
      .array();
  }

  static byte[] withUint32(byte[] info, int index, long value) {
    byte[] copy = info.clone();
    ByteBuffer.wrap(copy, index, 4).putInt((int) value);
    return copy;
  }

  static byte[] compressed(ECDHCurveSpec curve, byte[] publicKeyDer) {
    return curveOf(curve).getCurve().decodePoint(SubjectPublicKeyInfo.getInstance(publicKeyDer).getPublicKeyData().getBytes()).getEncoded(true);
  }

  // The hybrid SEC 1 encoding of a public key's point: the uncompressed point with prefix 6 + the parity of y.
  static byte[] hybrid(ECDHCurveSpec curve, byte[] publicKeyDer) {
    byte[] compressed = compressed(curve, publicKeyDer);
    byte[] point = curveOf(curve).getCurve().decodePoint(compressed).getEncoded(false);
    point[0] = (byte) (compressed[0] + 4);
    return spki(namedCurve(curve), point);
  }

  // A point on the curve with x = 0, which ValidatePublicKey reports as invalid: y = sqrt(b), as p = 3 mod 4.
  static byte[] zeroXKey(ECDHCurveSpec curve) {
    ECNamedCurveParameterSpec spec = curveOf(curve);
    BigInteger p = spec.getCurve().getField().getCharacteristic();
    BigInteger b = spec.getCurve().getB().toBigInteger();
    BigInteger y = b.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
    assertTrue(y.multiply(y).mod(p).equals(b), curve + " has no point with x = 0");
    return spki(namedCurve(curve), spec.getCurve().createPoint(BigInteger.ZERO, y).getEncoded(false));
  }

  static byte[] generatePublicKey(ECDHCurveSpec curve) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec(curveName(curve)));
      return generator.generateKeyPair().getPublic().getEncoded();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] rsaPrivateKey() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(1024);
      return pem("PRIVATE KEY", generator.generateKeyPair().getPrivate().getEncoded());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] spki(ASN1Encodable parameters, byte[] point) {
    try {
      return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, parameters), point).getEncoded();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static X962Parameters namedCurve(ECDHCurveSpec curve) {
    return new X962Parameters(org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID(curveName(curve)));
  }

  static ECNamedCurveParameterSpec curveOf(ECDHCurveSpec curve) {
    return ECNamedCurveTable.getParameterSpec(curveName(curve));
  }

  static String curveName(ECDHCurveSpec curve) {
    return curve == ECDHCurveSpec.ECC_NIST_P256 ? "secp256r1" : curve == ECDHCurveSpec.ECC_NIST_P384 ? "secp384r1" : "secp521r1";
  }

  static byte[] pem(String type, byte[] der) {
    StringWriter text = new StringWriter();
    try (PemWriter writer = new PemWriter(text)) {
      writer.writeObject(new PemObject(type, der));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return text.toString().getBytes(StandardCharsets.US_ASCII);
  }

  static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  static byte[] hex(String hex) {
    byte[] out = new byte[hex.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
  }

  private static JsonNode read(String resource) {
    try (InputStream stream = RawEcdhKeyringTest.class.getResourceAsStream(resource)) {
      return new ObjectMapper().readTree(stream);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
