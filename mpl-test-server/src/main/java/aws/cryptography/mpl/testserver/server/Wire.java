package aws.cryptography.mpl.testserver.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DbeAlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.EsdkCommitmentPolicy;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.PaddingScheme;

/**
 * Model shapes to native MPL values and back. The model carries ESDK suites and commitment
 * policies only, under the constant names the native enums use (policies with an {@code ESDK_} prefix).
 *
 * <p>The native materials types are built, not assembled field by field, so a wire materials
 * structure goes through the same builder and {@code with...} checks a keyring's input would.
 * A structure those checks reject is rejected by the MPL (MPLClientError); a structure the native
 * types cannot express at all is a GenericServerError naming what could not be carried.
 */
final class Wire {

  /** Where a signing suite's materials carry the base64 compressed verification key. */
  static final String PUBLIC_KEY_FIELD = "aws-crypto-public-key";

  private static final String ESDK_POLICY_PREFIX = "ESDK_";

  private Wire() {}

  // ---------------------------------------------------------------------
  // Enumerations
  // ---------------------------------------------------------------------

  static EsdkAlgorithmSuite suite(String wire) {
    try {
      return EsdkAlgorithmSuite.valueOf(wire);
    } catch (IllegalArgumentException e) {
      throw unknown("algorithm suite", wire);
    }
  }

  // GetAlgorithmSuiteInfo takes an id of either format; the formats' ids do not overlap.
  static AlgorithmSuite suiteFromBinaryId(byte[] binaryId) {
    try {
      return EsdkAlgorithmSuite.fromBinaryId(binaryId);
    } catch (ValidationException e) {
      return DbeAlgorithmSuite.fromBinaryId(binaryId);
    }
  }

  static String suiteToWire(AlgorithmSuite suite) {
    if (suite.format() != AlgorithmSuite.Format.ESDK) {
      throw ModeledError.generic("the MPL returned a non-ESDK algorithm suite, which the model cannot carry: " + suite);
    }
    return suite.name();
  }

  static EsdkCommitmentPolicy commitmentPolicy(String wire) {
    if (!wire.startsWith(ESDK_POLICY_PREFIX)) {
      throw unknown("commitment policy", wire);
    }
    try {
      return EsdkCommitmentPolicy.valueOf(wire.substring(ESDK_POLICY_PREFIX.length()));
    } catch (IllegalArgumentException e) {
      throw unknown("commitment policy", wire);
    }
  }

  static AesWrappingAlg aesWrappingAlg(String wire) {
    try {
      return AesWrappingAlg.valueOf(wire);
    } catch (IllegalArgumentException e) {
      throw unknown("AES wrapping algorithm", wire);
    }
  }

  static PaddingScheme paddingScheme(String wire) {
    try {
      return PaddingScheme.valueOf(wire);
    } catch (IllegalArgumentException e) {
      throw unknown("padding scheme", wire);
    }
  }

  static EcdhCurveSpec ecdhCurveSpec(String wire) {
    try {
      return EcdhCurveSpec.valueOf(wire);
    } catch (IllegalArgumentException e) {
      throw unknown("ECDH curve", wire);
    }
  }

  private static ModeledError unknown(String what, String wire) {
    return ModeledError.generic("unknown " + what + ": " + wire);
  }

  // ---------------------------------------------------------------------
  // Algorithm suite info
  // ---------------------------------------------------------------------

  /** The model's AlgorithmSuiteInfo, which carries ESDK suites only. */
  static ObjectNode suiteInfoToWire(AlgorithmSuite suite) {
    ObjectNode wire = Cbor.object();
    wire.put("id", suiteToWire(suite));
    wire.put("binaryId", suite.binaryId());
    wire.put("messageVersion", suite.messageVersion());
    ObjectNode encrypt = wire.putObject("encrypt");
    encrypt.put("keyLength", suite.dataKeyLength());
    encrypt.put("tagLength", suite.tagLength());
    encrypt.put("ivLength", suite.ivLength());
    ObjectNode kdf = wire.putObject("kdf");
    if (suite.keyDerivation() == AlgorithmSuite.KeyDerivation.IDENTITY) {
      kdf.putObject("IDENTITY");
    } else {
      putHkdf(kdf, suite.keyDerivation().hmacAlgorithm().get(), suite.kdfSaltLength(), suite.dataKeyLength(), suite.dataKeyLength());
    }
    ObjectNode commitment = wire.putObject("commitment");
    if (suite.isCommitting()) {
      // The native suite has no commitment salt of its own.
      // AlgorithmSuites.dfy derives the commitment key with the data key's HKDF, salt included.
      putHkdf(
        commitment,
        suite.commitmentHmacAlgorithm().get(),
        suite.kdfSaltLength(),
        suite.dataKeyLength(),
        suite.commitmentKeyLength()
      );
    } else {
      commitment.putObject("None");
    }
    ObjectNode signature = wire.putObject("signature");
    if (suite.signature().isPresent()) {
      signature.put("ECDSA", suite.signature().get().name());
    } else {
      signature.putObject("None");
    }
    return wire;
  }

  private static void putHkdf(ObjectNode union, String jcaMac, int saltLength, int inputKeyLength, int outputKeyLength) {
    ObjectNode hkdf = union.putObject("HKDF");
    hkdf.put("hmac", digest(jcaMac));
    hkdf.put("saltLength", saltLength);
    hkdf.put("inputKeyLength", inputKeyLength);
    hkdf.put("outputKeyLength", outputKeyLength);
  }

  private static String digest(String jcaMac) {
    switch (jcaMac) {
      case "HmacSHA256":
        return "SHA_256";
      case "HmacSHA384":
        return "SHA_384";
      case "HmacSHA512":
        return "SHA_512";
      default:
        throw ModeledError.generic("the MPL returned an HMAC the model cannot carry: " + jcaMac);
    }
  }

  // ---------------------------------------------------------------------
  // Encryption context and encrypted data keys
  // ---------------------------------------------------------------------

  /** An optional context member; absent means empty. */
  static EncryptionContext encryptionContext(JsonNode node, String field) {
    return EncryptionContext.copyOf(Cbor.stringMap(node, field));
  }

  static EncryptionContext requiredEncryptionContext(JsonNode node, String field) {
    return EncryptionContext.copyOf(Cbor.requiredStringMap(node, field));
  }

  static List<EncryptedDataKey> edks(JsonNode node, String field) {
    List<EncryptedDataKey> edks = new ArrayList<>();
    for (JsonNode edk : Cbor.list(node, field)) {
      edks.add(
        EncryptedDataKey.builder()
            .keyProviderId(Cbor.string(edk, "keyProviderId"))
            .keyProviderInfo(Cbor.blob(edk, "keyProviderInfo"))
            .ciphertext(Cbor.blob(edk, "ciphertext"))
            .build()
      );
    }
    return edks;
  }

  static ArrayNode edksToWire(List<EncryptedDataKey> edks) {
    ArrayNode wire = Cbor.array();
    for (EncryptedDataKey edk : edks) {
      ObjectNode entry = wire.addObject();
      entry.put("keyProviderId", edk.keyProviderId());
      entry.put("keyProviderInfo", edk.keyProviderInfo());
      entry.put("ciphertext", edk.ciphertext());
    }
    return wire;
  }

  // ---------------------------------------------------------------------
  // Materials
  // ---------------------------------------------------------------------

  /**
   * Rebuilds encryption materials: the builder with the context and signing key pair, then the data key,
   * then each encrypted data key in order. On the wire a signing suite's verification key is already in the
   * context; the builder takes it as the second half of the key pair and adds it back.
   */
  static EncryptionMaterials encryptionMaterials(JsonNode wire) {
    AlgorithmSuite suite = suite(Cbor.string(wire, "algorithmSuiteId"));
    Map<String, String> context = Cbor.requiredStringMap(wire, "encryptionContext");
    List<EncryptedDataKey> edks = edks(wire, "encryptedDataKeys");
    byte[] plaintextDataKey = Cbor.optionalBlob(wire, "plaintextDataKey");
    byte[] signingKey = Cbor.optionalBlob(wire, "signingKey");
    List<byte[]> symmetricSigningKeys = Cbor.optionalBlobList(wire, "symmetricSigningKeys");
    if (symmetricSigningKeys != null && !symmetricSigningKeys.isEmpty() && symmetricSigningKeys.size() != edks.size()) {
      throw ModeledError.generic(
        "the native materials pair each symmetric signing key with an encrypted data key; got " +
        symmetricSigningKeys.size() + " keys for " + edks.size() + " encrypted data keys"
      );
    }

    EncryptionMaterials.Builder builder = EncryptionMaterials
      .builder(suite)
      .requiredEncryptionContextKeys(Cbor.requiredStringList(wire, "requiredEncryptionContextKeys"));
    if (signingKey != null) {
      try {
        String encoded = context.remove(PUBLIC_KEY_FIELD);
        if (encoded == null && suite.isSigning()) {
          // Without the context entry there is no public half; the builder would invent an empty one.
          throw ModeledError.generic(
            "the native encryption materials take a signing key only with its verification key, which the " +
            PUBLIC_KEY_FIELD + " context entry carries; the entry is missing"
          );
        }
        // A non-signing suite rejects any key pair in the builder, as the MPL rejects these materials.
        byte[] verificationKey = encoded == null ? new byte[0] : base64(encoded);
        try (SecretBytes secret = SecretBytes.copyOf(signingKey)) {
          builder.signingKeyPair(secret, verificationKey);
        }
      } finally {
        Arrays.fill(signingKey, (byte) 0);
      }
    }
    EncryptionMaterials materials = builder.encryptionContext(EncryptionContext.copyOf(context)).build();

    if (plaintextDataKey != null) {
      materials = replace(materials, withPlaintextDataKey(materials, plaintextDataKey));
    }
    for (int i = 0; i < edks.size(); i++) {
      EncryptionMaterials next;
      if (symmetricSigningKeys == null || symmetricSigningKeys.isEmpty()) {
        next = materials.withEncryptedDataKey(edks.get(i));
      } else {
        byte[] key = symmetricSigningKeys.get(i);
        try (SecretBytes secret = SecretBytes.copyOf(key)) {
          next = materials.withEncryptedDataKey(edks.get(i), secret);
        } finally {
          Arrays.fill(key, (byte) 0);
        }
      }
      materials = replace(materials, next);
    }
    return materials;
  }

  /** Rebuilds decryption materials: the builder derives the verification key from the context. */
  static DecryptionMaterials decryptionMaterials(JsonNode wire) {
    AlgorithmSuite suite = suite(Cbor.string(wire, "algorithmSuiteId"));
    byte[] plaintextDataKey = Cbor.optionalBlob(wire, "plaintextDataKey");
    byte[] verificationKey = Cbor.optionalBlob(wire, "verificationKey");
    byte[] symmetricSigningKey = Cbor.optionalBlob(wire, "symmetricSigningKey");
    try {
      // Materials.dfy ValidDecryptionMaterials holds these invalid for every suite, so they are MPL
      // rejections, not shapes the native types merely cannot express.
      if (suite.isSigning() != (verificationKey != null)) {
        throw ModeledError.mpl(
          suite.isSigning()
            ? "A signing suite's decryption materials need a verification key."
            : "Verification key can not exist in non-signed Algorithm Suites."
        );
      }
      if (symmetricSigningKey != null && plaintextDataKey == null) {
        throw ModeledError.mpl("A symmetric signing key needs a plaintext data key.");
      }
      DecryptionMaterials materials = DecryptionMaterials
        .builder(suite)
        .encryptionContext(requiredEncryptionContext(wire, "encryptionContext"))
        .requiredEncryptionContextKeys(Cbor.requiredStringList(wire, "requiredEncryptionContextKeys"))
        .build();
      if (!Arrays.equals(verificationKey, materials.verificationKey().orElse(null))) {
        // Dafny accepts a verification key that differs from the context's; the native materials cannot hold one.
        throw ModeledError.generic(
          "the native decryption materials derive the verification key from the encryption context; " +
          "the verificationKey member does not match it"
        );
      }
      if (plaintextDataKey != null) {
        try (SecretBytes key = SecretBytes.copyOf(plaintextDataKey)) {
          DecryptionMaterials next;
          if (symmetricSigningKey == null) {
            next = materials.withPlaintextDataKey(key);
          } else {
            try (SecretBytes signing = SecretBytes.copyOf(symmetricSigningKey)) {
              next = materials.withPlaintextDataKey(key, signing);
            }
          }
          materials.destroy();
          materials = next;
        }
      }
      return materials;
    } finally {
      if (plaintextDataKey != null) {
        Arrays.fill(plaintextDataKey, (byte) 0);
      }
      if (symmetricSigningKey != null) {
        Arrays.fill(symmetricSigningKey, (byte) 0);
      }
    }
  }

  static ObjectNode encryptionMaterialsToWire(EncryptionMaterials materials) {
    ObjectNode wire = Cbor.object();
    wire.put("algorithmSuiteId", suiteToWire(materials.algorithmSuite()));
    Cbor.putMap(wire, "encryptionContext", materials.encryptionContext());
    wire.set("encryptedDataKeys", edksToWire(materials.encryptedDataKeys()));
    Cbor.putStringList(wire, "requiredEncryptionContextKeys", materials.requiredEncryptionContextKeys());
    putSecret(wire, "plaintextDataKey", materials.plaintextDataKey().orElse(null));
    putSecret(wire, "signingKey", materials.signingKey().orElse(null));
    putSymmetricSigningKeys(wire, materials);
    return wire;
  }

  static ObjectNode decryptionMaterialsToWire(DecryptionMaterials materials) {
    ObjectNode wire = Cbor.object();
    wire.put("algorithmSuiteId", suiteToWire(materials.algorithmSuite()));
    Cbor.putMap(wire, "encryptionContext", materials.encryptionContext());
    Cbor.putStringList(wire, "requiredEncryptionContextKeys", materials.requiredEncryptionContextKeys());
    putSecret(wire, "plaintextDataKey", materials.plaintextDataKey().orElse(null));
    if (materials.verificationKey().isPresent()) {
      wire.put("verificationKey", materials.verificationKey().get());
    }
    putSecret(wire, "symmetricSigningKey", materials.symmetricSigningKey().orElse(null));
    return wire;
  }

  /**
   * The list is present exactly when the suite signs symmetrically, as the MPL's
   * InitializeEncryptionMaterials sets it; the native accessor returns an empty list otherwise.
   */
  static void putSymmetricSigningKeys(ObjectNode wire, EncryptionMaterials materials) {
    if (!materials.algorithmSuite().isSymmetricSigning()) {
      return;
    }
    ArrayNode keys = wire.putArray("symmetricSigningKeys");
    for (SecretBytes key : materials.symmetricSigningKeys()) {
      keys.add(key.toByteArray());
    }
  }

  static void putSecret(ObjectNode wire, String field, SecretBytes secret) {
    if (secret != null) {
      wire.put(field, secret.toByteArray());
    }
  }

  private static EncryptionMaterials withPlaintextDataKey(EncryptionMaterials materials, byte[] plaintextDataKey) {
    try (SecretBytes key = SecretBytes.copyOf(plaintextDataKey)) {
      return materials.withPlaintextDataKey(key);
    } finally {
      Arrays.fill(plaintextDataKey, (byte) 0);
    }
  }

  /** Each {@code with...} result owns copies of the secrets, so the superseded materials are destroyed. */
  private static EncryptionMaterials replace(EncryptionMaterials old, EncryptionMaterials next) {
    old.destroy();
    return next;
  }

  private static byte[] base64(String encoded) {
    try {
      return Base64.getDecoder().decode(encoded);
    } catch (IllegalArgumentException e) {
      throw ModeledError.generic(
        "the native encryption materials need the " + PUBLIC_KEY_FIELD + " context entry as base64; it is not"
      );
    }
  }
}
