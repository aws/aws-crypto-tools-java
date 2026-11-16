package aws.cryptography.mpl.testserver.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.EsdkCommitmentPolicy;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.RequiredEncryptionContextCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.MultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyAgreementScheme;
import software.amazon.cryptography.materialproviders.keyrings.RawRsaKeyring;

/**
 * Maps each TestServer operation to the native MPL. Keyrings and CMMs live in typed registries keyed
 * by an opaque UUID handle; a handle is only looked up in the registry of the kind the operation
 * expects, so a wrong-kind handle is unknown there.
 */
final class Operations {

  private final Map<String, Keyring> keyrings = new ConcurrentHashMap<>();
  private final Map<String, CryptographicMaterialsManager> cmms = new ConcurrentHashMap<>();

  ObjectNode dispatch(String operation, JsonNode request) {
    switch (operation) {
      case "CreateRawAesKeyring":
        return createRawAesKeyring(request);
      case "CreateDefaultCmm":
        return createDefaultCmm(request);
      case "InitializeEncryptionMaterials":
        return initializeEncryptionMaterials(request);
      case "InitializeDecryptionMaterials":
        return initializeDecryptionMaterials(request);
      case "OnEncrypt":
        return onEncrypt(request);
      case "OnDecrypt":
        return onDecrypt(request);
      case "GetEncryptionMaterials":
        return getEncryptionMaterials(request);
      case "DecryptMaterials":
        return decryptMaterials(request);
      case "CreateRequiredEncryptionContextCmm":
        return createRequiredEncryptionContextCmm(request);
      case "CreateMultiKeyring":
        return createMultiKeyring(request);
      case "CreateRawRsaKeyring":
        return createRawRsaKeyring(request);
      case "CreateRawEcdhKeyring":
        return createRawEcdhKeyring(request);
      case "GetAlgorithmSuiteInfo":
        return Wire.suiteInfoToWire(AlgorithmSuite.fromBinaryId(Cbor.blob(request, "binaryId")));
      case "ValidateCommitmentPolicyOnEncrypt":
        return validateCommitmentPolicyOnEncrypt(request);
      case "ValidateCommitmentPolicyOnDecrypt":
        return validateCommitmentPolicyOnDecrypt(request);
      case "ValidEncryptionMaterialsTransition":
        return validEncryptionMaterialsTransition(request);
      case "ValidDecryptionMaterialsTransition":
        return validDecryptionMaterialsTransition(request);
      case "EncryptionMaterialsHasPlaintextDataKey":
        return encryptionMaterialsHasPlaintextDataKey(request);
      case "DecryptionMaterialsWithPlaintextDataKey":
        return decryptionMaterialsWithPlaintextDataKey(request);
      default:
        throw ModeledError.generic("unknown operation: " + operation);
    }
  }

  // ---------------------------------------------------------------------
  // Construction
  // ---------------------------------------------------------------------

  private ObjectNode createRawAesKeyring(JsonNode request) {
    String keyNamespace = Cbor.string(request, "keyNamespace");
    String keyName = Cbor.string(request, "keyName");
    byte[] wrappingKey = Cbor.blob(request, "wrappingKey");
    RawAesKeyring keyring;
    try (SecretBytes key = SecretBytes.copyOf(wrappingKey)) {
      keyring = RawAesKeyring
        .builder()
        .keyNamespace(keyNamespace)
        .keyName(keyName)
        .wrappingKey(key)
        .wrappingAlg(Wire.aesWrappingAlg(Cbor.string(request, "wrappingAlg")))
        .build();
    } finally {
      Arrays.fill(wrappingKey, (byte) 0);
    }
    ObjectNode response = Cbor.object();
    response.put("keyringId", register(keyrings, keyring));
    return response;
  }

  private ObjectNode createDefaultCmm(JsonNode request) {
    Keyring keyring = lookup(keyrings, Cbor.string(request, "keyringId"), "keyringId");
    ObjectNode response = Cbor.object();
    response.put("cmmId", register(cmms, DefaultCryptographicMaterialsManager.of(keyring)));
    return response;
  }

  private ObjectNode createRequiredEncryptionContextCmm(JsonNode request) {
    CryptographicMaterialsManager underlying = lookup(cmms, Cbor.string(request, "underlyingCmmId"), "underlyingCmmId");
    CryptographicMaterialsManager cmm = RequiredEncryptionContextCryptographicMaterialsManager
      .builder()
      .underlyingCmm(underlying)
      .requiredEncryptionContextKeys(Cbor.requiredStringList(request, "requiredEncryptionContextKeys"))
      .build();
    ObjectNode response = Cbor.object();
    response.put("cmmId", register(cmms, cmm));
    return response;
  }

  private ObjectNode createMultiKeyring(JsonNode request) {
    MultiKeyring.Builder builder = MultiKeyring.builder();
    if (Cbor.present(request, "generatorKeyringId")) {
      builder.generator(lookup(keyrings, Cbor.string(request, "generatorKeyringId"), "generatorKeyringId"));
    }
    List<Keyring> children = new ArrayList<>();
    for (String id : Cbor.requiredStringList(request, "childKeyringIds")) {
      children.add(lookup(keyrings, id, "childKeyringIds"));
    }
    return keyringResponse(builder.childKeyrings(children).build());
  }

  private ObjectNode createRawRsaKeyring(JsonNode request) {
    RawRsaKeyring.Builder builder = RawRsaKeyring
      .builder()
      .keyNamespace(Cbor.string(request, "keyNamespace"))
      .keyName(Cbor.string(request, "keyName"))
      .paddingScheme(Wire.paddingScheme(Cbor.string(request, "paddingScheme")));
    byte[] publicKey = Cbor.optionalBlob(request, "publicKey");
    if (publicKey != null) {
      builder.publicKey(publicKey);
    }
    byte[] privateKey = Cbor.optionalBlob(request, "privateKey");
    if (privateKey == null) {
      return keyringResponse(builder.build());
    }
    try (SecretBytes key = SecretBytes.copyOf(privateKey)) {
      return keyringResponse(builder.privateKey(key).build());
    } finally {
      Arrays.fill(privateKey, (byte) 0);
    }
  }

  private ObjectNode createRawEcdhKeyring(JsonNode request) {
    EcdhCurveSpec curve = Wire.ecdhCurveSpec(Cbor.string(request, "curveSpec"));
    Map.Entry<String, JsonNode> scheme = Cbor.union(request, "KeyAgreementScheme");
    JsonNode config = scheme.getValue();
    switch (scheme.getKey()) {
      case "RawPrivateKeyToStaticPublicKey":
        return rawEcdhKeyring(
          curve,
          Cbor.blob(config, "senderStaticPrivateKey"),
          key -> RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey(key, Cbor.blob(config, "recipientPublicKey"))
        );
      case "EphemeralPrivateKeyToStaticPublicKey":
        return keyringResponse(
          RawEcdhKeyring
            .builder()
            .curveSpec(curve)
            .keyAgreementScheme(
              RawEcdhKeyAgreementScheme.ephemeralPrivateKeyToStaticPublicKey(Cbor.blob(config, "recipientPublicKey"))
            )
            .build()
        );
      case "PublicKeyDiscovery":
        return rawEcdhKeyring(curve, Cbor.blob(config, "recipientStaticPrivateKey"), RawEcdhKeyAgreementScheme::publicKeyDiscovery);
      default:
        throw ModeledError.generic("unknown key agreement scheme: " + scheme.getKey());
    }
  }

  /** A keyring over a scheme that holds {@code privateKey}; the keyring keeps its own copy. */
  private ObjectNode rawEcdhKeyring(
    EcdhCurveSpec curve,
    byte[] privateKey,
    Function<SecretBytes, RawEcdhKeyAgreementScheme> scheme
  ) {
    try (SecretBytes key = SecretBytes.copyOf(privateKey)) {
      return keyringResponse(RawEcdhKeyring.builder().curveSpec(curve).keyAgreementScheme(scheme.apply(key)).build());
    } finally {
      Arrays.fill(privateKey, (byte) 0);
    }
  }

  private ObjectNode keyringResponse(Keyring keyring) {
    ObjectNode response = Cbor.object();
    response.put("keyringId", register(keyrings, keyring));
    return response;
  }

  // ---------------------------------------------------------------------
  // Materials initialization and the keyring interface
  // ---------------------------------------------------------------------

  private ObjectNode initializeEncryptionMaterials(JsonNode request) {
    EncryptionMaterials materials = EncryptionMaterials
      .builder(Wire.suite(Cbor.string(request, "algorithmSuiteId")))
      .encryptionContext(Wire.requiredEncryptionContext(request, "encryptionContext"))
      .requiredEncryptionContextKeys(Cbor.requiredStringList(request, "requiredEncryptionContextKeys"))
      .build();
    try {
      ObjectNode response = Cbor.object();
      response.set("materials", Wire.encryptionMaterialsToWire(materials));
      return response;
    } finally {
      materials.destroy();
    }
  }

  private ObjectNode initializeDecryptionMaterials(JsonNode request) {
    DecryptionMaterials materials = DecryptionMaterials
      .builder(Wire.suite(Cbor.string(request, "algorithmSuiteId")))
      .encryptionContext(Wire.requiredEncryptionContext(request, "encryptionContext"))
      .requiredEncryptionContextKeys(Cbor.requiredStringList(request, "requiredEncryptionContextKeys"))
      .build();
    try {
      ObjectNode response = Cbor.object();
      response.set("materials", Wire.decryptionMaterialsToWire(materials));
      return response;
    } finally {
      materials.destroy();
    }
  }

  private ObjectNode onEncrypt(JsonNode request) {
    Keyring keyring = lookup(keyrings, Cbor.string(request, "keyringId"), "keyringId");
    EncryptionMaterials input = Wire.encryptionMaterials(Cbor.member(request, "materials"));
    try {
      EncryptionMaterials output = keyring.onEncrypt(OnEncryptRequest.builder().materials(input).build()).materials();
      try {
        ObjectNode response = Cbor.object();
        response.set("materials", Wire.encryptionMaterialsToWire(output));
        return response;
      } finally {
        output.destroy();
      }
    } finally {
      input.destroy();
    }
  }

  private ObjectNode onDecrypt(JsonNode request) {
    Keyring keyring = lookup(keyrings, Cbor.string(request, "keyringId"), "keyringId");
    DecryptionMaterials input = Wire.decryptionMaterials(Cbor.member(request, "materials"));
    try {
      DecryptionMaterials output = keyring.onDecrypt(
        OnDecryptRequest.builder().materials(input).encryptedDataKeys(Wire.edks(request, "encryptedDataKeys")).build()
      ).materials();
      try {
        ObjectNode response = Cbor.object();
        response.set("materials", Wire.decryptionMaterialsToWire(output));
        return response;
      } finally {
        output.destroy();
      }
    } finally {
      input.destroy();
    }
  }

  // ---------------------------------------------------------------------
  // CMM
  // ---------------------------------------------------------------------

  private ObjectNode getEncryptionMaterials(JsonNode request) {
    CryptographicMaterialsManager cmm = lookup(cmms, Cbor.string(request, "cmmId"), "cmmId");
    GetEncryptionMaterialsRequest.Builder input = GetEncryptionMaterialsRequest
      .builder()
      .encryptionContext(Wire.encryptionContext(request, "encryptionContext"))
      .commitmentPolicy(Wire.commitmentPolicy(Cbor.string(request, "commitmentPolicy")));
    if (Cbor.present(request, "algorithmSuiteId")) {
      input.algorithmSuiteId(Wire.suite(Cbor.string(request, "algorithmSuiteId")));
    }
    if (Cbor.present(request, "maxPlaintextLength")) {
      input.maxPlaintextLength(Cbor.longValue(request, "maxPlaintextLength"));
    }
    if (Cbor.present(request, "requiredEncryptionContextKeys")) {
      input.requiredEncryptionContextKeys(Cbor.stringList(request, "requiredEncryptionContextKeys"));
    }
    EncryptionMaterials materials = cmm.getEncryptionMaterials(input.build()).encryptionMaterials();
    try {
      SecretBytes plaintextDataKey = materials
        .plaintextDataKey()
        .orElseThrow(() -> ModeledError.mpl("no plaintext data key in materials"));
      ObjectNode response = Cbor.object();
      response.put("algorithmSuiteId", Wire.suiteToWire(materials.algorithmSuite()));
      Cbor.putMap(response, "encryptionContext", materials.encryptionContext());
      response.set("encryptedDataKeys", Wire.edksToWire(materials.encryptedDataKeys()));
      Wire.putSecret(response, "plaintextDataKey", plaintextDataKey);
      Wire.putSecret(response, "signingKey", materials.signingKey().orElse(null));
      Wire.putSymmetricSigningKeys(response, materials);
      Cbor.putStringList(response, "requiredEncryptionContextKeys", materials.requiredEncryptionContextKeys());
      return response;
    } finally {
      materials.destroy();
    }
  }

  private ObjectNode decryptMaterials(JsonNode request) {
    CryptographicMaterialsManager cmm = lookup(cmms, Cbor.string(request, "cmmId"), "cmmId");
    DecryptMaterialsRequest.Builder input = DecryptMaterialsRequest
      .builder()
      .algorithmSuiteId(Wire.suite(Cbor.string(request, "algorithmSuiteId")))
      .commitmentPolicy(Wire.commitmentPolicy(Cbor.string(request, "commitmentPolicy")))
      .encryptedDataKeys(Wire.edks(request, "encryptedDataKeys"))
      .encryptionContext(Wire.encryptionContext(request, "encryptionContext"));
    if (Cbor.present(request, "reproducedEncryptionContext")) {
      input.reproducedEncryptionContext(Wire.encryptionContext(request, "reproducedEncryptionContext"));
    }
    DecryptionMaterials materials = cmm.decryptMaterials(input.build()).decryptionMaterials();
    try {
      SecretBytes plaintextDataKey = materials
        .plaintextDataKey()
        .orElseThrow(() -> ModeledError.mpl("no plaintext data key in materials"));
      ObjectNode response = Cbor.object();
      Wire.putSecret(response, "plaintextDataKey", plaintextDataKey);
      Cbor.putMap(response, "encryptionContext", materials.encryptionContext());
      if (materials.verificationKey().isPresent()) {
        response.put("verificationKey", materials.verificationKey().get());
      }
      Wire.putSecret(response, "symmetricSigningKey", materials.symmetricSigningKey().orElse(null));
      Cbor.putStringList(response, "requiredEncryptionContextKeys", materials.requiredEncryptionContextKeys());
      return response;
    } finally {
      materials.destroy();
    }
  }

  // ---------------------------------------------------------------------
  // Validation
  //
  // The native API answers these with a boolean.
  // A false answer is an MPLClientError with the Dafny MPL's message
  // (Commitment.dfy, AwsCryptographyMaterialProvidersOperations.dfy).
  // Wire rebuilds the materials first, so a native builder rejection is an MPLClientError before any check runs.
  // ---------------------------------------------------------------------

  private ObjectNode validateCommitmentPolicyOnEncrypt(JsonNode request) {
    AlgorithmSuite suite = Wire.suite(Cbor.string(request, "algorithm"));
    EsdkCommitmentPolicy policy = Wire.commitmentPolicy(Cbor.string(request, "commitmentPolicy"));
    if (!policy.allowsEncrypt(suite)) {
      throw ModeledError.mpl(
        policy == EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
          ? "Configuration conflict. Commitment policy requires only non-committing algorithm suites"
          : "Configuration conflict. Commitment policy requires only committing algorithm suites"
      );
    }
    return Cbor.object();
  }

  private ObjectNode validateCommitmentPolicyOnDecrypt(JsonNode request) {
    AlgorithmSuite suite = Wire.suite(Cbor.string(request, "algorithm"));
    if (!Wire.commitmentPolicy(Cbor.string(request, "commitmentPolicy")).allowsDecrypt(suite)) {
      throw ModeledError.mpl("Configuration conflict. Commitment policy requires only committing algorithm suites");
    }
    return Cbor.object();
  }

  private ObjectNode validEncryptionMaterialsTransition(JsonNode request) {
    EncryptionMaterials start = Wire.encryptionMaterials(Cbor.member(request, "start"));
    try {
      EncryptionMaterials stop = Wire.encryptionMaterials(Cbor.member(request, "stop"));
      try {
        if (!stop.isValidTransitionFrom(start)) {
          throw ModeledError.mpl("Invalid Encryption Materials Transition");
        }
        return Cbor.object();
      } finally {
        stop.destroy();
      }
    } finally {
      start.destroy();
    }
  }

  private ObjectNode validDecryptionMaterialsTransition(JsonNode request) {
    DecryptionMaterials start = Wire.decryptionMaterials(Cbor.member(request, "start"));
    try {
      DecryptionMaterials stop = Wire.decryptionMaterials(Cbor.member(request, "stop"));
      try {
        if (!stop.isValidTransitionFrom(start)) {
          throw ModeledError.mpl("Invalid Decryption Materials Transition");
        }
        return Cbor.object();
      } finally {
        stop.destroy();
      }
    } finally {
      start.destroy();
    }
  }

  private ObjectNode encryptionMaterialsHasPlaintextDataKey(JsonNode request) {
    EncryptionMaterials materials = Wire.encryptionMaterials(Cbor.member(request, "materials"));
    try {
      if (!materials.isReadyForEncrypt()) {
        throw ModeledError.mpl("Invalid Encryption Materials");
      }
      return Cbor.object();
    } finally {
      materials.destroy();
    }
  }

  private ObjectNode decryptionMaterialsWithPlaintextDataKey(JsonNode request) {
    DecryptionMaterials materials = Wire.decryptionMaterials(Cbor.member(request, "materials"));
    try {
      if (!materials.isReadyForDecrypt()) {
        throw ModeledError.mpl("Invalid Decryption Materials");
      }
      return Cbor.object();
    } finally {
      materials.destroy();
    }
  }

  // ---------------------------------------------------------------------
  // Registry
  // ---------------------------------------------------------------------

  private static <T> String register(Map<String, T> registry, T resource) {
    String id = UUID.randomUUID().toString();
    registry.put(id, resource);
    return id;
  }

  private static <T> T lookup(Map<String, T> registry, String id, String member) {
    if (id.isEmpty()) {
      throw ModeledError.generic(member + " must be non-empty");
    }
    T resource = registry.get(id);
    if (resource == null) {
      throw ModeledError.generic("unknown " + member + ": " + id);
    }
    return resource;
  }
}
