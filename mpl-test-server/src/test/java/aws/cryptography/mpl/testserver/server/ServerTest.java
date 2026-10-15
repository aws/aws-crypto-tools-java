package aws.cryptography.mpl.testserver.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * The server over real HTTP: each operation against the native MPL, the handle and error contract,
 * and the wire materials reconstruction. The cross-language behavior is the commons Tests suite's job;
 * these tests pin what this server adds on top of the library.
 */
class ServerTest {

  private static final String GENERIC = "aws.cryptography.mpl.testserver#GenericServerError";
  private static final String MPL = "aws.cryptography.mpl.testserver#MPLClientError";
  private static final String UNKNOWN_ID = "00000000-0000-4000-8000-000000000000";
  private static final String COMMITTING = "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY";
  private static final String COMMITTING_SIGNING = "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384";
  private static final String REQUIRE_REQUIRE = "ESDK_REQUIRE_ENCRYPT_REQUIRE_DECRYPT";

  private static HttpServer server;
  private static TestClient client;

  @BeforeAll
  static void start() throws IOException {
    server = ServerMain.start(0);
    client = new TestClient(server.getAddress().getPort());
  }

  @AfterAll
  static void stop() {
    server.stop(0);
  }

  // ---------------------------------------------------------------------
  // Keyring interface
  // ---------------------------------------------------------------------

  @Test
  void onEncryptThenOnDecryptRecoversTheDataKey() {
    String keyring = rawAesKeyring("key-a", key(32, 0), "ALG_AES256_GCM_IV12_TAG16");
    JsonNode initial = initializeEncryption(COMMITTING, ec("purpose", "unit"));
    assertFalse(initial.has("plaintextDataKey"));
    assertFalse(initial.has("symmetricSigningKeys"), "an ESDK suite carries no symmetric signing key list");
    assertEquals(0, initial.get("encryptedDataKeys").size());

    JsonNode encrypted = onEncrypt(keyring, initial);
    assertEquals(COMMITTING, encrypted.get("algorithmSuiteId").asText());
    assertEquals("unit", encrypted.get("encryptionContext").get("purpose").asText());
    byte[] dataKey = blob(encrypted, "plaintextDataKey");
    assertEquals(32, dataKey.length);
    JsonNode edk = encrypted.get("encryptedDataKeys").get(0);
    assertEquals("ns", edk.get("keyProviderId").asText());
    byte[] info = blob(edk, "keyProviderInfo");
    byte[] name = "key-a".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(name, Arrays.copyOf(info, name.length));
    ByteBuffer fields = ByteBuffer.wrap(info, name.length, 8);
    assertEquals(128, fields.getInt());
    assertEquals(12, fields.getInt());
    assertEquals(name.length + 8 + 12, info.length);
    assertEquals(32 + 16, blob(edk, "ciphertext").length);

    JsonNode decrypted = onDecrypt(
      rawAesKeyring("key-a", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"),
      initializeDecryption(COMMITTING, ec("purpose", "unit")),
      (ArrayNode) encrypted.get("encryptedDataKeys")
    );
    assertArrayEquals(dataKey, blob(decrypted, "plaintextDataKey"));
  }

  @Test
  void onEncryptOverMaterialsWithADataKeyWrapsThatKey() {
    JsonNode first = onEncrypt(rawAesKeyring("first", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"), initializeEncryption(COMMITTING, ec()));
    JsonNode second = onEncrypt(rawAesKeyring("second", key(32, 1), "ALG_AES256_GCM_IV12_TAG16"), first);

    assertArrayEquals(blob(first, "plaintextDataKey"), blob(second, "plaintextDataKey"));
    assertEquals(2, second.get("encryptedDataKeys").size());
    assertEquals(first.get("encryptedDataKeys").get(0), second.get("encryptedDataKeys").get(0));
    JsonNode decrypted = onDecrypt(
      rawAesKeyring("second", key(32, 1), "ALG_AES256_GCM_IV12_TAG16"),
      initializeDecryption(COMMITTING, ec()),
      (ArrayNode) second.get("encryptedDataKeys")
    );
    assertArrayEquals(blob(first, "plaintextDataKey"), blob(decrypted, "plaintextDataKey"));
  }

  /** The verification key travels inside the context; the rebuilt materials must keep it and the signing key unchanged. */
  @Test
  void signingSuiteMaterialsSurviveTheWire() {
    JsonNode materials = getEncryptionMaterials(defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16")), ec("a", "b"));
    ObjectNode wire = TestClient.object();
    wire.put("algorithmSuiteId", materials.get("algorithmSuiteId").asText());
    wire.set("encryptionContext", materials.get("encryptionContext"));
    wire.set("encryptedDataKeys", materials.get("encryptedDataKeys"));
    wire.putArray("requiredEncryptionContextKeys");
    wire.set("plaintextDataKey", materials.get("plaintextDataKey"));
    wire.set("signingKey", materials.get("signingKey"));

    JsonNode out = onEncrypt(rawAesKeyring("k2", key(32, 1), "ALG_AES256_GCM_IV12_TAG16"), wire);

    assertEquals(materials.get("encryptionContext"), out.get("encryptionContext"));
    assertArrayEquals(blob(materials, "signingKey"), blob(out, "signingKey"));
    assertArrayEquals(blob(materials, "plaintextDataKey"), blob(out, "plaintextDataKey"));
    assertEquals(2, out.get("encryptedDataKeys").size());
  }

  @Test
  void encryptedDataKeysWithoutADataKeyAreRejectedByTheMpl() {
    JsonNode encrypted = onEncrypt(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"), initializeEncryption(COMMITTING, ec()));
    ObjectNode wire = (ObjectNode) encrypted.deepCopy();
    wire.remove("plaintextDataKey");

    assertError(
      MPL,
      "Adding encrypted data keys without a plaintext data key is not allowed.",
      client.call("OnEncrypt", onEncryptRequest(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"), wire))
    );
  }

  @Test
  void onDecryptOverMaterialsWithADataKeyIsAnMplError() {
    String keyring = rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16");
    JsonNode encrypted = onEncrypt(keyring, initializeEncryption(COMMITTING, ec()));
    ObjectNode materials = (ObjectNode) initializeDecryption(COMMITTING, ec()).deepCopy();
    materials.set("plaintextDataKey", encrypted.get("plaintextDataKey"));

    TestClient.Reply reply = client.call("OnDecrypt", onDecryptRequest(keyring, materials, (ArrayNode) encrypted.get("encryptedDataKeys")));
    assertEquals(MPL, reply.errorType(), reply.body.toString());
  }

  @Test
  void aVerificationKeyThatDisagreesWithTheContextIsAGenericError() {
    JsonNode encryption = getEncryptionMaterials(defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16")), ec("a", "b"));
    ObjectNode materials = TestClient.object();
    materials.put("algorithmSuiteId", COMMITTING_SIGNING);
    materials.set("encryptionContext", encryption.get("encryptionContext"));
    materials.putArray("requiredEncryptionContextKeys");
    materials.put("verificationKey", new byte[] { 1 });
    TestClient.Reply reply = client.call(
      "OnDecrypt",
      onDecryptRequest(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"), materials, TestClient.CBOR.createArrayNode())
    );
    assertError(GENERIC,
      "the native decryption materials derive the verification key from the encryption context; " +
      "the verificationKey member does not match it", reply);
  }

  @Test
  void signingMaterialOnNonSigningDecryptionMaterialsIsAnMplError() {
    String keyring = rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16");
    ArrayNode edks = (ArrayNode) onEncrypt(keyring, initializeEncryption(COMMITTING, ec())).get("encryptedDataKeys");

    ObjectNode withVerificationKey = (ObjectNode) initializeDecryption(COMMITTING, ec()).deepCopy();
    withVerificationKey.put("verificationKey", new byte[] { 4, 4, 4, 4 });
    assertError(MPL, "Verification key can not exist in non-signed Algorithm Suites.",
      client.call("OnDecrypt", onDecryptRequest(keyring, withVerificationKey, edks)));

    ObjectNode withSymmetricKey = (ObjectNode) initializeDecryption(COMMITTING, ec()).deepCopy();
    withSymmetricKey.put("symmetricSigningKey", new byte[] { 's', 'y', 'm' });
    assertError(MPL, "A symmetric signing key needs a plaintext data key.",
      client.call("OnDecrypt", onDecryptRequest(keyring, withSymmetricKey, edks)));
  }

  @Test
  void initializingSigningSuiteMaterialsWithoutASigningKeyIsAnMplError() {
    ObjectNode request = TestClient.object();
    request.put("algorithmSuiteId", COMMITTING_SIGNING);
    request.set("encryptionContext", ec());
    request.putArray("requiredEncryptionContextKeys");
    assertEquals(MPL, client.call("InitializeEncryptionMaterials", request).errorType());
  }

  @Test
  void aSigningKeyWithoutItsContextEntryIsAGenericError() {
    JsonNode materials = getEncryptionMaterials(defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16")), ec("a", "b"));
    ObjectNode wire = TestClient.object();
    wire.put("algorithmSuiteId", COMMITTING_SIGNING);
    wire.set("encryptionContext", ec("a", "b"));
    wire.putArray("encryptedDataKeys");
    wire.putArray("requiredEncryptionContextKeys");
    wire.set("signingKey", materials.get("signingKey"));
    TestClient.Reply reply = client.call("OnEncrypt", onEncryptRequest(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"), wire));
    assertEquals(GENERIC, reply.errorType(), reply.body.toString());

    ObjectNode nonSigning = (ObjectNode) initializeEncryption(COMMITTING, ec("a", "b")).deepCopy();
    nonSigning.set("signingKey", materials.get("signingKey"));
    assertError(MPL, "Missing signature key for signed suite.",
      client.call("OnEncrypt", onEncryptRequest(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"), nonSigning)));
  }

  @Test
  void signingSuiteDecryptionMaterialsWithoutTheVerificationKeyAreAnMplError() {
    JsonNode encryption = getEncryptionMaterials(defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16")), ec("a", "b"));
    ObjectNode materials = TestClient.object();
    materials.put("algorithmSuiteId", COMMITTING_SIGNING);
    materials.set("encryptionContext", encryption.get("encryptionContext"));
    materials.putArray("requiredEncryptionContextKeys");
    TestClient.Reply reply = client.call(
      "OnDecrypt",
      onDecryptRequest(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"), materials, (ArrayNode) encryption.get("encryptedDataKeys"))
    );
    assertError(MPL, "A signing suite's decryption materials need a verification key.", reply);
  }

  @Test
  void requiredEncryptionContextKeysTravelThroughTheKeyringInterface() {
    ObjectNode request = TestClient.object();
    request.put("algorithmSuiteId", COMMITTING);
    request.set("encryptionContext", ec("a", "b", "c", "d"));
    request.putArray("requiredEncryptionContextKeys").add("c");
    JsonNode initial = client.ok("InitializeEncryptionMaterials", request).get("materials");
    JsonNode encrypted = onEncrypt(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"), initial);
    assertEquals("[\"c\"]", encrypted.get("requiredEncryptionContextKeys").toString());
    JsonNode decryption = client.ok("InitializeDecryptionMaterials", request).get("materials");
    assertEquals("[\"c\"]", decryption.get("requiredEncryptionContextKeys").toString());

    ObjectNode missing = request.deepCopy();
    missing.putArray("requiredEncryptionContextKeys").add("zz");
    assertError(MPL, "Required encryption context keys do not exist in provided encryption context.",
      client.call("InitializeEncryptionMaterials", missing));
  }

  @Test
  void absentRequiredContextMembersAreGenericErrors() {
    ObjectNode request = TestClient.object();
    request.put("algorithmSuiteId", COMMITTING);
    request.putArray("requiredEncryptionContextKeys");
    assertError(GENERIC, "missing required member: encryptionContext", client.call("InitializeEncryptionMaterials", request));
    assertError(GENERIC, "missing required member: encryptionContext", client.call("InitializeDecryptionMaterials", request));
    request.set("encryptionContext", ec());
    request.remove("requiredEncryptionContextKeys");
    assertError(GENERIC, "missing required member: requiredEncryptionContextKeys", client.call("InitializeEncryptionMaterials", request));
    assertError(GENERIC, "missing required member: requiredEncryptionContextKeys", client.call("InitializeDecryptionMaterials", request));

    String keyring = rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16");
    ObjectNode encryption = (ObjectNode) initializeEncryption(COMMITTING, ec()).deepCopy();
    encryption.remove("encryptionContext");
    assertError(GENERIC, "missing required member: encryptionContext", client.call("OnEncrypt", onEncryptRequest(keyring, encryption)));
    ObjectNode decryption = (ObjectNode) initializeDecryption(COMMITTING, ec()).deepCopy();
    decryption.remove("requiredEncryptionContextKeys");
    assertError(GENERIC, "missing required member: requiredEncryptionContextKeys",
      client.call("OnDecrypt", onDecryptRequest(keyring, decryption, TestClient.CBOR.createArrayNode())));
  }

  // ---------------------------------------------------------------------
  // Default CMM
  // ---------------------------------------------------------------------

  @Test
  void defaultCmmRoundTripUsesThePolicyDefaultSuite() {
    String cmm = defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"));
    JsonNode encryption = getEncryptionMaterials(cmm, ec("purpose", "cmm"));
    assertEquals(COMMITTING_SIGNING, encryption.get("algorithmSuiteId").asText());
    assertTrue(encryption.has("signingKey"));
    assertFalse(encryption.has("symmetricSigningKeys"));
    String publicKey = encryption.get("encryptionContext").get(Wire.PUBLIC_KEY_FIELD).asText();

    ObjectNode request = TestClient.object();
    request.put("cmmId", defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16")));
    request.put("algorithmSuiteId", COMMITTING_SIGNING);
    request.set("encryptedDataKeys", encryption.get("encryptedDataKeys"));
    request.set("encryptionContext", encryption.get("encryptionContext"));
    request.put("commitmentPolicy", REQUIRE_REQUIRE);
    JsonNode decryption = client.ok("DecryptMaterials", request);

    assertArrayEquals(blob(encryption, "plaintextDataKey"), blob(decryption, "plaintextDataKey"));
    assertArrayEquals(Base64.getDecoder().decode(publicKey), blob(decryption, "verificationKey"));
    assertFalse(decryption.has("symmetricSigningKey"));
  }

  @Test
  void requestedSuiteReachesTheCmm() {
    String cmm = defaultCmm(rawAesKeyring("k", key(16, 0), "ALG_AES128_GCM_IV12_TAG16"));
    ObjectNode request = TestClient.object();
    request.put("cmmId", cmm);
    request.put("commitmentPolicy", "ESDK_FORBID_ENCRYPT_ALLOW_DECRYPT");
    request.put("algorithmSuiteId", "ALG_AES_128_GCM_IV12_TAG16_NO_KDF");
    request.put("maxPlaintextLength", 1024L);
    JsonNode materials = client.ok("GetEncryptionMaterials", request);
    assertEquals("ALG_AES_128_GCM_IV12_TAG16_NO_KDF", materials.get("algorithmSuiteId").asText());
    assertEquals(16, blob(materials, "plaintextDataKey").length);
    assertFalse(materials.has("signingKey"));
  }

  @Test
  void decryptMaterialsAppliesTheCommitmentPolicy() {
    ObjectNode request = TestClient.object();
    request.put("cmmId", defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16")));
    request.put("algorithmSuiteId", "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256");
    request.putArray("encryptedDataKeys");
    request.put("commitmentPolicy", REQUIRE_REQUIRE);
    assertError(MPL, "Configuration conflict. Commitment policy requires only committing algorithm suites",
      client.call("DecryptMaterials", request));
  }

  @Test
  void aSuiteThePolicyForbidsIsAnMplError() {
    ObjectNode request = TestClient.object();
    request.put("cmmId", defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16")));
    request.put("commitmentPolicy", REQUIRE_REQUIRE);
    request.put("algorithmSuiteId", "ALG_AES_256_GCM_IV12_TAG16_NO_KDF");
    assertEquals(MPL, client.call("GetEncryptionMaterials", request).errorType());
  }

  @Test
  void aReproducedContextThatDisagreesIsAnMplError() {
    String cmm = defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"));
    JsonNode encryption = getEncryptionMaterials(cmm, ec("purpose", "cmm"));
    ObjectNode request = TestClient.object();
    request.put("cmmId", cmm);
    request.put("algorithmSuiteId", COMMITTING_SIGNING);
    request.set("encryptedDataKeys", encryption.get("encryptedDataKeys"));
    request.set("encryptionContext", encryption.get("encryptionContext"));
    request.put("commitmentPolicy", REQUIRE_REQUIRE);
    request.set("reproducedEncryptionContext", ec("purpose", "other"));
    assertEquals(MPL, client.call("DecryptMaterials", request).errorType());
  }

  // ---------------------------------------------------------------------
  // Handle and error contract
  // ---------------------------------------------------------------------

  @Test
  void libraryExceptionsAreMplErrorsAndEverythingElseIsGeneric() {
    assertEquals(MPL, ServerMain.classify(new ValidationException("bad input")).typeId());
    assertEquals("bad input", ServerMain.classify(new ValidationException("bad input")).getMessage());
    ModeledError noMessage = ServerMain.classify(new ValidationException(null));
    assertEquals(MPL, noMessage.typeId());
    assertEquals(ValidationException.class.getName(), noMessage.getMessage());
    ModeledError bug = ServerMain.classify(new IllegalStateException("boom"));
    assertEquals(GENERIC, bug.typeId());
    assertEquals("unexpected server error: java.lang.IllegalStateException: boom", bug.getMessage());
    assertEquals(GENERIC, ServerMain.classify(new AssertionError("x")).typeId());
    ModeledError modeled = ModeledError.generic("as is");
    assertSame(modeled, ServerMain.classify(modeled));
  }


  @Test
  void unknownEmptyAndWrongKindHandlesAreGenericErrors() {
    String keyring = rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16");
    String cmm = defaultCmm(keyring);
    JsonNode materials = initializeEncryption(COMMITTING, ec());

    assertError(GENERIC, "unknown keyringId: " + UNKNOWN_ID, client.call("OnEncrypt", onEncryptRequest(UNKNOWN_ID, materials)));
    assertError(GENERIC, "unknown keyringId: " + cmm, client.call("OnEncrypt", onEncryptRequest(cmm, materials)));
    assertError(GENERIC, "keyringId must be non-empty", client.call("OnEncrypt", onEncryptRequest("", materials)));
    ObjectNode cmmRequest = TestClient.object();
    cmmRequest.put("keyringId", UNKNOWN_ID);
    assertError(GENERIC, "unknown keyringId: " + UNKNOWN_ID, client.call("CreateDefaultCmm", cmmRequest));

    ObjectNode request = TestClient.object();
    request.put("cmmId", keyring);
    request.set("encryptionContext", ec());
    request.put("commitmentPolicy", REQUIRE_REQUIRE);
    assertError(GENERIC, "unknown cmmId: " + keyring, client.call("GetEncryptionMaterials", request));
    request.put("cmmId", UNKNOWN_ID);
    assertError(GENERIC, "unknown cmmId: " + UNKNOWN_ID, client.call("GetEncryptionMaterials", request));
  }

  @Test
  void mplRejectionCarriesTheLibraryMessage() {
    ObjectNode request = rawAesKeyringRequest("k", new byte[16], "ALG_AES256_GCM_IV12_TAG16");
    assertError(MPL, "Wrapping key length does not match specified wrapping algorithm", client.call("CreateRawAesKeyring", request));
  }

  @Test
  void malformedRequestsAreGenericErrors() {
    byte[] body = TestClient.encode(rawAesKeyringRequest("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16"));
    assertError(GENERIC, "unknown service: Other; expected MPLTestServer",
      client.post("/service/Other/operation/CreateRawAesKeyring", "rpc-v2-cbor", "application/cbor", body));
    assertError(GENERIC, "unexpected path: /service/MPLTestServer",
      client.post("/service/MPLTestServer", "rpc-v2-cbor", "application/cbor", body));
    assertError(GENERIC, "missing or invalid smithy-protocol header; expected rpc-v2-cbor",
      client.post("/service/MPLTestServer/operation/CreateRawAesKeyring", null, "application/cbor", body));
    assertError(GENERIC, "missing or invalid content-type; expected application/cbor",
      client.post("/service/MPLTestServer/operation/CreateRawAesKeyring", "rpc-v2-cbor", "application/json", body));
    assertError(GENERIC, "unknown operation: Nope", client.call("Nope", TestClient.object()));
    assertError(GENERIC, "request body is not a CBOR map",
      client.post("/service/MPLTestServer/operation/CreateRawAesKeyring", "rpc-v2-cbor", "application/cbor", new byte[] { 0x01 }));

    ObjectNode missing = rawAesKeyringRequest("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16");
    missing.remove("wrappingKey");
    assertError(GENERIC, "missing required member: wrappingKey", client.call("CreateRawAesKeyring", missing));
    ObjectNode mistyped = rawAesKeyringRequest("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16");
    mistyped.put("wrappingKey", "not a blob");
    assertError(GENERIC, "member is not a blob: wrappingKey", client.call("CreateRawAesKeyring", mistyped));
    assertError(GENERIC, "unknown AES wrapping algorithm: ALG_NOPE",
      client.call("CreateRawAesKeyring", rawAesKeyringRequest("k", key(32, 0), "ALG_NOPE")));
  }

  @Test
  void suitesAndPoliciesOutsideTheModelAreGenericErrors() {
    ObjectNode request = TestClient.object();
    request.put("algorithmSuiteId", "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384");
    request.set("encryptionContext", ec());
    request.putArray("requiredEncryptionContextKeys");
    assertError(GENERIC, "unknown algorithm suite: ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384",
      client.call("InitializeEncryptionMaterials", request));

    ObjectNode gem = TestClient.object();
    gem.put("cmmId", defaultCmm(rawAesKeyring("k", key(32, 0), "ALG_AES256_GCM_IV12_TAG16")));
    gem.put("commitmentPolicy", "REQUIRE_ENCRYPT_REQUIRE_DECRYPT");
    assertError(GENERIC, "unknown commitment policy: REQUIRE_ENCRYPT_REQUIRE_DECRYPT", client.call("GetEncryptionMaterials", gem));
    gem.put("commitmentPolicy", "ESDK_NOPE");
    assertError(GENERIC, "unknown commitment policy: ESDK_NOPE", client.call("GetEncryptionMaterials", gem));
  }

  // ---------------------------------------------------------------------
  // Catalog features: wire shapes the commons suite never sends
  // ---------------------------------------------------------------------

  @Test
  void aKeyAgreementSchemeThatIsNotOneKnownVariantIsAGenericError() {
    ObjectNode request = TestClient.object();
    request.put("curveSpec", "ECC_NIST_P256");
    request.putObject("KeyAgreementScheme");
    assertError(GENERIC, "member is not a union (a map with one entry): KeyAgreementScheme",
      client.call("CreateRawEcdhKeyring", request));
    ObjectNode twoVariants = request.putObject("KeyAgreementScheme");
    twoVariants.putObject("PublicKeyDiscovery");
    twoVariants.putObject("EphemeralPrivateKeyToStaticPublicKey");
    assertError(GENERIC, "member is not a union (a map with one entry): KeyAgreementScheme",
      client.call("CreateRawEcdhKeyring", request));
    request.putObject("KeyAgreementScheme").putObject("Nope");
    assertError(GENERIC, "unknown key agreement scheme: Nope", client.call("CreateRawEcdhKeyring", request));
  }

  @Test
  void paddingSchemesAndCurvesOutsideTheModelAreGenericErrors() {
    ObjectNode rsa = TestClient.object();
    rsa.put("keyNamespace", "ns");
    rsa.put("keyName", "k");
    rsa.put("paddingScheme", "NOPE");
    assertError(GENERIC, "unknown padding scheme: NOPE", client.call("CreateRawRsaKeyring", rsa));
    ObjectNode ecdh = TestClient.object();
    ecdh.put("curveSpec", "NOPE");
    ecdh.putObject("KeyAgreementScheme").putObject("PublicKeyDiscovery").put("recipientStaticPrivateKey", new byte[1]);
    assertError(GENERIC, "unknown ECDH curve: NOPE", client.call("CreateRawEcdhKeyring", ecdh));
  }

  @Test
  void suiteInfoForADbeSuiteIsAGenericErrorAndForAnUnknownIdAnMplError() {
    ObjectNode dbe = TestClient.object();
    dbe.put("binaryId", new byte[] { 0x67, 0x00 });
    assertError(GENERIC,
      "the MPL returned a non-ESDK algorithm suite, which the model cannot carry: ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384",
      client.call("GetAlgorithmSuiteInfo", dbe));
    ObjectNode unknown = TestClient.object();
    unknown.put("binaryId", new byte[] { 0x00, 0x00 });
    assertError(MPL, "Invalid BinaryId", client.call("GetAlgorithmSuiteInfo", unknown));
  }

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  private static void assertError(String type, String message, TestClient.Reply reply) {
    assertEquals(400, reply.status, reply.body.toString());
    assertEquals(type, reply.errorType(), reply.body.toString());
    assertEquals(message, reply.message());
  }

  private static ObjectNode rawAesKeyringRequest(String keyName, byte[] wrappingKey, String alg) {
    ObjectNode request = TestClient.object();
    request.put("keyNamespace", "ns");
    request.put("keyName", keyName);
    request.put("wrappingKey", wrappingKey);
    request.put("wrappingAlg", alg);
    return request;
  }

  private static String rawAesKeyring(String keyName, byte[] wrappingKey, String alg) {
    return client.ok("CreateRawAesKeyring", rawAesKeyringRequest(keyName, wrappingKey, alg)).get("keyringId").asText();
  }

  private static String defaultCmm(String keyring) {
    ObjectNode request = TestClient.object();
    request.put("keyringId", keyring);
    return client.ok("CreateDefaultCmm", request).get("cmmId").asText();
  }

  private static JsonNode getEncryptionMaterials(String cmm, ObjectNode ec) {
    ObjectNode request = TestClient.object();
    request.put("cmmId", cmm);
    request.set("encryptionContext", ec);
    request.put("commitmentPolicy", REQUIRE_REQUIRE);
    return client.ok("GetEncryptionMaterials", request);
  }

  private static JsonNode initializeEncryption(String suite, ObjectNode ec) {
    ObjectNode request = TestClient.object();
    request.put("algorithmSuiteId", suite);
    request.set("encryptionContext", ec);
    request.putArray("requiredEncryptionContextKeys");
    return client.ok("InitializeEncryptionMaterials", request).get("materials");
  }

  private static JsonNode initializeDecryption(String suite, ObjectNode ec) {
    ObjectNode request = TestClient.object();
    request.put("algorithmSuiteId", suite);
    request.set("encryptionContext", ec);
    request.putArray("requiredEncryptionContextKeys");
    return client.ok("InitializeDecryptionMaterials", request).get("materials");
  }

  private static ObjectNode onEncryptRequest(String keyring, JsonNode materials) {
    ObjectNode request = TestClient.object();
    request.put("keyringId", keyring);
    request.set("materials", materials);
    return request;
  }

  private static JsonNode onEncrypt(String keyring, JsonNode materials) {
    return client.ok("OnEncrypt", onEncryptRequest(keyring, materials)).get("materials");
  }

  private static ObjectNode onDecryptRequest(String keyring, JsonNode materials, ArrayNode edks) {
    ObjectNode request = TestClient.object();
    request.put("keyringId", keyring);
    request.set("materials", materials);
    request.set("encryptedDataKeys", edks);
    return request;
  }

  private static JsonNode onDecrypt(String keyring, JsonNode materials, ArrayNode edks) {
    return client.ok("OnDecrypt", onDecryptRequest(keyring, materials, edks)).get("materials");
  }

  private static ObjectNode ec(String... keysAndValues) {
    ObjectNode ec = TestClient.object();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      ec.put(keysAndValues[i], keysAndValues[i + 1]);
    }
    return ec;
  }

  private static byte[] key(int length, int seed) {
    byte[] key = new byte[length];
    for (int i = 0; i < length; i++) {
      key[i] = (byte) (i + seed * 101);
    }
    return key;
  }

  private static byte[] blob(JsonNode node, String field) {
    try {
      return node.get(field).binaryValue();
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }
}
