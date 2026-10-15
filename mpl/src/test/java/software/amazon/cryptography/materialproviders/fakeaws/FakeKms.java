// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.fakeaws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.UnaryOperator;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * The KMS half of {@link FakeAws}: the operations the MPL's KMS keyrings and key store call.
 *
 * <p>Supported: GenerateDataKey, GenerateDataKeyWithoutPlaintext, Encrypt, Decrypt, ReEncrypt with
 * symmetric keys; Decrypt (RSAES_OAEP_SHA_1, RSAES_OAEP_SHA_256) and GetPublicKey with RSA keys;
 * GetPublicKey and DeriveSharedSecret (ECDH) with ECC key agreement keys.
 * Any other operation fails with {@code UnknownOperationException}.
 *
 * <p>A key identifier may be a key ARN, a key id, an alias name, or an alias ARN.
 * Key ids and alias names resolve in the request's region and {@link #ACCOUNT}.
 * A key ARN or alias ARN for another region does not resolve, as with KMS.
 *
 * <p>A symmetric ciphertext blob holds the ARN of the key that made it and an AES-GCM ciphertext
 * whose AAD is the encryption context, so a changed blob or a different context fails
 * with {@code InvalidCiphertextException}. Decrypt resolves the blob's key id in the request's region,
 * so a multi-Region key's replica decrypts what another replica encrypted.
 * Responses name keys by their ARN in the request's region.
 *
 * <p>Error codes and messages follow what real KMS answered in the integration tests (report 27):
 * a symmetric ciphertext whose key is not in the request's region is AccessDeniedException;
 * a symmetric Decrypt KeyId that names no key of the region, or another key, is IncorrectKeyException;
 * other operations, and Decrypt with an RSA algorithm, report an unknown identifier as NotFoundException.
 */
public final class FakeKms {

  /** The account of every key this fake creates. */
  public static final String ACCOUNT = "111122223333";
  // The principal real KMS names in AccessDeniedException messages.
  private static final String CALLER = "arn:aws:sts::" + ACCOUNT + ":assumed-role/fake-role/fake-session";

  private static final byte BLOB_VERSION = 1;
  private static final int IV_LENGTH = 12;
  private static final int TAG_BITS = 128;
  private static final String SYMMETRIC_DEFAULT = "SYMMETRIC_DEFAULT";
  private static final String ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT";
  private static final String KEY_AGREEMENT = "KEY_AGREEMENT";
  private static final List<String> RSA_ALGORITHMS = Arrays.asList("RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256");

  private final SecureRandom random = new SecureRandom();
  private final Map<String, Key> keys = new HashMap<>();
  private final Map<String, String> aliases = new HashMap<>();
  private final List<Failure> failures = new ArrayList<>();
  private final List<Edit> edits = new ArrayList<>();
  private long keyCount;

  FakeKms() {}

  /** Creates a symmetric encryption key and returns its ARN. */
  public synchronized String createSymmetricKey(String region) {
    Material material = new Material(SYMMETRIC_DEFAULT, ENCRYPT_DECRYPT, randomBytes(32), null);
    return add(region, String.format("00000000-0000-4000-8000-%012d", ++keyCount), material);
  }

  /**
   * Creates a symmetric multi-Region key with a replica in each region and returns the replica ARNs in order.
   * The ARNs differ only by region and the replicas share key material.
   */
  public synchronized List<String> createMultiRegionKey(String... regions) {
    if (regions.length == 0) {
      throw new IllegalArgumentException("a multi-Region key needs at least one region");
    }
    Material material = new Material(SYMMETRIC_DEFAULT, ENCRYPT_DECRYPT, randomBytes(32), null);
    String id = String.format("mrk-%032d", ++keyCount);
    List<String> arns = new ArrayList<>();
    for (String region : regions) {
      arns.add(add(region, id, material));
    }
    return arns;
  }

  /**
   * Creates symmetric encryption keys with the given key ARNs, of any account, sharing key material, so a test can use
   * the ARNs a manifest names. ARNs that differ only by Region model one multi-Region key's replicas.
   */
  public synchronized void createSymmetricKeys(String... keyArns) {
    Material material = new Material(SYMMETRIC_DEFAULT, ENCRYPT_DECRYPT, randomBytes(32), null);
    for (String arn : keyArns) {
      String[] parts = arn.split(":", 6);
      if (parts.length != 6 || !parts[2].equals("kms") || !parts[5].startsWith("key/") || keys.containsKey(arn)) {
        throw new IllegalArgumentException("not a new key ARN: " + arn);
      }
      keys.put(arn, new Key(arn, parts[3], material));
    }
  }

  /** Creates an RSA encryption key ({@code keySpec} RSA_2048, RSA_3072, or RSA_4096) and returns its ARN. */
  public synchronized String createRsaKey(String region, String keySpec) {
    int bits;
    switch (keySpec) {
      case "RSA_2048":
        bits = 2048;
        break;
      case "RSA_3072":
        bits = 3072;
        break;
      case "RSA_4096":
        bits = 4096;
        break;
      default:
        throw new IllegalArgumentException("not an RSA key spec: " + keySpec);
    }
    KeyPair pair;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(bits, random);
      pair = generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
    return add(region, String.format("00000000-0000-4000-8000-%012d", ++keyCount), new Material(keySpec, ENCRYPT_DECRYPT, null, pair));
  }

  /**
   * Creates an ECC key agreement key ({@code keySpec} ECC_NIST_P256, ECC_NIST_P384, or ECC_NIST_P521)
   * and returns its ARN.
   */
  public synchronized String createEccKeyAgreementKey(String region, String keySpec) {
    String curve;
    switch (keySpec) {
      case "ECC_NIST_P256":
        curve = "secp256r1";
        break;
      case "ECC_NIST_P384":
        curve = "secp384r1";
        break;
      case "ECC_NIST_P521":
        curve = "secp521r1";
        break;
      default:
        throw new IllegalArgumentException("not an ECC NIST key spec: " + keySpec);
    }
    KeyPair pair;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec(curve), random);
      pair = generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
    return add(region, String.format("00000000-0000-4000-8000-%012d", ++keyCount), new Material(keySpec, KEY_AGREEMENT, null, pair));
  }

  /** Creates {@code aliasName} (starting with "alias/") for a key, in the key's region and account. */
  public synchronized void createAlias(String aliasName, String keyArn) {
    if (!aliasName.startsWith("alias/")) {
      throw new IllegalArgumentException("alias names start with alias/: " + aliasName);
    }
    Key key = existing(keyArn);
    aliases.put(arnPrefix(key.region) + aliasName, key.arn);
  }

  /** The public key of an asymmetric key as PEM-encoded X.509 SubjectPublicKeyInfo. */
  public synchronized String publicKeyPem(String keyArn) {
    Key key = existing(keyArn);
    if (key.material.pair == null) {
      throw new IllegalArgumentException("not an asymmetric key: " + keyArn);
    }
    String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(publicKeyDer(key));
    return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
  }

  /**
   * Makes every later {@code operation} request fail with {@code error}: requests that use the key
   * {@code keyArn}, or every request when {@code keyArn} is null. A key-specific rule applies after the
   * request's key identifier resolves, so an unknown key still fails with NotFoundException.
   * Rules stay until {@link #clearFailures}.
   */
  public synchronized void fail(String operation, String keyArn, ServiceError error) {
    failures.add(new Failure(operation, keyArn, error));
  }

  /**
   * Makes every later successful {@code operation} response pass through {@code edit}, to model a misbehaving KMS.
   * Edits stay until {@link #clearFailures}.
   */
  public synchronized void editResponses(String operation, UnaryOperator<ObjectNode> edit) {
    editResponses(operation, null, edit);
  }

  /** As {@link #editResponses(String, UnaryOperator)}, for responses whose KeyId is {@code keyArn}, or all if null. */
  public synchronized void editResponses(String operation, String keyArn, UnaryOperator<ObjectNode> edit) {
    edits.add(new Edit(operation, keyArn, edit));
  }

  /** Removes every {@link #fail} rule and {@link #editResponses} edit. */
  public synchronized void clearFailures() {
    failures.clear();
    edits.clear();
  }

  synchronized JsonNode handle(String operation, String region, ObjectNode request) {
    JsonNode response = respond(operation, region, request);
    for (Edit edit : edits) {
      boolean keyMatches = edit.keyArn == null || edit.keyArn.equals(response.path("KeyId").asText(null));
      if (edit.operation.equals(operation) && keyMatches) {
        response = edit.edit.apply((ObjectNode) response);
      }
    }
    return response;
  }

  private JsonNode respond(String operation, String region, ObjectNode request) {
    failIfConfigured(operation, null);
    switch (operation) {
      case "GenerateDataKey":
        return generateDataKey(region, request, true);
      case "GenerateDataKeyWithoutPlaintext":
        return generateDataKey(region, request, false);
      case "Encrypt":
        return encrypt(region, request);
      case "Decrypt":
        return decrypt(region, request);
      case "ReEncrypt":
        return reEncrypt(region, request);
      case "GetPublicKey":
        return getPublicKey(region, request);
      case "DeriveSharedSecret":
        return deriveSharedSecret(region, request);
      default:
        throw ServiceError.of("UnknownOperationException", "the fake KMS does not implement " + operation);
    }
  }

  private JsonNode generateDataKey(String region, ObjectNode request, boolean withPlaintext) {
    String operation = withPlaintext ? "GenerateDataKey" : "GenerateDataKeyWithoutPlaintext";
    Key key = resolve(required(request, "KeyId").asText(), region);
    failIfConfigured(operation, key.arn);
    requireSymmetric(key, operation);
    JsonNode numberOfBytes = request.get("NumberOfBytes");
    JsonNode keySpec = request.get("KeySpec");
    int length;
    if (numberOfBytes != null && keySpec != null) {
      throw validation("Please specify either number of bytes or key spec.");
    } else if (numberOfBytes != null) {
      length = numberOfBytes.asInt();
      if (length < 1 || length > 1024) {
        throw validation("Value '" + length + "' at 'numberOfBytes' failed to satisfy constraint: Member must have value between 1 and 1024");
      }
    } else if (keySpec != null && keySpec.asText().equals("AES_256")) {
      length = 32;
    } else if (keySpec != null && keySpec.asText().equals("AES_128")) {
      length = 16;
    } else {
      throw validation("Please specify either number of bytes or key spec.");
    }
    byte[] plaintext = randomBytes(length);
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    response.put("CiphertextBlob", encode(seal(key, plaintext, encryptionContext(request, "EncryptionContext"))));
    if (withPlaintext) {
      response.put("Plaintext", encode(plaintext));
    }
    response.put("KeyId", key.arn);
    return response;
  }

  private JsonNode encrypt(String region, ObjectNode request) {
    Key key = resolve(required(request, "KeyId").asText(), region);
    failIfConfigured("Encrypt", key.arn);
    requireSymmetric(key, "Encrypt");
    requireAlgorithm(request, "EncryptionAlgorithm");
    byte[] plaintext = blob(request, "Plaintext");
    if (plaintext.length < 1 || plaintext.length > 4096) {
      throw validation("Value at 'plaintext' failed to satisfy constraint: Member must have length between 1 and 4096");
    }
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    response.put("CiphertextBlob", encode(seal(key, plaintext, encryptionContext(request, "EncryptionContext"))));
    response.put("KeyId", key.arn);
    response.put("EncryptionAlgorithm", SYMMETRIC_DEFAULT);
    return response;
  }

  private JsonNode decrypt(String region, ObjectNode request) {
    byte[] ciphertext = blob(request, "CiphertextBlob");
    JsonNode keyId = request.get("KeyId");
    JsonNode algorithm = request.get("EncryptionAlgorithm");
    if (algorithm != null && RSA_ALGORITHMS.contains(algorithm.asText())) {
      Key key = resolve(required(request, "KeyId").asText(), region);
      if (key.material.pair == null) {
        throw ServiceError.of("InvalidKeyUsageException", "Algorithm " + algorithm.asText() + " is incompatible with key spec " + key.material.keySpec + ".");
      }
      failIfConfigured("Decrypt", key.arn);
      return decryptAsymmetric(key, ciphertext, request);
    }
    requireAlgorithm(request, "EncryptionAlgorithm");
    Opened opened = open(ciphertext, region, encryptionContext(request, "EncryptionContext"), keyId, "Decrypt");
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    response.put("KeyId", opened.key.arn);
    response.put("Plaintext", encode(opened.plaintext));
    response.put("EncryptionAlgorithm", SYMMETRIC_DEFAULT);
    return response;
  }

  private JsonNode decryptAsymmetric(Key key, byte[] ciphertext, ObjectNode request) {
    if (!key.material.keyUsage.equals(ENCRYPT_DECRYPT)) {
      throw ServiceError.of("InvalidKeyUsageException", null);
    }
    JsonNode algorithm = request.get("EncryptionAlgorithm");
    if (!encryptionContext(request, "EncryptionContext").isEmpty()) {
      throw validation("EncryptionContext is not supported with asymmetric keys");
    }
    String hash = algorithm.asText().equals("RSAES_OAEP_SHA_1") ? "SHA-1" : "SHA-256";
    MGF1ParameterSpec mgf = hash.equals("SHA-1") ? MGF1ParameterSpec.SHA1 : MGF1ParameterSpec.SHA256;
    byte[] plaintext;
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
      cipher.init(
        Cipher.DECRYPT_MODE,
        key.material.pair.getPrivate(),
        new OAEPParameterSpec(hash, "MGF1", mgf, PSource.PSpecified.DEFAULT)
      );
      plaintext = cipher.doFinal(ciphertext);
    } catch (GeneralSecurityException e) {
      throw ServiceError.of("InvalidCiphertextException", null);
    }
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    response.put("KeyId", key.arn);
    response.put("Plaintext", encode(plaintext));
    response.put("EncryptionAlgorithm", algorithm.asText());
    return response;
  }

  private JsonNode reEncrypt(String region, ObjectNode request) {
    byte[] ciphertext = blob(request, "CiphertextBlob");
    JsonNode sourceKeyId = request.get("SourceKeyId");
    Key destination = resolve(required(request, "DestinationKeyId").asText(), region);
    failIfConfigured("ReEncrypt", destination.arn);
    requireSymmetric(destination, "ReEncrypt");
    requireAlgorithm(request, "SourceEncryptionAlgorithm");
    requireAlgorithm(request, "DestinationEncryptionAlgorithm");
    Opened opened = open(ciphertext, region, encryptionContext(request, "SourceEncryptionContext"), sourceKeyId, "ReEncrypt");
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    response.put(
      "CiphertextBlob",
      encode(seal(destination, opened.plaintext, encryptionContext(request, "DestinationEncryptionContext")))
    );
    response.put("SourceKeyId", opened.key.arn);
    response.put("KeyId", destination.arn);
    response.put("SourceEncryptionAlgorithm", SYMMETRIC_DEFAULT);
    response.put("DestinationEncryptionAlgorithm", SYMMETRIC_DEFAULT);
    return response;
  }

  private JsonNode getPublicKey(String region, ObjectNode request) {
    Key key = resolve(required(request, "KeyId").asText(), region);
    failIfConfigured("GetPublicKey", key.arn);
    if (key.material.pair == null) {
      throw ServiceError.of("UnsupportedOperationException", null);
    }
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    response.put("KeyId", key.arn);
    response.put("PublicKey", encode(publicKeyDer(key)));
    response.put("CustomerMasterKeySpec", key.material.keySpec);
    response.put("KeySpec", key.material.keySpec);
    response.put("KeyUsage", key.material.keyUsage);
    if (key.material.keyUsage.equals(KEY_AGREEMENT)) {
      response.putArray("KeyAgreementAlgorithms").add("ECDH");
    } else {
      ArrayNode algorithms = response.putArray("EncryptionAlgorithms");
      RSA_ALGORITHMS.forEach(algorithms::add);
    }
    return response;
  }

  private JsonNode deriveSharedSecret(String region, ObjectNode request) {
    Key key = resolve(required(request, "KeyId").asText(), region);
    failIfConfigured("DeriveSharedSecret", key.arn);
    if (!key.material.keyUsage.equals(KEY_AGREEMENT)) {
      throw ServiceError.of("InvalidKeyUsageException", key.arn + " key usage is " + key.material.keyUsage + " which is not valid for DeriveSharedSecret.");
    }
    String algorithm = required(request, "KeyAgreementAlgorithm").asText();
    if (!algorithm.equals("ECDH")) {
      throw validation("Value '" + algorithm + "' at 'keyAgreementAlgorithm' failed to satisfy constraint: Member must satisfy enum value set: [ECDH]");
    }
    ECPrivateKey privateKey = (ECPrivateKey) key.material.pair.getPrivate();
    byte[] secret;
    try {
      PublicKey peer = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(blob(request, "PublicKey")));
      if (!(peer instanceof ECPublicKey) || !sameCurve(((ECPublicKey) peer).getParams(), privateKey.getParams())) {
        throw validation("The public key is not on the key's curve " + key.material.keySpec);
      }
      KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
      agreement.init(privateKey);
      agreement.doPhase(peer, true);
      secret = agreement.generateSecret();
    } catch (GeneralSecurityException e) {
      throw validation("The public key is not a valid X.509 SubjectPublicKeyInfo EC key: " + e.getMessage());
    }
    ObjectNode response = JsonNodeFactory.instance.objectNode();
    response.put("KeyId", key.arn);
    response.put("SharedSecret", encode(secret));
    response.put("KeyAgreementAlgorithm", "ECDH");
    response.put("KeyOrigin", "AWS_KMS");
    return response;
  }

  private static boolean sameCurve(ECParameterSpec a, ECParameterSpec b) {
    return a.getCurve().equals(b.getCurve()) && a.getGenerator().equals(b.getGenerator()) && a.getOrder().equals(b.getOrder());
  }

  // blob = version || u16 ARN length || ARN || IV || AES-GCM(ciphertext || tag), AAD = encoded context.
  // The ARN needs no authentication: another ARN selects other key material, so the tag check fails.
  private byte[] seal(Key key, byte[] plaintext, Map<String, String> context) {
    byte[] header = header(key.arn);
    byte[] iv = randomBytes(IV_LENGTH);
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.material.aesKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      cipher.updateAAD(aad(context));
      byte[] sealed = cipher.doFinal(plaintext);
      return ByteBuffer.allocate(header.length + iv.length + sealed.length).put(header).put(iv).put(sealed).array();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  // Resolves the blob's key in the request's region, checks it against the requested key, and decrypts.
  private Opened open(byte[] blob, String region, Map<String, String> context, JsonNode requestedKeyId, String operation) {
    ByteBuffer buffer = ByteBuffer.wrap(blob);
    if (buffer.remaining() < 3 || buffer.get() != BLOB_VERSION) {
      throw ServiceError.of("InvalidCiphertextException", null);
    }
    int arnLength = buffer.getShort() & 0xffff;
    if (buffer.remaining() < arnLength + IV_LENGTH + TAG_BITS / 8) {
      throw ServiceError.of("InvalidCiphertextException", null);
    }
    byte[] arnBytes = new byte[arnLength];
    buffer.get(arnBytes);
    String[] arn = new String(arnBytes, StandardCharsets.UTF_8).split(":", 6);
    if (arn.length != 6) {
      throw ServiceError.of("InvalidCiphertextException", null);
    }
    arn[3] = region;
    Key key = keys.get(String.join(":", arn));
    if (key == null) {
      throw ServiceError.of(
        "AccessDeniedException",
        "User: " + CALLER + " is not authorized to perform: kms:" + (operation.equals("ReEncrypt") ? "ReEncryptFrom" : operation) +
          " on the resource associated with this ciphertext because the resource does not exist in this Region," +
          " no resource-based policies allow access, or a resource-based policy explicitly denies access"
      );
    }
    if (requestedKeyId != null && tryResolve(requestedKeyId.asText(), region) != key) {
      throw ServiceError.of(
        "IncorrectKeyException",
        "The key ID in the request does not identify a CMK that can perform this operation."
      );
    }
    failIfConfigured(operation, key.arn);
    byte[] iv = new byte[IV_LENGTH];
    buffer.get(iv);
    byte[] sealed = new byte[buffer.remaining()];
    buffer.get(sealed);
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.material.aesKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      cipher.updateAAD(aad(context));
      return new Opened(key, cipher.doFinal(sealed));
    } catch (AEADBadTagException e) {
      throw ServiceError.of("InvalidCiphertextException", null);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] header(String arn) {
    byte[] arnBytes = arn.getBytes(StandardCharsets.UTF_8);
    return ByteBuffer.allocate(3 + arnBytes.length).put(BLOB_VERSION).putShort((short) arnBytes.length).put(arnBytes).array();
  }

  // An absent and an empty encryption context are the same, as in KMS.
  private static byte[] aad(Map<String, String> context) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (Map.Entry<String, String> entry : new TreeMap<>(context).entrySet()) {
      writeField(out, entry.getKey());
      writeField(out, entry.getValue());
    }
    return out.toByteArray();
  }

  private static void writeField(ByteArrayOutputStream out, String value) {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    out.write(ByteBuffer.allocate(4).putInt(bytes.length).array(), 0, 4);
    out.write(bytes, 0, bytes.length);
  }

  private Key resolve(String identifier, String region) {
    String[] parts = identifier.split(":", 6);
    if (identifier.startsWith("arn:") && parts.length == 6 && parts[2].equals("kms") && !parts[3].equals(region)) {
      throw ServiceError.of("NotFoundException", "Invalid arn " + parts[3]);
    }
    Key key = tryResolve(identifier, region);
    if (key != null) {
      return key;
    }
    String arn = identifier.startsWith("arn:") ? identifier : arnPrefix(region) + (identifier.startsWith("alias/") ? identifier : "key/" + identifier);
    if (arn.contains(":alias/")) {
      throw ServiceError.of("NotFoundException", "Alias " + arn + " is not found.");
    }
    throw ServiceError.of("NotFoundException", "Key '" + arn + "' does not exist");
  }

  /** The key {@code identifier} names in {@code region}, or null. */
  private Key tryResolve(String identifier, String region) {
    String arn;
    if (identifier.startsWith("arn:")) {
      String[] parts = identifier.split(":", 6);
      if (parts.length != 6 || !parts[2].equals("kms") || !parts[3].equals(region)) {
        return null;
      }
      arn = parts[5].startsWith("alias/") ? aliases.get(identifier) : identifier;
    } else if (identifier.startsWith("alias/")) {
      arn = aliases.get(arnPrefix(region) + identifier);
    } else {
      arn = arnPrefix(region) + "key/" + identifier;
    }
    return arn == null ? null : keys.get(arn);
  }

  private Key existing(String keyArn) {
    Key key = keys.get(keyArn);
    if (key == null) {
      throw new IllegalArgumentException("no such key: " + keyArn);
    }
    return key;
  }

  private void failIfConfigured(String operation, String keyArn) {
    for (Failure failure : failures) {
      boolean keyMatches = failure.keyArn == null || failure.keyArn.equals(keyArn);
      if (failure.operation.equals(operation) && keyMatches) {
        throw failure.error;
      }
    }
  }

  private String add(String region, String id, Material material) {
    String arn = arnPrefix(region) + "key/" + id;
    keys.put(arn, new Key(arn, region, material));
    return arn;
  }

  private static String arnPrefix(String region) {
    return "arn:aws:kms:" + region + ":" + ACCOUNT + ":";
  }

  private static void requireSymmetric(Key key, String operation) {
    if (key.material.aesKey == null) {
      throw invalidKeyUsage(key, operation);
    }
  }

  private static void requireAlgorithm(ObjectNode request, String field) {
    JsonNode algorithm = request.get(field);
    if (algorithm != null && !algorithm.asText().equals(SYMMETRIC_DEFAULT)) {
      throw ServiceError.of("InvalidKeyUsageException", "The encryption algorithm " + algorithm.asText() + " is not compatible with a symmetric key");
    }
  }

  private static ServiceError invalidKeyUsage(Key key, String operation) {
    return ServiceError.of(
      "InvalidKeyUsageException",
      "You cannot use " + operation + " with " + key.arn + ": its key spec is " + key.material.keySpec +
        " and its key usage is " + key.material.keyUsage
    );
  }

  private static ServiceError validation(String message) {
    return ServiceError.of("ValidationException", message);
  }

  private static JsonNode required(ObjectNode request, String field) {
    JsonNode value = request.get(field);
    if (value == null || value.isNull()) {
      throw validation("Value null at '" + field + "' failed to satisfy constraint: Member must not be null");
    }
    return value;
  }

  private static byte[] blob(ObjectNode request, String field) {
    try {
      return Base64.getDecoder().decode(required(request, field).asText());
    } catch (IllegalArgumentException e) {
      throw ServiceError.of("SerializationException", field + " is not base64: " + e.getMessage());
    }
  }

  private static Map<String, String> encryptionContext(ObjectNode request, String field) {
    Map<String, String> context = new TreeMap<>();
    JsonNode node = request.get(field);
    if (node == null) {
      return context;
    }
    if (!node.isObject()) {
      throw ServiceError.of("SerializationException", field + " is not a JSON object");
    }
    Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> entry = fields.next();
      if (!entry.getValue().isTextual()) {
        throw ServiceError.of("SerializationException", field + " values must be strings");
      }
      context.put(entry.getKey(), entry.getValue().asText());
    }
    return context;
  }

  private static byte[] publicKeyDer(Key key) {
    return key.material.pair.getPublic().getEncoded();
  }

  private static String encode(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  private byte[] randomBytes(int length) {
    byte[] bytes = new byte[length];
    random.nextBytes(bytes);
    return bytes;
  }

  private static final class Material {

    final String keySpec;
    final String keyUsage;
    final byte[] aesKey;
    final KeyPair pair;

    Material(String keySpec, String keyUsage, byte[] aesKey, KeyPair pair) {
      this.keySpec = keySpec;
      this.keyUsage = keyUsage;
      this.aesKey = aesKey;
      this.pair = pair;
    }
  }

  private static final class Key {

    final String arn;
    final String region;
    final Material material;

    Key(String arn, String region, Material material) {
      this.arn = arn;
      this.region = region;
      this.material = material;
    }
  }

  private static final class Opened {

    final Key key;
    final byte[] plaintext;

    Opened(Key key, byte[] plaintext) {
      this.key = key;
      this.plaintext = plaintext;
    }
  }

  private static final class Edit {

    final String operation;
    final String keyArn;
    final UnaryOperator<ObjectNode> edit;

    Edit(String operation, String keyArn, UnaryOperator<ObjectNode> edit) {
      this.operation = operation;
      this.keyArn = keyArn;
      this.edit = edit;
    }
  }

  private static final class Failure {

    final String operation;
    final String keyArn;
    final ServiceError error;

    Failure(String operation, String keyArn, ServiceError error) {
      this.operation = operation;
      this.keyArn = keyArn;
      this.error = error;
    }
  }
}
