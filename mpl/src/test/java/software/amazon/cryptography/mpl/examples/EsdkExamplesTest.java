// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.FakeKms;
import software.amazon.cryptography.materialproviders.fakeaws.RecordedRequest;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.CryptographicMaterialsManager;
import software.amazon.cryptography.mpl.DecryptMaterialsRequest;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.mpl.examples.esdk.AwsKmsRsaKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.CommitmentPolicyAndAlgorithmExample;
import software.amazon.cryptography.mpl.examples.esdk.CustomClientSupplierExample;
import software.amazon.cryptography.mpl.examples.esdk.CustomCmmExample;
import software.amazon.cryptography.mpl.examples.esdk.CustomKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.DiscoveryKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.ErrorHandlingExample;
import software.amazon.cryptography.mpl.examples.esdk.ErrorHandlingExample.Outcome;
import software.amazon.cryptography.mpl.examples.esdk.EscrowMultiKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.EsdkLikeClient;
import software.amazon.cryptography.mpl.examples.esdk.HierarchicalKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.KmsKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.KmsMultiKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.MrkDiscoveryKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.RawAesKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.RawEcdhKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.RawRsaKeyringExample;
import software.amazon.cryptography.mpl.examples.esdk.RequiredEncryptionContextCmmExample;
import software.amazon.cryptography.mpl.examples.esdk.SharedCacheExample;
import software.amazon.cryptography.mpl.examples.esdk.integration.CmmHandler;
import software.amazon.cryptography.mpl.examples.esdk.integration.CommitmentPolicy;
import software.amazon.cryptography.mpl.examples.esdk.integration.CryptoAlgorithm;
import software.amazon.cryptography.mpl.examples.esdk.integration.EncryptionMaterialsHandler;
import software.amazon.cryptography.mpl.examples.esdk.integration.KeyBlob;
import software.amazon.cryptography.mpl.exceptions.EncryptionContextMismatchException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.keyrings.AesWrappingAlg;
import software.amazon.cryptography.mpl.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.mpl.keyrings.RawAesKeyring;
import software.amazon.cryptography.mpl.keyrings.ClientSupplier;
import software.amazon.cryptography.mpl.keystore.BranchKeyStore;
import software.amazon.cryptography.mpl.keystore.KmsConfiguration;

// Runs every ESDK example against the in-process fake AWS. The examples check their own results and throw on a mismatch;
// these tests add what only the fake can observe (requests sent, clients built) and pin the integration mappings.
class EsdkExamplesTest {

  private static final String REGION = "us-west-2";
  private static final byte[] DATA = "data".getBytes(StandardCharsets.UTF_8);
  private static final Map<String, String> CONTEXT = Collections.singletonMap("k", "v");

  private final FakeAws aws = FakeAws.start();
  private final KmsClient kms = aws.kmsClient("native", REGION);
  private final ClientSupplier clients = region -> aws.kmsClient("native", region);

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void kmsMultiKeyring() {
    KmsMultiKeyringExample.encryptAndDecrypt(aws.kms().createSymmetricKey(REGION), aws.kms().createSymmetricKey("us-east-1"), clients);
  }

  @Test
  void kmsKeyring() {
    KmsKeyringExample.encryptAndDecrypt(aws.kms().createSymmetricKey(REGION), kms);
  }

  @Test
  void discoveryKeyrings() {
    DiscoveryKeyringExample.encryptAndDecrypt(aws.kms().createSymmetricKey(REGION), REGION, "aws", FakeKms.ACCOUNT, kms, clients);
  }

  @Test
  void mrkDiscoveryKeyringDecryptsInTheReplicaRegion() {
    String encryptArn = aws.kms().createMultiRegionKey("us-east-1", REGION).get(0);
    MrkDiscoveryKeyringExample.encryptAndDecrypt(encryptArn, REGION, "aws", FakeKms.ACCOUNT, clients);
    List<String> decryptRegions = requests("Decrypt").stream().map(RecordedRequest::region).collect(Collectors.toList());
    assertEquals(Collections.singletonList(REGION), decryptRegions);
  }

  @Test
  void rawKeyrings() throws Exception {
    RawAesKeyringExample.encryptAndDecrypt();
    RawRsaKeyringExample.encryptAndDecrypt();
    RawEcdhKeyringExample.encryptAndDecrypt();
  }

  @Test
  void escrowMultiKeyring() throws Exception {
    EscrowMultiKeyringExample.encryptAndDecrypt(aws.kms().createSymmetricKey(REGION), kms);
  }

  @Test
  void awsKmsRsaKeyring() {
    String arn = aws.kms().createRsaKey(REGION, "RSA_2048");
    AwsKmsRsaKeyringExample.encryptAndDecrypt(arn, aws.kms().publicKeyPem(arn).getBytes(StandardCharsets.UTF_8), kms);
  }

  @Test
  void hierarchicalKeyringWithKeyStoreAdmin() {
    HierarchicalKeyringExample.encryptAndDecrypt(
      "KeyStoreTable",
      "logical",
      aws.kms().createSymmetricKey(REGION),
      kms,
      aws.dynamoDbClient("native", REGION)
    );
  }

  // Encrypt and decrypt each need one branch key unwrap; with the cache shared, keyring2 needs none.
  @Test
  void sharedCacheServesTheSecondKeyring() {
    String kmsKey = aws.kms().createSymmetricKey(REGION);
    String branchKeyId;
    try (BranchKeyStore admin = keyStore(kmsKey)) {
      admin.createKeyStore();
      branchKeyId = admin.createKey();
    }
    aws.clearRequests();
    SharedCacheExample.encryptAndDecrypt("KeyStoreTable", "logical", "partition", kmsKey, branchKeyId, kms, aws.dynamoDbClient("native", REGION));
    assertEquals(2, requests("Decrypt").size());
  }

  @Test
  void requiredEncryptionContextCmm() {
    RequiredEncryptionContextCmmExample.encryptAndDecrypt(aws.kms().createSymmetricKey(REGION), kms);
  }

  @Test
  void customClientSupplierBuildsOneClientPerRegion() {
    Map<String, KmsClient> built = CustomClientSupplierExample.encryptAndDecrypt(
      aws.kms().createSymmetricKey(REGION),
      region -> aws.kmsClient("custom", region)
    );
    assertEquals(Collections.singleton(REGION), built.keySet());
    assertFalse(aws.requests("custom").isEmpty());
    assertTrue(aws.requests("native").isEmpty());
  }

  @Test
  void commitmentPolicyAndAlgorithm() {
    CommitmentPolicyAndAlgorithmExample.encryptAndDecrypt(aws.kms().createSymmetricKey(REGION), kms);
  }

  @Test
  void customKeyringAndCmm() {
    CustomKeyringExample.encryptAndDecrypt();
    CustomCmmExample.encryptAndDecrypt(aws.kms().createSymmetricKey(REGION), kms);
  }

  @Test
  void errorHandlingClassifiesFailures() {
    String key = aws.kms().createSymmetricKey(REGION);
    Keyring keyring = AwsKmsKeyring.builder().kmsKeyId(key).kmsClient(kms).build();
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    byte[] ciphertext = crypto.encryptData(keyring, DATA, CONTEXT);

    assertEquals(Outcome.DECRYPTED, ErrorHandlingExample.decrypt(crypto, keyring, ciphertext, CONTEXT));
    Keyring otherKey = AwsKmsKeyring.builder().kmsKeyId(aws.kms().createSymmetricKey(REGION)).kmsClient(kms).build();
    assertEquals(Outcome.NOT_FOR_THIS_KEYRING, ErrorHandlingExample.decrypt(crypto, otherKey, ciphertext, CONTEXT));
    Map<String, String> otherValue = Collections.singletonMap("k", "other");
    assertEquals(Outcome.INVALID_REQUEST, ErrorHandlingExample.decrypt(crypto, keyring, ciphertext, otherValue));
    assertThrows(EncryptionContextMismatchException.class, () -> crypto.decryptData(keyring, ciphertext, otherValue));

    aws.kms().fail("Decrypt", key, ServiceError.accessDenied("no kms:Decrypt"));
    assertEquals(Outcome.ACCESS_DENIED, ErrorHandlingExample.decrypt(crypto, keyring, ciphertext, CONTEXT));
    aws.kms().clearFailures();
    aws.kms().fail("Decrypt", key, ServiceError.throttling("slow down"));
    assertEquals(Outcome.RETRY_LATER, ErrorHandlingExample.decrypt(crypto, keyring, ciphertext, CONTEXT));
  }

  // Every suite through the stand-in: key derivation, commitment, and both signature curves.
  @Test
  void everySuiteRoundTrips() {
    Keyring keyring = rawAesKeyring();
    for (CryptoAlgorithm algorithm : CryptoAlgorithm.values()) {
      EsdkLikeClient crypto = EsdkLikeClient
        .builder()
        .withEncryptionAlgorithm(algorithm)
        .withCommitmentPolicy(algorithm.isCommitting() ? CommitmentPolicy.RequireEncryptRequireDecrypt : CommitmentPolicy.ForbidEncryptAllowDecrypt)
        .build();
      byte[] message = crypto.encryptData(keyring, DATA, CONTEXT);
      assertArrayEquals(DATA, crypto.decryptData(keyring, message, CONTEXT).getResult(), algorithm.toString());
    }
  }

  // The stand-in must not accept what the ESDK rejects, or it would hide a wrong MPL key.
  @Test
  void tamperedSignatureAndCommitmentFail() {
    Keyring keyring = rawAesKeyring();
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    byte[] signed = crypto.encryptData(keyring, DATA, CONTEXT);
    signed[signed.length - 1] ^= 1;
    assertEquals("Bad trailing signature", assertThrows(EsdkLikeClient.AwsCryptoException.class, () -> crypto.decryptData(keyring, signed, CONTEXT)).getMessage());

    EsdkLikeClient unsigned = EsdkLikeClient.builder().withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY).build();
    byte[] committed = unsigned.encryptData(keyring, DATA, CONTEXT);
    // The commitment ends the header, before the IV, the ciphertext length, and the ciphertext with its tag.
    committed[committed.length - (12 + 2 + DATA.length + 16) - 1] ^= 1;
    assertEquals(
      "Key commitment validation failed",
      assertThrows(EsdkLikeClient.AwsCryptoException.class, () -> unsigned.decryptData(keyring, committed, CONTEXT)).getMessage()
    );
  }

  // A customer manager that answers for another suite: the data key fits, the message must still be refused.
  @Test
  void materialsForAnotherSuiteAreRefused() {
    Keyring keyring = rawAesKeyring();
    EsdkLikeClient crypto = EsdkLikeClient
      .builder()
      .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256)
      .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
      .build();
    byte[] message = crypto.encryptData(keyring, DATA, CONTEXT);
    CryptographicMaterialsManager defaultCmm = DefaultCryptographicMaterialsManager.of(keyring);
    CryptographicMaterialsManager wrongSuite = new CryptographicMaterialsManager() {
      @Override
      public EncryptionMaterials getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
        return defaultCmm.getEncryptionMaterials(request);
      }

      @Override
      public DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request) {
        return defaultCmm.decryptMaterials(
          DecryptMaterialsRequest
            .builder()
            .algorithmSuiteId(AlgorithmSuite.ALG_AES_128_GCM_IV12_TAG16_NO_KDF)
            .commitmentPolicy(request.commitmentPolicy())
            .encryptedDataKeys(request.encryptedDataKeys())
            .encryptionContext(request.encryptionContext())
            .build()
        );
      }
    };
    assertThrows(EsdkLikeClient.AwsCryptoException.class, () -> crypto.decryptData(wrongSuite, message, CONTEXT));
  }

  // The getters return what ESDK 3.x returns from GetAlgorithmSuiteInfo:
  // value, version, message id length, header nonce, nonce, tag, key length, data key algorithm, signature algorithm,
  // signature length, safe to cache, committing, commitment length, commitment nonce length, suite data length, commitment algorithm.
  @Test
  void cryptoAlgorithmMatchesEsdk3() {
    List<String> expected = Arrays.asList(
      "20 1 16 null 12 16 16 AES null 0 false false 0 0 0 null",
      "70 1 16 null 12 16 24 AES null 0 false false 0 0 0 null",
      "120 1 16 null 12 16 32 AES null 0 false false 0 0 0 null",
      "276 1 16 null 12 16 16 HkdfSHA256 null 0 true false 0 0 0 null",
      "326 1 16 null 12 16 24 HkdfSHA256 null 0 true false 0 0 0 null",
      "376 1 16 null 12 16 32 HkdfSHA256 null 0 true false 0 0 0 null",
      "532 1 16 null 12 16 16 HkdfSHA256 SHA256withECDSA 71 true false 0 0 0 null",
      "838 1 16 null 12 16 24 HkdfSHA384 SHA384withECDSA 103 true false 0 0 0 null",
      "888 1 16 null 12 16 32 HkdfSHA384 SHA384withECDSA 103 true false 0 0 0 null",
      "1144 2 32 12 12 16 32 HkdfSHA512 null 0 true true 32 32 32 HkdfSHA512",
      "1400 2 32 12 12 16 32 HkdfSHA512 SHA384withECDSA 103 true true 32 32 32 HkdfSHA512"
    );
    List<String> actual = new ArrayList<>();
    for (CryptoAlgorithm a : CryptoAlgorithm.values()) {
      byte[] nonce = a.getHeaderNonce();
      actual.add(
        Stream
          .of(
            a.getValue(), a.getMessageFormatVersion(), a.getMessageIdLength(), nonce == null ? null : nonce.length,
            a.getNonceLen(), a.getTagLen(), a.getKeyLength(), a.getDataKeyAlgo(), a.getTrailingSignatureAlgo(),
            a.getTrailingSignatureLength(), a.isSafeToCache(), a.isCommitting(), a.getCommitmentLength(),
            a.getCommitmentNonceLength(), a.getSuiteDataLength(), a.getKeyCommitmentAlgo_()
          )
          .map(String::valueOf)
          .collect(Collectors.joining(" "))
      );
      assertEquals(a, CryptoAlgorithm.of(a.algorithmSuite()));
      assertEquals(a, CryptoAlgorithm.deserialize(a.getMessageFormatVersion(), a.getValue()));
    }
    assertEquals(expected, actual);
    assertNull(CryptoAlgorithm.deserialize((byte) 2, (short) 0x0378));
  }

  // ESDK 3.x CommitmentPolicy: Forbid encrypts only non-committing suites; only RequireRequire refuses to decrypt them.
  @Test
  void commitmentPolicyMatchesEsdk3() {
    for (CryptoAlgorithm algorithm : CryptoAlgorithm.values()) {
      boolean committing = algorithm.isCommitting();
      assertEquals(!committing, CommitmentPolicy.ForbidEncryptAllowDecrypt.algorithmAllowedForEncrypt(algorithm));
      assertEquals(committing, CommitmentPolicy.RequireEncryptAllowDecrypt.algorithmAllowedForEncrypt(algorithm));
      assertEquals(committing, CommitmentPolicy.RequireEncryptRequireDecrypt.algorithmAllowedForEncrypt(algorithm));
      assertTrue(CommitmentPolicy.ForbidEncryptAllowDecrypt.algorithmAllowedForDecrypt(algorithm));
      assertTrue(CommitmentPolicy.RequireEncryptAllowDecrypt.algorithmAllowedForDecrypt(algorithm));
      assertEquals(committing, CommitmentPolicy.RequireEncryptRequireDecrypt.algorithmAllowedForDecrypt(algorithm));
    }
  }

  // ESDK 3.x decoded the signing key with new BigInteger(1, bytes); the MPL's JCA key must hold the same scalar.
  @Test
  void trailingSignatureKeyIsTheScalarEsdk3Decoded() {
    Recording recording = new Recording(DefaultCryptographicMaterialsManager.of(newKmsKeyring()));
    EncryptionMaterialsHandler materials = new CmmHandler(recording)
      .getMaterialsForEncrypt(CONTEXT, null, CommitmentPolicy.RequireEncryptRequireDecrypt, 4);
    BigInteger scalar = new BigInteger(1, recording.encryption.signingKey().get().toByteArray());
    assertEquals(scalar, ((ECPrivateKey) materials.getTrailingSignatureKey()).getS());
  }

  @Test
  void p256TrailingSignatureKeyIsTheScalarEsdk3Decoded() {
    Recording recording = new Recording(DefaultCryptographicMaterialsManager.of(rawAesKeyring()));
    EncryptionMaterialsHandler materials = new CmmHandler(recording).getMaterialsForEncrypt(
      CONTEXT,
      CryptoAlgorithm.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
      CommitmentPolicy.ForbidEncryptAllowDecrypt,
      4
    );
    BigInteger scalar = new BigInteger(1, recording.encryption.signingKey().get().toByteArray());
    ECPrivateKey key = (ECPrivateKey) materials.getTrailingSignatureKey();
    assertEquals(scalar, key.getS());
    assertEquals(256, key.getParams().getCurve().getField().getFieldSize());
  }

  @Test
  void cmmHandlerMapsUnknownPlaintextSizeToAbsent() {
    Recording recording = new Recording(DefaultCryptographicMaterialsManager.of(newKmsKeyring()));
    CmmHandler handler = new CmmHandler(recording);
    handler.getMaterialsForEncrypt(CONTEXT, null, CommitmentPolicy.RequireEncryptRequireDecrypt, -1);
    assertEquals(OptionalLong.empty(), recording.encryptRequest.maxPlaintextLength());
    handler.getMaterialsForEncrypt(CONTEXT, CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, CommitmentPolicy.RequireEncryptRequireDecrypt, 0);
    assertEquals(OptionalLong.of(0), recording.encryptRequest.maxPlaintextLength());
    assertEquals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, recording.encryptRequest.algorithmSuiteId().get());
  }

  @Test
  void keyBlobConversionKeepsEveryField() {
    EncryptedDataKey edk = EncryptedDataKey.of("provider", new byte[] { 1, 2 }, new byte[] { 3 });
    KeyBlob blob = KeyBlob.from(edk);
    assertEquals("provider", blob.getProviderId());
    assertArrayEquals(new byte[] { 1, 2 }, blob.getProviderInformation());
    assertArrayEquals(new byte[] { 3 }, blob.getEncryptedDataKey());
    assertEquals(edk, blob.toEncryptedDataKey());
  }

  // The examples show customer and ESDK code, which can only use the public API.
  @Test
  void examplesUseOnlyThePublicApi() throws IOException {
    List<Path> offending;
    try (Stream<Path> files = Files.walk(Paths.get("src/examples/java/software/amazon/cryptography/mpl/examples/esdk"))) {
      offending = files
        .filter(path -> path.toString().endsWith(".java"))
        .filter(path -> read(path).contains("software.amazon.cryptography.mpl.internal"))
        .collect(Collectors.toList());
    }
    assertEquals(Collections.emptyList(), offending);
  }

  private static String read(Path path) {
    try {
      return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private List<RecordedRequest> requests(String operation) {
    return aws.requests().stream().filter(r -> r.service().equals("kms") && r.operation().equals(operation)).collect(Collectors.toList());
  }

  private BranchKeyStore keyStore(String kmsKey) {
    return BranchKeyStore
      .builder()
      .ddbTableName("KeyStoreTable")
      .logicalKeyStoreName("logical")
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKey))
      .kmsClient(kms)
      .ddbClient(aws.dynamoDbClient("native", REGION))
      .build();
  }

  private static Keyring rawAesKeyring() {
    return RawAesKeyring
      .builder()
      .keyNamespace("ns")
      .keyName("name")
      .wrappingKey(SecretBytes.random(32))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
  }

  private Keyring newKmsKeyring() {
    return AwsKmsKeyring.builder().kmsKeyId(aws.kms().createSymmetricKey(REGION)).kmsClient(kms).build();
  }

  /** Passes calls through and keeps the last request and result. */
  private static final class Recording implements CryptographicMaterialsManager {

    private final CryptographicMaterialsManager underlying;
    GetEncryptionMaterialsRequest encryptRequest;
    EncryptionMaterials encryption;

    Recording(CryptographicMaterialsManager underlying) {
      this.underlying = underlying;
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
      encryptRequest = request;
      encryption = underlying.getEncryptionMaterials(request);
      return encryption;
    }

    @Override
    public DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request) {
      return underlying.decryptMaterials(request);
    }
  }
}
