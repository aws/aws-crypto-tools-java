// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkValidationException;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptMaterialsResponse;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsResponse;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Encrypts and decrypts messages with a materials manager the application implements. It wraps the default
 * manager, stamps every message with the application's name, accepts only messages with that stamp, and
 * requires a signing algorithm suite.
 *
 * <p>Owners of a custom ESDK {@code CryptoMaterialsManager} move their logic to this interface.
 *
 * <p>No arguments; runs without AWS (the default manager uses a raw AES keyring).
 */
public final class CustomCmmExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private CustomCmmExample() {}

  public static void main(String[] args) throws GeneralSecurityException {
    run();
  }

  public static void run() throws GeneralSecurityException {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();

    // 2. Create a keyring, and wrap its default materials manager in the custom one.
    // wrappingKey takes SecretBytes, a byte[], or, as here, a JCA SecretKey; the keyring keeps its own copy.
    // A JCA key cannot be cleared; RawAesKeyringExample keeps the key in SecretBytes, which can.
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(256);
    SecretKey wrappingKey = generator.generateKey();
    Keyring keyring = RawAesKeyring
      .builder()
      .keyNamespace("example-namespace")
      .keyName("example-key")
      .wrappingKey(wrappingKey)
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    CryptographicMaterialsManager defaultCmm = DefaultCryptographicMaterialsManager.create(keyring);
    CryptographicMaterialsManager billingCmm = new ApplicationCmm("billing", defaultCmm);

    // 3. Encrypt and decrypt; the manager adds its stamp to the message's encryption context.
    Map<String, String> encryptionContext = Collections.singletonMap("order", "1234");
    EncryptResponse encryptResponse = esdk.encrypt(b ->
      b.plaintext(EXAMPLE_DATA).materialsManager(billingCmm).encryptionContext(encryptionContext)
    );
    DecryptResponse decryptResponse = esdk.decrypt(b ->
      b.ciphertext(encryptResponse.ciphertext()).materialsManager(billingCmm).encryptionContext(encryptionContext)
    );
    if (!Arrays.equals(decryptResponse.plaintext(), EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }
    if (!"billing".equals(decryptResponse.encryptionContext().get("application"))) {
      throw new IllegalStateException("The message has no application stamp");
    }

    // 4. Another application's manager rejects the message, though it uses the same keyring.
    CryptographicMaterialsManager shippingCmm = new ApplicationCmm("shipping", defaultCmm);
    try {
      esdk.decrypt(b -> b.ciphertext(encryptResponse.ciphertext()).materialsManager(shippingCmm));
      throw new IllegalStateException("The shipping manager accepted a billing message");
    } catch (EsdkValidationException expected) {
      // Rejected by ApplicationCmm before any data key is decrypted; the ESDK wraps the manager's ValidationException.
    }

    // 5. The manager refuses a suite that does not sign.
    // The suite is a request member, so the same client encrypts with it.
    try {
      esdk.encrypt(b ->
        b
          .plaintext(EXAMPLE_DATA)
          .materialsManager(billingCmm)
          .algorithmSuite(EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
      );
      throw new IllegalStateException("The manager allowed a suite without a signature");
    } catch (EsdkValidationException expected) {
      // Rejected by ApplicationCmm.
    }
  }

  /** Adds {@code application=<name>} to every message, and decrypts only signed messages with that stamp. */
  static final class ApplicationCmm implements CryptographicMaterialsManager {

    private static final String KEY = "application";

    private final String application;
    private final CryptographicMaterialsManager underlying;

    ApplicationCmm(String application, CryptographicMaterialsManager underlying) {
      this.application = application;
      this.underlying = underlying;
    }

    @Override
    public GetEncryptionMaterialsResponse getEncryptionMaterials(GetEncryptionMaterialsRequest request) {
      String existing = request.encryptionContext().get(KEY);
      if (existing != null && !existing.equals(application)) {
        throw new ValidationException("The encryption context names another application: " + existing);
      }
      // Checked early, so a refused request costs no data key.
      if (request.algorithmSuite().isPresent()) {
        requireSigning(request.algorithmSuite().get());
      }
      GetEncryptionMaterialsRequest stamped = request
        .toBuilder()
        .encryptionContext(request.encryptionContext().with(KEY, application))
        .build();
      GetEncryptionMaterialsResponse response = underlying.getEncryptionMaterials(stamped);
      // With no suite requested, the underlying manager chooses one, so check what it chose.
      requireSigning(response.encryptionMaterials().algorithmSuite());
      return response;
    }

    @Override
    public DecryptMaterialsResponse decryptMaterials(DecryptMaterialsRequest request) {
      // Checked before the underlying manager runs, so a rejected message costs no key unwrapping.
      if (!application.equals(request.encryptionContext().get(KEY))) {
        throw new ValidationException("The message is not from " + application);
      }
      requireSigning(request.algorithmSuite());
      return underlying.decryptMaterials(request);
    }

    private static void requireSigning(AlgorithmSuite suite) {
      if (!suite.isSigning()) {
        throw new ValidationException("Messages must be signed; the suite is " + suite);
      }
    }
  }
}
