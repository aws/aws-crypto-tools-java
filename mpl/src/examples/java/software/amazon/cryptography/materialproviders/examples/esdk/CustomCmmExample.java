// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptMaterialsResponse;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsResponse;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;

/**
 * A materials manager the customer implements by wrapping the default one: it stamps every message with the
 * application name, insists on signed messages, and checks the stamp on decrypt.
 * ESDK 3.0 tells owners of custom legacy managers to move to this interface.
 */
public final class CustomCmmExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private CustomCmmExample() {}

  /** @param kmsClient real AWS: {@code KmsClient.create()} */
  public static void encryptAndDecrypt(String keyArn, KmsClient kmsClient) {
    CryptographicMaterialsManager cmm = new ApplicationCmm(
      "billing",
      DefaultCryptographicMaterialsManager.create(AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build())
    );
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Map<String, String> encryptionContext = Collections.singletonMap("order", "1234");

    byte[] ciphertext = crypto.encryptData(cmm, EXAMPLE_DATA, encryptionContext);
    EsdkLikeClient.Decrypted decrypted = crypto.decryptData(cmm, ciphertext, encryptionContext);
    Expect.equal(EXAMPLE_DATA, decrypted.getResult());
    Expect.isTrue("billing".equals(decrypted.getEncryptionContext().get("application")), "the stamp in the context");

    // Another application's manager rejects the message.
    CryptographicMaterialsManager other = new ApplicationCmm(
      "shipping",
      DefaultCryptographicMaterialsManager.create(AwsKmsKeyring.builder().kmsKeyId(keyArn).kmsClient(kmsClient).build())
    );
    Expect.failure(ValidationException.class, () -> crypto.decryptData(other, ciphertext, encryptionContext));
  }

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
      GetEncryptionMaterialsRequest.Builder stamped = request
        .toBuilder()
        .encryptionContext(request.encryptionContext().with(KEY, application));
      if (!request.algorithmSuiteId().isPresent()) {
        stamped.algorithmSuiteId(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384);
      } else if (!request.algorithmSuiteId().get().isSigning()) {
        throw new ValidationException("Messages must be signed");
      }
      return underlying.getEncryptionMaterials(stamped.build());
    }

    @Override
    public DecryptMaterialsResponse decryptMaterials(DecryptMaterialsRequest request) {
      if (!application.equals(request.encryptionContext().get(KEY))) {
        throw new ValidationException("Message is not from " + application);
      }
      if (!request.algorithmSuiteId().isSigning()) {
        throw new ValidationException("Messages must be signed");
      }
      // The caller need not repeat the stamp; it is added to what they reproduced.
      EncryptionContext reproduced = request.reproducedEncryptionContext().orElse(EncryptionContext.empty()).with(KEY, application);
      return underlying.decryptMaterials(request.toBuilder().reproducedEncryptionContext(reproduced).build());
    }
  }
}
