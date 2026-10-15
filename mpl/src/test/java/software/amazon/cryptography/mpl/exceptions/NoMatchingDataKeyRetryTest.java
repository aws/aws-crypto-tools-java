// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.exceptions;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.RetryableException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.mpl.keyrings.MultiKeyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;

// NoMatchingDataKeyException.isRetryable: any collected failure that is retryable, unless the thread was interrupted.
// The old API has no isRetryable; AwsKmsMultiKeyringTest compares the throttled decrypt itself with the reference.
class NoMatchingDataKeyRetryTest {

  @Test
  void retryableWhenAnyFailureIsRetryable() {
    assertTrue(noMatch(new ThrottlingException("slow")).isRetryable());
    assertTrue(noMatch(new DispatchException("unreachable")).isRetryable());
    assertTrue(noMatch(new AccessDeniedException("no"), new ThrottlingException("slow")).isRetryable());
    assertTrue(noMatch(new ServiceException("busy", RetryableException.builder().message("retry me").build())).isRetryable());
    // A custom keyring can let an AWS SDK exception through unwrapped; its place among the failures does not matter.
    RetryableException unwrapped = RetryableException.builder().message("retry me").build();
    AccessDeniedException denied = new AccessDeniedException("no", software.amazon.awssdk.services.kms.model.KmsException.builder().message("no").build());
    assertTrue(noMatch(unwrapped).isRetryable());
    assertTrue(noMatch(denied, unwrapped).isRetryable());
    assertTrue(noMatch(unwrapped, denied).isRetryable());
    software.amazon.awssdk.core.exception.SdkException notRetryable = software.amazon.awssdk.core.exception.SdkException.builder().message("no").build();
    assertTrue(noMatch(notRetryable, unwrapped).isRetryable());
    assertFalse(noMatch(notRetryable).isRetryable());
  }

  @Test
  void notRetryableWhenNoFailureIs() {
    assertFalse(noMatch().isRetryable());
    assertFalse(noMatch(new AccessDeniedException("no"), new CryptographicException("tag")).isRetryable());
    assertFalse(noMatch(new IllegalStateException("a customer keyring's failure")).isRetryable());
  }

  @Test
  void nestedFailuresCount() {
    assertTrue(noMatch(noMatch(new ThrottlingException("slow"))).isRetryable());
    assertFalse(noMatch(noMatch(new AccessDeniedException("no"))).isRetryable());
  }

  @Test
  void anInterruptedAttemptIsNeverRetryable() {
    ThrottlingException interrupted = new ThrottlingException("slow", new InterruptedException());
    assertFalse(noMatch(interrupted).isRetryable());
    assertFalse(noMatch(new ThrottlingException("slow"), new DispatchException("cancelled", new InterruptedException())).isRetryable());
  }

  @Test
  void aThrottledKmsDecryptIsRetryable() {
    try (FakeAws aws = FakeAws.start()) {
      KmsClient kms = aws.kmsClient("retry", "us-west-2");
      Keyring keyring = AwsKmsKeyring.builder().kmsKeyId(aws.kms().createSymmetricKey("us-west-2")).kmsClient(kms).build();
      Keyring multi = MultiKeyring.builder().generator(keyring).build();
      EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(EncryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()).build());
      DecryptionMaterials start = DecryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build();
      List<EncryptedDataKey> edks = encrypted.encryptedDataKeys();

      aws.kms().fail("Decrypt", null, ServiceError.throttling("slow down"));
      assertTrue(assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(edks).build())).isRetryable());
      assertTrue(assertThrows(NoMatchingDataKeyException.class, () -> multi.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(edks).build())).isRetryable());
      aws.kms().clearFailures();

      aws.kms().fail("Decrypt", null, ServiceError.accessDenied("no"));
      assertFalse(assertThrows(NoMatchingDataKeyException.class, () -> multi.onDecrypt(OnDecryptRequest.builder().materials(start).encryptedDataKeys(edks).build())).isRetryable());
    }
  }

  private static NoMatchingDataKeyException noMatch(Throwable... failures) {
    return new NoMatchingDataKeyException("Unable to decrypt", failures.length == 0 ? Collections.emptyList() : Arrays.asList(failures));
  }
}
