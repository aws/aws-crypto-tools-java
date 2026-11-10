// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.materialproviders.keyrings.MultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.PaddingScheme;
import software.amazon.cryptography.materialproviders.keyrings.RawRsaKeyring;

/**
 * Encrypts under a KMS key and an escrow RSA public key, so the holder of the escrow private key can decrypt without
 * KMS, for example if access to the KMS key is lost.
 *
 * <p>Arguments: the ARN of a symmetric KMS key in the SDK's default Region. Calls KMS GenerateDataKey and Decrypt.
 */
public final class EscrowMultiKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private EscrowMultiKeyringExample() {}

  public static void main(String[] args) throws GeneralSecurityException {
    if (args.length != 1) {
      throw new IllegalArgumentException("Arguments: <kms-key-arn>");
    }
    try (KmsClient kmsClient = KmsClient.create()) {
      run(args[0], kmsClient);
    }
  }

  public static void run(String kmsKeyArn, KmsClient kmsClient) throws GeneralSecurityException {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();

    // 2. Create the escrow key pair.
    // In practice the escrow holder keeps the private key offline and gives the application only the public key.
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(4096);
    KeyPair escrowKeyPair = generator.generateKeyPair();

    // 3. Create the multi keyring: KMS generates the data key, and the escrow public key encrypts it again.
    Keyring kmsKeyring = AwsKmsKeyring.builder().kmsKeyId(kmsKeyArn).kmsClient(kmsClient).build();
    Keyring escrowEncryptingKeyring = escrowKeyring().publicKey(escrowKeyPair.getPublic()).build();
    Keyring multiKeyring = MultiKeyring.builder().generator(kmsKeyring).childKeyrings(escrowEncryptingKeyring).build();

    // 4. Encrypt, and decrypt the usual way, with KMS.
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    byte[] ciphertext = esdk
      .encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(multiKeyring).encryptionContext(encryptionContext))
      .ciphertext();
    byte[] decrypted = esdk
      .decrypt(b -> b.ciphertext(ciphertext).keyring(multiKeyring).encryptionContext(encryptionContext))
      .plaintext();
    if (!Arrays.equals(decrypted, EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }

    // 5. Decrypt with the escrow private key alone, without KMS.
    Keyring escrowDecryptingKeyring = escrowKeyring().privateKey(escrowKeyPair.getPrivate()).build();
    byte[] recovered = esdk
      .decrypt(b -> b.ciphertext(ciphertext).keyring(escrowDecryptingKeyring).encryptionContext(encryptionContext))
      .plaintext();
    if (!Arrays.equals(recovered, EXAMPLE_DATA)) {
      throw new IllegalStateException("Escrow-decrypted plaintext does not match");
    }
  }

  // The namespace and name are written into the message, so both escrow keyrings must use the same ones.
  private static RawRsaKeyring.Builder escrowKeyring() {
    return RawRsaKeyring
      .builder()
      .keyNamespace("escrow")
      .keyName("escrow-rsa-4096")
      .paddingScheme(PaddingScheme.OAEP_SHA512_MGF1);
  }
}
