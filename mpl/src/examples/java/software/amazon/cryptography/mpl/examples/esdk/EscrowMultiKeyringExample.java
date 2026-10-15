// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.mpl.keyrings.MultiKeyring;
import software.amazon.cryptography.mpl.keyrings.PaddingScheme;
import software.amazon.cryptography.mpl.keyrings.RawRsaKeyring;

/**
 * Pattern (d): a multi keyring that encrypts under KMS and an escrow RSA public key, so the escrow private key
 * can decrypt without KMS. ESDK examples: EscrowedEncryptKeyringExample, MultiKeyringExample.
 */
public final class EscrowMultiKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private EscrowMultiKeyringExample() {}

  /** @param kmsClient real AWS: {@code KmsClient.create()} */
  public static void encryptAndDecrypt(String kmsKeyArn, KmsClient kmsClient) throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(4096);
    KeyPair escrow = generator.generateKeyPair();
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    Keyring kms = AwsKmsKeyring.builder().kmsKeyId(kmsKeyArn).kmsClient(kmsClient).build();
    Keyring escrowPublic = escrowKeyring().publicKey(escrow.getPublic()).build();
    Keyring multi = MultiKeyring.builder().generator(kms).childKeyrings(Collections.singletonList(escrowPublic)).build();
    byte[] ciphertext = crypto.encryptData(multi, EXAMPLE_DATA, encryptionContext);

    // The usual path: the multi keyring decrypts with KMS.
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(multi, ciphertext, encryptionContext).getResult());
    // The escrow path: the private key alone, no KMS.
    Keyring escrowPrivate = escrowKeyring().privateKey(escrow.getPrivate()).build();
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(escrowPrivate, ciphertext, encryptionContext).getResult());
  }

  private static RawRsaKeyring.Builder escrowKeyring() {
    return RawRsaKeyring.builder().keyNamespace("Escrow").keyName("Escrow").paddingScheme(PaddingScheme.OAEP_SHA512_MGF1);
  }
}
