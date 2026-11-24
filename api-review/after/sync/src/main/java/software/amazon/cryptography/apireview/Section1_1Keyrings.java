// Section 1.1 of the API review doc: Keyrings
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;
import software.amazon.cryptography.materialproviders.keyrings.DiscoveryFilter;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.PaddingScheme;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyAgreementScheme;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawRsaKeyring;

final class Section1_1Keyrings {
  private Section1_1Keyrings() {}

  // 1.1: Keyrings build themselves
  static byte[] multi(EsdkClient esdk, String keyArn1, String keyArn2, byte[] plaintext,
      Map<String, String> encryptionContext) {
    // @card 11-build
    AwsKmsMultiKeyring keyring = AwsKmsMultiKeyring.builder()
        .generator(keyArn1)
        .kmsKeyIds(keyArn2)
        .build();
    byte[] ciphertext = esdk.encrypt(b -> b
        .plaintext(plaintext).keyring(keyring).encryptionContext(encryptionContext)).ciphertext();
    // @end
    return ciphertext;
  }

  // 1.1: Key lists take a list or several keys
  static byte[] keyList(EsdkClient esdk, KmsClient kmsClient, String keyArn1, String keyArn2, String keyArn3,
      String keyArn4, byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 11-keylist
    AwsKmsMultiKeyring keyring = AwsKmsMultiKeyring.builder()
        .generator(keyArn1)
        .kmsKeyIds(keyArn2, keyArn3, keyArn4)
        .build();
    // The same keys as a List.
    List<String> listOfKeys = Arrays.asList(keyArn2, keyArn3, keyArn4);
    AwsKmsMultiKeyring sameKeyring = AwsKmsMultiKeyring.builder().generator(keyArn1).kmsKeyIds(listOfKeys).build();
    byte[] ciphertext = esdk.encrypt(b -> b
        .plaintext(plaintext).keyring(keyring).encryptionContext(encryptionContext)).ciphertext();
    // Any one of the keys decrypts.
    AwsKmsKeyring key3Only = AwsKmsKeyring.builder().kmsKeyId(keyArn3).kmsClient(kmsClient).build();
    byte[] decrypted = esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(key3Only)).plaintext();
    // @end
    return sameKeyring.kmsKeyIds().size() == 3 ? decrypted : ciphertext;
  }

  // 1.1: Discovery keyrings need a filter that names accounts
  static byte[] discovery(EsdkClient esdk, byte[] ciphertext) {
    // @card 11-discovery
    DiscoveryFilter filter = DiscoveryFilter.of(Collections.singletonList("111122223333"), "aws");
    AwsKmsDiscoveryMultiKeyring keyring = AwsKmsDiscoveryMultiKeyring.builder()
        .regions("us-west-2")
        .discoveryFilter(filter)
        .build();
    byte[] plaintext = esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(keyring)).plaintext();
    // @end
    return plaintext;
  }

  // 1.1: Keys go in as SecretBytes, bytes, or JCA keys
  static Keyring rsa(KeyPair keyPair) {
    // @card 11-keys
    // JCA keys go in directly; PEM bytes also work, as before.
    RawRsaKeyring keyring = RawRsaKeyring.builder()
        .keyNamespace("HSM_01")
        .keyName("RSA_2048_06")
        .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
        .publicKey(keyPair.getPublic())
        .privateKey(keyPair.getPrivate())
        .build();
    // @end
    return keyring;
  }

  // 1.1: One builder per ECDH scheme
  static Keyring ecdh(KeyPair senderKeyPair, PublicKey recipientPublicKey) {
    // @card 11-ecdh
    RawEcdhKeyAgreementScheme scheme = RawEcdhKeyAgreementScheme.rawPrivateKeyToStaticPublicKey()
        .senderStaticPrivateKey(senderKeyPair.getPrivate())
        .recipientPublicKey(recipientPublicKey)
        .build();
    RawEcdhKeyring keyring = RawEcdhKeyring.builder()
        .keyAgreementScheme(scheme)
        .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
        .build();
    // @end
    return keyring;
  }

  // 1.1: The client supplier takes a Region string
  static Keyring multiWithSupplier(String keyArn1, String keyArn2) {
    // @card 11-supplier
    ClientSupplier supplier = region -> KmsClient.builder().region(Region.of(region)).build();
    AwsKmsMultiKeyring keyring = AwsKmsMultiKeyring.builder()
        .generator(keyArn1)
        .kmsKeyIds(keyArn2)
        .clientSupplier(supplier)
        .build();
    // @end
    return keyring;
  }
}
