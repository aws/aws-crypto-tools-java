// Section 1.1 of the API review doc: Keyrings
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import com.amazonaws.encryptionsdk.AwsCrypto;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.model.Discovery;
import software.amazon.cryptography.materialproviders.IClientSupplier;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsDiscoveryMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawEcdhKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.materialproviders.model.DiscoveryFilter;
import software.amazon.cryptography.materialproviders.model.GetClientInput;
import software.amazon.cryptography.materialproviders.model.PaddingScheme;
import software.amazon.cryptography.materialproviders.model.RawEcdhStaticConfigurations;
import software.amazon.cryptography.materialproviders.model.RawPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.primitives.model.ECDHCurveSpec;

final class Section1_1Keyrings {
  private Section1_1Keyrings() {}

  // 1.1: Keyrings build themselves
  static byte[] multi(MaterialProviders mpl, AwsCrypto crypto, String keyArn1, String keyArn2, byte[] plaintext,
      Map<String, String> encryptionContext) {
    // @card 11-build
    IKeyring keyring = mpl.CreateAwsKmsMultiKeyring(CreateAwsKmsMultiKeyringInput.builder()
        .generator(keyArn1)
        .kmsKeyIds(Collections.singletonList(keyArn2))
        .build());
    byte[] ciphertext = crypto.encryptData(keyring, plaintext, encryptionContext).getResult();
    // @end
    return ciphertext;
  }

  // 1.1: Key lists take a list or several keys
  static byte[] keyList(MaterialProviders mpl, AwsCrypto crypto, KmsClient kmsClient, String keyArn1,
      String keyArn2, String keyArn3, String keyArn4, byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 11-keylist
    IKeyring keyring = mpl.CreateAwsKmsMultiKeyring(CreateAwsKmsMultiKeyringInput.builder()
        .generator(keyArn1)
        .kmsKeyIds(Arrays.asList(keyArn2, keyArn3, keyArn4))
        .build());
    byte[] ciphertext = crypto.encryptData(keyring, plaintext, encryptionContext).getResult();
    // Any one of the keys decrypts.
    IKeyring key3Only = mpl.CreateAwsKmsKeyring(
        CreateAwsKmsKeyringInput.builder().kmsKeyId(keyArn3).kmsClient(kmsClient).build());
    byte[] decrypted = crypto.decryptData(key3Only, ciphertext, encryptionContext).getResult();
    // @end
    return decrypted;
  }

  // 1.1: Discovery keyrings need a filter that names accounts
  static byte[] discovery(MaterialProviders mpl, AwsCrypto crypto, byte[] ciphertext) {
    // @card 11-discovery
    DiscoveryFilter filter = DiscoveryFilter.builder()
        .accountIds(Collections.singletonList("111122223333"))
        .partition("aws")
        .build();
    IKeyring keyring = mpl.CreateAwsKmsDiscoveryMultiKeyring(CreateAwsKmsDiscoveryMultiKeyringInput.builder()
        .regions(Collections.singletonList("us-west-2"))
        .discoveryFilter(filter)
        .build());
    byte[] plaintext = crypto.decryptData(keyring, ciphertext).getResult();
    // @end
    return plaintext;
  }

  // 1.1: Keys go in as SecretBytes, bytes, or JCA keys
  static IKeyring rsa(MaterialProviders mpl, KeyPair keyPair) {
    // @card 11-keys
    // 1.x takes PEM-encoded keys.
    IKeyring keyring = mpl.CreateRawRsaKeyring(CreateRawRsaKeyringInput.builder()
        .keyNamespace("HSM_01")
        .keyName("RSA_2048_06")
        .paddingScheme(PaddingScheme.OAEP_SHA256_MGF1)
        .publicKey(ByteBuffer.wrap(pem("PUBLIC KEY", keyPair.getPublic().getEncoded())))
        .privateKey(ByteBuffer.wrap(pem("PRIVATE KEY", keyPair.getPrivate().getEncoded())))
        .build());
    // @end
    return keyring;
  }

  // 1.1: One builder per ECDH scheme
  static IKeyring ecdh(MaterialProviders mpl, KeyPair senderKeyPair, PublicKey recipientPublicKey) {
    // @card 11-ecdh
    RawEcdhStaticConfigurations scheme = RawEcdhStaticConfigurations.builder()
        .RawPrivateKeyToStaticPublicKey(RawPrivateKeyToStaticPublicKeyInput.builder()
            .senderStaticPrivateKey(ByteBuffer.wrap(pem("PRIVATE KEY", senderKeyPair.getPrivate().getEncoded())))
            .recipientPublicKey(ByteBuffer.wrap(recipientPublicKey.getEncoded()))
            .build())
        .build();
    IKeyring keyring = mpl.CreateRawEcdhKeyring(CreateRawEcdhKeyringInput.builder()
        .KeyAgreementScheme(scheme)
        .curveSpec(ECDHCurveSpec.ECC_NIST_P256)
        .build());
    // @end
    return keyring;
  }

  // 1.1: The client supplier takes a Region string
  static IKeyring multiWithSupplier(MaterialProviders mpl, String keyArn1, String keyArn2) {
    // @card 11-supplier
    IClientSupplier supplier = new IClientSupplier() {
      @Override
      public KmsClient GetClient(GetClientInput input) {
        return KmsClient.builder().region(Region.of(input.region())).build();
      }
    };
    IKeyring keyring = mpl.CreateAwsKmsMultiKeyring(CreateAwsKmsMultiKeyringInput.builder()
        .generator(keyArn1)
        .kmsKeyIds(Collections.singletonList(keyArn2))
        .clientSupplier(supplier)
        .build());
    // @end
    return keyring;
  }

  private static byte[] pem(String type, byte[] der) {
    String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
    return ("-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n")
        .getBytes(StandardCharsets.UTF_8);
  }
}
