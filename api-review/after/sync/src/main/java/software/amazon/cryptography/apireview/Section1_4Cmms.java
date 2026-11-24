// Section 1.4 of the API review doc: CMMs
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.Map;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.RequiredEncryptionContextCryptographicMaterialsManager;

final class Section1_4Cmms {
  private Section1_4Cmms() {}

  // 1.4: The default CMM is created from a keyring
  static byte[] defaultCmm(EsdkClient esdk, Keyring keyring, byte[] plaintext,
      Map<String, String> encryptionContext) {
    // @card 13-default
    DefaultCryptographicMaterialsManager cmm = DefaultCryptographicMaterialsManager.create(keyring);
    byte[] ciphertext = esdk.encrypt(b -> b
        .plaintext(plaintext).materialsManager(cmm).encryptionContext(encryptionContext)).ciphertext();
    // @end
    return ciphertext;
  }

  // 1.4: The required encryption context CMM builds itself
  static byte[] requiredCmm(EsdkClient esdk, CryptographicMaterialsManager cmm, byte[] plaintext,
      Map<String, String> encryptionContext) {
    // @card 13-required
    RequiredEncryptionContextCryptographicMaterialsManager requiredCmm =
        RequiredEncryptionContextCryptographicMaterialsManager.builder()
            .underlyingCmm(cmm)
            .requiredEncryptionContextKeys("tenant", "purpose")
            .build();
    byte[] ciphertext = esdk.encrypt(b -> b
        .plaintext(plaintext).materialsManager(requiredCmm).encryptionContext(encryptionContext)).ciphertext();
    // @end
    return ciphertext;
  }

  // 1.4: A CMM goes on the ESDK request
  static byte[] cmmOnRequest(EsdkClient esdk, CryptographicMaterialsManager requiredCmm, byte[] plaintext,
      Map<String, String> encryptionContext, Map<String, String> requiredPairs) {
    // @card 13-onrequest
    byte[] ciphertext = esdk.encrypt(b -> b
        .plaintext(plaintext).materialsManager(requiredCmm).encryptionContext(encryptionContext)).ciphertext();
    // The required pairs are not stored in the message, so decrypt supplies them again.
    DecryptResponse decrypted = esdk.decrypt(b -> b
        .ciphertext(ciphertext).materialsManager(requiredCmm).encryptionContext(requiredPairs));
    byte[] roundTrip = decrypted.plaintext();
    // @end
    return roundTrip;
  }
}
