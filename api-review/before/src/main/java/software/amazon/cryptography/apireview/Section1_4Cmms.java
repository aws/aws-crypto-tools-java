// Section 1.4 of the API review doc: CMMs
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import java.util.Arrays;
import java.util.Map;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.CreateRequiredEncryptionContextCMMInput;

final class Section1_4Cmms {
  private Section1_4Cmms() {}

  // 1.4: The default CMM is created from a keyring
  static byte[] defaultCmm(MaterialProviders mpl, AwsCrypto crypto, IKeyring keyring, byte[] plaintext,
      Map<String, String> encryptionContext) {
    // @card 13-default
    ICryptographicMaterialsManager cmm = mpl.CreateDefaultCryptographicMaterialsManager(
        CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build());
    byte[] ciphertext = crypto.encryptData(cmm, plaintext, encryptionContext).getResult();
    // @end
    return ciphertext;
  }

  // 1.4: The required encryption context CMM builds itself
  static byte[] requiredCmm(MaterialProviders mpl, AwsCrypto crypto, ICryptographicMaterialsManager cmm,
      byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 13-required
    ICryptographicMaterialsManager requiredCmm = mpl.CreateRequiredEncryptionContextCMM(
        CreateRequiredEncryptionContextCMMInput.builder()
            .underlyingCMM(cmm)
            .requiredEncryptionContextKeys(Arrays.asList("tenant", "purpose"))
            .build());
    byte[] ciphertext = crypto.encryptData(requiredCmm, plaintext, encryptionContext).getResult();
    // @end
    return ciphertext;
  }

  // 1.4: A CMM goes on the ESDK request
  static byte[] cmmOnRequest(AwsCrypto crypto, ICryptographicMaterialsManager requiredCmm, byte[] plaintext,
      Map<String, String> encryptionContext, Map<String, String> requiredPairs) {
    // @card 13-onrequest
    byte[] ciphertext = crypto.encryptData(requiredCmm, plaintext, encryptionContext).getResult();
    // The required pairs are not stored in the message, so decrypt supplies them again.
    CryptoResult<byte[], ?> decrypted = crypto.decryptData(requiredCmm, ciphertext, requiredPairs);
    byte[] roundTrip = decrypted.getResult();
    // @end
    return roundTrip;
  }
}
