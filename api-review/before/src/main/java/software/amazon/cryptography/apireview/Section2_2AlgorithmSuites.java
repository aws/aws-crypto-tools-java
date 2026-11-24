// Section 2.2 of the API review doc: Algorithm suites and commitment policies
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.nio.ByteBuffer;
import java.util.Map;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteInfo;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.ESDKCommitmentPolicy;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.ValidateCommitmentPolicyOnEncryptInput;

final class Section2_2AlgorithmSuites {
  private Section2_2AlgorithmSuites() {}

  // 2.2: One suite enum per message format
  static GetEncryptionMaterialsInput suiteEnum(Map<String, String> encryptionContext) {
    // @card 22-enum
    AlgorithmSuiteId suite = AlgorithmSuiteId.builder()
        .ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
        .build();
    GetEncryptionMaterialsInput input = GetEncryptionMaterialsInput.builder()
        .encryptionContext(encryptionContext)
        .commitmentPolicy(CommitmentPolicy.builder().ESDK(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).build())
        .algorithmSuiteId(suite)
        .build();
    // @end
    return input;
  }

  // 2.2: Suite properties are methods, and lookup is per format
  static int suiteProperties(MaterialProviders mpl, byte[] suiteId) {
    // @card 22-props
    AlgorithmSuiteInfo suite = mpl.GetAlgorithmSuiteInfo(ByteBuffer.wrap(suiteId));
    boolean signing = suite.signature().ECDSA() != null;
    boolean committing = suite.commitment().HKDF() != null;
    int dataKeyLength = suite.kdf().HKDF() != null
        ? suite.kdf().HKDF().inputKeyLength()
        : suite.encrypt().AES_GCM().keyLength();
    // @end
    return signing && committing ? dataKeyLength : 0;
  }

  // 2.2: Commitment policies answer questions
  static boolean policy(MaterialProviders mpl, AlgorithmSuiteId suite) {
    // @card 22-policy
    CommitmentPolicy policy = CommitmentPolicy.builder()
        .ESDK(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
        .build();
    try {
      mpl.ValidateCommitmentPolicyOnEncrypt(ValidateCommitmentPolicyOnEncryptInput.builder()
          .algorithm(suite).commitmentPolicy(policy).build());
      return true;
    } catch (AwsCryptographicMaterialProvidersException e) {
      return false;
    }
    // @end
  }
}
