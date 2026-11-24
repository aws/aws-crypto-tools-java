// Section 2.2 of the API review doc: Algorithm suites and commitment policies
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.Map;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.EsdkCommitmentPolicy;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;

final class Section2_2AlgorithmSuites {
  private Section2_2AlgorithmSuites() {}

  // 2.2: One suite enum per message format
  static GetEncryptionMaterialsRequest suiteEnum(Map<String, String> encryptionContext) {
    // @card 22-enum
    EsdkAlgorithmSuite suite = EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
    GetEncryptionMaterialsRequest request = GetEncryptionMaterialsRequest.builder()
        .encryptionContext(encryptionContext)
        .commitmentPolicy(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
        .algorithmSuite(suite)
        .build();
    // @end
    return request;
  }

  // 2.2: Suite properties are methods, and lookup is per format
  static int suiteProperties(byte[] suiteId) {
    // @card 22-props
    EsdkAlgorithmSuite suite = EsdkAlgorithmSuite.fromBinaryId(suiteId);
    boolean signing = suite.isSigning();
    boolean committing = suite.isCommitting();
    int dataKeyLength = suite.dataKeyLength();
    // @end
    return signing && committing ? dataKeyLength : 0;
  }

  // 2.2: Commitment policies answer questions
  static boolean policy(EsdkAlgorithmSuite suite) {
    // @card 22-policy
    EsdkCommitmentPolicy policy = EsdkCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT;
    boolean allowed = policy.allowsEncrypt(suite);
    boolean readable = policy.allowsDecrypt(suite);
    EsdkAlgorithmSuite defaultSuite = policy.defaultSuite();
    // @end
    return allowed && readable && defaultSuite.isCommitting();
  }
}
