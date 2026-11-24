package spike;

import java.util.List;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;

/** The sync keyring's encrypt as a thin shell around KmsSteps, as AwsKmsAsyncKeyring is the async one. */
final class SyncKmsShell {
  private final String kmsKeyId;
  private final KmsClient kmsClient;
  private final List<String> grantTokens;

  SyncKmsShell(String kmsKeyId, KmsClient kmsClient, List<String> grantTokens) {
    this.kmsKeyId = kmsKeyId;
    this.kmsClient = kmsClient;
    this.grantTokens = grantTokens;
  }

  OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials m = request.materials();
    if (!m.plaintextDataKey().isPresent()) {
      return OnEncryptResponse.builder()
          .materials(KmsSteps.afterGenerate(kmsKeyId, m, kmsClient.generateDataKey(KmsSteps.generateDataKey(kmsKeyId, m, grantTokens))))
          .build();
    }
    return OnEncryptResponse.builder()
        .materials(KmsSteps.afterEncrypt(m, kmsClient.encrypt(KmsSteps.encrypt(kmsKeyId, m, grantTokens))))
        .build();
  }
}
