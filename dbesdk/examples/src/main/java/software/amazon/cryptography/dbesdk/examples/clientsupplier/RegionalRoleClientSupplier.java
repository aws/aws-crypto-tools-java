package software.amazon.cryptography.dbesdk.examples.clientsupplier;

import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;

/*
 Example class demonstrating an implementation of a custom client supplier. This particular
 implementation will create KMS clients with different IAM roles, depending on the region passed.
*/
public class RegionalRoleClientSupplier implements ClientSupplier {

  private final StsClient stsClient;
  private final RegionalRoleClientSupplierConfig config;

  public RegionalRoleClientSupplier() {
    stsClient = StsClient.create();
    config = new RegionalRoleClientSupplierConfig();
  }

  @Override
  public KmsClient getClient(String region) {
    final String roleArn = config.regionIamRoleMap().get(region);
    if (roleArn == null) {
      throw new IllegalArgumentException(
        "No IAM role configured for region " + region
      );
    }
    final Credentials credentials = stsClient
      .assumeRole(
        AssumeRoleRequest
          .builder()
          .roleArn(roleArn)
          .durationSeconds(900) // 15 minutes is the minimum value
          .roleSessionName("Java-Client-Supplier-Example-Session")
          .build()
      )
      .credentials();

    return KmsClient
      .builder()
      .credentialsProvider(
        StaticCredentialsProvider.create(
          AwsSessionCredentials.create(
            credentials.accessKeyId(),
            credentials.secretAccessKey(),
            credentials.sessionToken()
          )
        )
      )
      .region(Region.of(region))
      .build();
  }
}
