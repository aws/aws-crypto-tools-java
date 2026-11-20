package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.clientsupplier;

import java.util.Map;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;

/**
 * Example class demonstrating an implementation of a custom client supplier. This particular
 * implementation will create KMS clients with different IAM roles, depending on the region passed.
 *
 * <p>It owns the STS client it uses to assume those roles, so close the supplier once no keyring
 * that uses it will run again.
 */
public class RegionalRoleClientSupplier
  implements ClientSupplier, AutoCloseable {

  // The IAM role to assume for each Region, keyed by Region ID. These are placeholder roles in the
  // documentation example account 111122223333; replace them with roles in your account that can
  // use the KMS keys in each Region. In your own code, this map might be hardcoded, or come from an
  // external source, e.g. environment variables or AWS AppConfig.
  private static final Map<String, String> REGION_IAM_ROLES = Map.of(
    Region.US_EAST_1.id(),
    "arn:aws:iam::111122223333:role/ExampleKmsRole-us-east-1",
    Region.EU_WEST_1.id(),
    "arn:aws:iam::111122223333:role/ExampleKmsRole-eu-west-1"
  );

  private final StsClient stsClient;

  public RegionalRoleClientSupplier() {
    this.stsClient = StsClient.create();
  }

  @Override
  public KmsClient getClient(String region) {
    String roleArn = REGION_IAM_ROLES.get(region);
    if (roleArn == null) {
      throw new IllegalArgumentException(
        "No IAM role configured for region " + region
      );
    }
    Credentials credentials = stsClient
      .assumeRole(
        AssumeRoleRequest
          .builder()
          .roleArn(roleArn)
          .durationSeconds(900) // 15 minutes is the minimum value
          .roleSessionName("DbEsdkClientSupplierExampleSession")
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

  @Override
  public void close() {
    stsClient.close();
  }
}
