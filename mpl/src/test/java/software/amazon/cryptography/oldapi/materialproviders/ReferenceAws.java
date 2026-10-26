// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;

/**
 * AWS clients for differential tests: a native client, labeled {@link #NATIVE}, whose reference-side twin,
 * labeled {@link #REFERENCE}, talks to the same {@link FakeAws} endpoint.
 * Put the native client in a native model; {@link ReferenceMpl#call} passes the twin to the reference MPL.
 * Then {@code fake.requests(NATIVE)} and {@code fake.requests(REFERENCE)} hold what each side sent.
 */
final class ReferenceAws {

  static final String NATIVE = "native";
  static final String REFERENCE = "reference";

  private ReferenceAws() {}

  static KmsClient kms(FakeAws fake, String region) {
    KmsClient client = fake.kmsClient(NATIVE, region);
    ReferenceMpl.registerTwin(client, fake.kmsClient(ReferenceMpl.loader(), REFERENCE, region));
    return client;
  }

  static DynamoDbClient dynamoDb(FakeAws fake, String region) {
    DynamoDbClient client = fake.dynamoDbClient(NATIVE, region);
    ReferenceMpl.registerTwin(client, fake.dynamoDbClient(ReferenceMpl.loader(), REFERENCE, region));
    return client;
  }
}
