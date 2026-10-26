// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EsdkCommitmentPolicy;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.oldapi.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.DBECommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKCommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsInput;

/** Test adapter: materials manager requests between the old models and the native core, after the boundary checks. */
public final class Requests {

  private Requests() {}

  public static GetEncryptionMaterialsRequest request(GetEncryptionMaterialsInput input) {
    Boundary.encryptionContext(input.encryptionContext());
    List<String> required = Boundary.optional(input.requiredEncryptionContextKeys());
    if (required != null) {
      Boundary.utf8List(required);
    }
    GetEncryptionMaterialsRequest.Builder builder = GetEncryptionMaterialsRequest
      .builder()
      .encryptionContext(EncryptionContext.copyOf(input.encryptionContext()))
      .commitmentPolicy(Convert.policy(input.commitmentPolicy()));
    if (input.algorithmSuiteId() != null) {
      builder.algorithmSuiteId(Convert.suite(input.algorithmSuiteId()));
    }
    if (input.maxPlaintextLength() != null) {
      builder.maxPlaintextLength(input.maxPlaintextLength());
    }
    if (required != null) {
      builder.requiredEncryptionContextKeys(required);
    }
    return builder.build();
  }

  public static DecryptMaterialsRequest request(DecryptMaterialsInput input) {
    Boundary.encryptionContext(input.encryptionContext());
    List<software.amazon.cryptography.materialproviders.EncryptedDataKey> edks = new ArrayList<>();
    for (EncryptedDataKey edk : input.encryptedDataKeys()) {
      edks.add(Convert.edk(Boundary.encryptedDataKey(edk)));
    }
    DecryptMaterialsRequest.Builder builder = DecryptMaterialsRequest
      .builder()
      .algorithmSuiteId(Convert.suite(input.algorithmSuiteId()))
      .commitmentPolicy(Convert.policy(input.commitmentPolicy()))
      .encryptedDataKeys(edks)
      .encryptionContext(EncryptionContext.copyOf(input.encryptionContext()));
    if (Boundary.optional(input.reproducedEncryptionContext()) != null) {
      Boundary.encryptionContext(input.reproducedEncryptionContext());
      builder.reproducedEncryptionContext(EncryptionContext.copyOf(input.reproducedEncryptionContext()));
    }
    return builder.build();
  }

  public static GetEncryptionMaterialsInput input(GetEncryptionMaterialsRequest request) {
    GetEncryptionMaterialsInput.Builder builder = GetEncryptionMaterialsInput
      .builder()
      .encryptionContext(new HashMap<>(request.encryptionContext()))
      .commitmentPolicy(policy(request.commitmentPolicy()))
      .requiredEncryptionContextKeys(new ArrayList<>(request.requiredEncryptionContextKeys()));
    request.algorithmSuiteId().ifPresent(suite -> builder.algorithmSuiteId(Convert.id(suite)));
    if (request.maxPlaintextLength().isPresent()) {
      builder.maxPlaintextLength(request.maxPlaintextLength().getAsLong());
    }
    return builder.build();
  }

  public static DecryptMaterialsInput input(DecryptMaterialsRequest request) {
    List<EncryptedDataKey> edks = new ArrayList<>();
    for (software.amazon.cryptography.materialproviders.EncryptedDataKey edk : request.encryptedDataKeys()) {
      edks.add(Convert.edk(edk));
    }
    return DecryptMaterialsInput
      .builder()
      .algorithmSuiteId(Convert.id(request.algorithmSuiteId()))
      .commitmentPolicy(policy(request.commitmentPolicy()))
      .encryptedDataKeys(edks)
      .encryptionContext(new HashMap<>(request.encryptionContext()))
      .reproducedEncryptionContext(request.reproducedEncryptionContext().map(HashMap::new).orElse(null))
      .build();
  }

  private static CommitmentPolicy policy(software.amazon.cryptography.materialproviders.CommitmentPolicy policy) {
    return policy instanceof EsdkCommitmentPolicy
      ? CommitmentPolicy.builder().ESDK(ESDKCommitmentPolicy.valueOf(((EsdkCommitmentPolicy) policy).name())).build()
      : CommitmentPolicy.builder().DBE(DBECommitmentPolicy.valueOf(((Enum<?>) policy).name())).build();
  }
}
