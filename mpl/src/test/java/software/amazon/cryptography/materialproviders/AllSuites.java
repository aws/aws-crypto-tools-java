// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** Test helper: both formats' suites, for vectors and old-API calls that name a suite of either format. */
public final class AllSuites {

  private AllSuites() {}

  /** The ESDK suites, then the DBE suites. */
  public static List<AlgorithmSuite> all() {
    List<AlgorithmSuite> all = new ArrayList<>(Arrays.<AlgorithmSuite>asList(EsdkAlgorithmSuite.values()));
    all.addAll(Arrays.asList(DbeAlgorithmSuite.values()));
    return Collections.unmodifiableList(all);
  }

  /** The suite of either format with this 2-byte id; the formats' ids do not overlap. */
  public static AlgorithmSuite fromBinaryId(byte[] binaryId) {
    try {
      return EsdkAlgorithmSuite.fromBinaryId(binaryId);
    } catch (ValidationException e) {
      return DbeAlgorithmSuite.fromBinaryId(binaryId);
    }
  }
}
