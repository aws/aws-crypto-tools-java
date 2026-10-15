// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.cache;

/** The clock resolution a storm-tracking cache computes with. More constants may be added; a {@code switch} needs a {@code default} branch. */
public enum TimeUnits {
  SECONDS,
  MILLISECONDS,
}
