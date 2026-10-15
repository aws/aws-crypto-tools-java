// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.vectors;

/** A manifest the runner cannot parse or a key description it cannot build, with the Dafny runner's message. */
final class VectorException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  VectorException(String message) {
    super(message);
  }
}
