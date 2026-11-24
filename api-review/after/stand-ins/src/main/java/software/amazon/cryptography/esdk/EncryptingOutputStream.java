// SCRATCH STUB: same public signatures as the sketch; streaming is not used by these examples.
package software.amazon.cryptography.esdk;

import java.io.IOException;
import java.io.OutputStream;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.EncryptionContext;

public final class EncryptingOutputStream extends OutputStream {
  private EncryptingOutputStream() {}
  @Override public void write(final int b) throws IOException { throw new UnsupportedOperationException(); }
  public EncryptionContext encryptionContext() { throw new UnsupportedOperationException(); }
  public EsdkAlgorithmSuite algorithmSuite() { throw new UnsupportedOperationException(); }
}
