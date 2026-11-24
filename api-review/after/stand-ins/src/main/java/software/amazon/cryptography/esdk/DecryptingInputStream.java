// SCRATCH STUB: same public signatures as the sketch; streaming is not used by these examples.
package software.amazon.cryptography.esdk;

import java.io.IOException;
import java.io.InputStream;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.EncryptionContext;

public final class DecryptingInputStream extends InputStream {
  private DecryptingInputStream() {}
  @Override public int read() throws IOException { throw new UnsupportedOperationException(); }
  public EncryptionContext encryptionContext() throws IOException { throw new UnsupportedOperationException(); }
  public EsdkAlgorithmSuite algorithmSuite() throws IOException { throw new UnsupportedOperationException(); }
}
