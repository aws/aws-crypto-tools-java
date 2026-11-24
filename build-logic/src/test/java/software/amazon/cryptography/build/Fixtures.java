package software.amazon.cryptography.build;

import java.util.Collection;

/** A tiny library for ApiSurfaceTest to discover. */
final class Fixtures {

  public interface Keyring {}

  public interface CryptographicMaterialsManager {}

  public static final class FakeKeyring implements Keyring {
    private FakeKeyring() {}

    public static Builder builder() {
      return new Builder();
    }

    public static FakeKeyring fromKeyName(String keyName) {
      return builder().keyName(keyName).build();
    }

    // Not a constructor: returns neither the keyring nor its builder.
    public static String defaultKeyName() {
      return "key";
    }

    public static final class Builder {
      public Builder keyName(String keyName) {
        return this;
      }

      public Builder wrappingKey(String wrappingKey) {
        return this;
      }

      public Builder wrappingKey(byte[] wrappingKey) {
        return this;
      }

      public Builder grantTokens(Collection<String> grantTokens) {
        return this;
      }

      public Builder grantTokens(String... grantTokens) {
        return this;
      }

      // Not a setter: returns the keyring.
      public FakeKeyring build() {
        return new FakeKeyring();
      }
    }
  }

  public abstract static class BaseCmm implements CryptographicMaterialsManager {}

  public static final class FakeCmm extends BaseCmm {
    public FakeCmm(Keyring keyring) {}
  }

  public static final class NotAKeyring {
    private NotAKeyring() {}

    public static NotAKeyring create() {
      return new NotAKeyring();
    }
  }

  public static final class EsdkClient {
    private EsdkClient() {}

    public static Builder builder() {
      return new Builder();
    }

    public byte[] encrypt(EncryptInput input) {
      return new byte[0];
    }

    public int maxEncryptedDataKeys() {
      return 0;
    }

    public static final class Builder {
      public Builder maxEncryptedDataKeys(int max) {
        return this;
      }

      public EsdkClient build() {
        return new EsdkClient();
      }
    }
  }

  public static final class EncryptInput {
    private EncryptInput() {}

    public static Builder builder() {
      return new Builder();
    }

    public static final class Builder {
      public Builder plaintext(byte[] plaintext) {
        return this;
      }

      public EncryptInput build() {
        return new EncryptInput();
      }
    }
  }

  private Fixtures() {}
}
