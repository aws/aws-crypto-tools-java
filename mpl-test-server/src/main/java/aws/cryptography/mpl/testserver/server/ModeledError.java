package aws.cryptography.mpl.testserver.server;

/** One of the two modeled TestServer errors, carrying its rpcv2Cbor shape id. */
final class ModeledError extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private static final String NAMESPACE = "aws.cryptography.mpl.testserver#";

  private final String shapeName;

  private ModeledError(String shapeName, String message) {
    super(message);
    this.shapeName = shapeName;
  }

  /** A framework-side failure: bad request, unknown operation, bad handle, or a value the native API cannot take. */
  static ModeledError generic(String message) {
    return new ModeledError("GenericServerError", message);
  }

  /** A failure the MPL raised. */
  static ModeledError mpl(String message) {
    return new ModeledError("MPLClientError", message);
  }

  String typeId() {
    return NAMESPACE + shapeName;
  }
}
