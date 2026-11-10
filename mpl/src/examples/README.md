# Native MPL usage examples

These examples show how the AWS Encryption SDK (ESDK) and its customers use the native Material Providers Library.

- The ESDK calls (`EsdkClient`, `encrypt`, `decrypt`) follow the proposed ESDK 4.0 API, which is not released.
- ESDK calls throw the ESDK's own exceptions (`EsdkException` and its subclasses, such as `EsdkValidationException`). An MPL failure is the cause, so the kind is the same.
- The examples that call AWS take their KMS keys and key store from arguments; each class comment lists them.
- The build does not compile these files yet. It will compile them once the APIs they use exist.
