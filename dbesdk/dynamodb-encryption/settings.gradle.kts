rootProject.name = "dbesdk-dynamodb-encryption"

// The native StructuredEncryption module supplies the Terminal (value + 2-byte
// type id) that DynamoToStruct produces and consumes.
includeBuild("../structured-encryption")
