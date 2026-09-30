rootProject.name = "dbesdk-dynamodb-item-encryptor"

// DynamoToStruct (item ↔ terminal-map) lives in the dynamodb-encryption build, which
// itself composite-includes structured-encryption (Terminal, CryptoAction).
includeBuild("../dynamodb-encryption")
