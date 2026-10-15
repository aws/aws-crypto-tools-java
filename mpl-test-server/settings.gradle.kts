// The native Java Language_Server for the cross-language MPL TestServer.
rootProject.name = "mpl-test-server-native-java"

// The native MPL is a sibling Gradle build in this repository; including it makes the
// server run against this working tree's library rather than a published artifact.
includeBuild("../mpl")
