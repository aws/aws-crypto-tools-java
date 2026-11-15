// One Gradle wrapper for the repository. Each library is its own build, included here,
// so it keeps its own settings, toolchain, and dependencies.
rootProject.name = "aws-crypto-tools-java"

includeBuild("mpl")
includeBuild("canary")
