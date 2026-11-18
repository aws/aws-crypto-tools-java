plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.spotless.gradle)
    implementation(libs.errorprone.gradle)
    implementation(libs.pitest.gradle)
    implementation(libs.japicmp.gradle)
}
