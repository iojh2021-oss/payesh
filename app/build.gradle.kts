plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// every CI build gets a higher version number, so Android always treats it as an upgrade
val runNo = System.getenv("GITHUB_RUN_NUMBER")?.toIntOrNull() ?: 1

android {
    namespace = "app.payesh"
    compileSdk = 34

    defaultConfig {
        applicationId = "app.payesh"
        minSdk = 29
        targetSdk = 34
        versionCode = runNo
        versionName = "1.0.$runNo"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a") }
    }
    // A FIXED signing key (from GitHub secrets). Without it every CI run invents a new random debug key and
    // Android refuses to install the new APK over the old one.
    signingConfigs {
        val ksPath = System.getenv("PAYESH_KEYSTORE")
        if (ksPath != null && file(ksPath).exists()) {
            getByName("debug") {
                storeFile = file(ksPath)
                storePassword = System.getenv("PAYESH_KEYSTORE_PASSWORD")
                keyAlias = "payesh"
                keyPassword = System.getenv("PAYESH_KEYSTORE_PASSWORD")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.conscrypt:conscrypt-android:2.7.0") // bundled BoringSSL TLS with hybrid post-quantum key exchange
}
