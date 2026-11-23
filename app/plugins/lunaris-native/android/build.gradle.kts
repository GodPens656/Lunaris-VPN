plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.sever.vpn"
    compileSdk = 36
    defaultConfig {
        minSdk = 26
        ndk { abiFilters += listOf("arm64-v8a") }
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions { jvmTarget = "1.8" }
    packaging { jniLibs { useLegacyPackaging = true; keepDebugSymbols += setOf("**/libxray.so", "**/liblunaris_mihomo.so") } }
}

rootProject.allprojects {
    repositories { flatDir { dirs(project(":tauri-plugin-lunaris-native").file("libs")) } }
}

dependencies {
    implementation(project(":tauri-android"))
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation(mapOf("name" to "libbox", "ext" to "aar"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1")
}
