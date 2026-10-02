plugins {
    id("com.android.application")
}

android {
    namespace = "dev.altru.safetyprotocol.runtime"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        applicationId = "dev.altru.safetyprotocol.runtime"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.3-runtime-smoke"
    }

    buildFeatures {
        buildConfig = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":android-adapter"))
}
