plugins {
    id("com.android.library")
}

val rustHostLibrary = rootProject.layout.projectDirectory.file("target/debug/libsafetyprotocol.so")
val generatedRustJni = project.layout.projectDirectory.dir("src/main/jniLibs")

val buildRustHost = tasks.register<Exec>("buildRustHost") {
    workingDir(rootProject.projectDir)
    commandLine("cargo", "build")
}

val buildRustAndroid = tasks.register<Exec>("buildRustAndroid") {
    workingDir(rootProject.projectDir)
    environment("ANDROID_SDK_ROOT", System.getenv("ANDROID_SDK_ROOT") ?: "${System.getProperty("user.home")}/.local/android-sdk")
    commandLine("bash", "scripts/build-android-native.sh", generatedRustJni.asFile.absolutePath)
}

android {
    namespace = "dev.altru.safetyprotocol.android"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }

    buildFeatures {
        buildConfig = false
    }

    testOptions {
        unitTests.isIncludeAndroidResources = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

tasks.withType<Test>().configureEach {
    dependsOn(buildRustHost)
    systemProperty("safetyprotocol.native.path", rustHostLibrary.asFile.absolutePath)
}

tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(buildRustAndroid)
}
