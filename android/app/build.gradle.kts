import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.github.jurybu.catcloud"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.jurybu.catcloud"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += "arm64-v8a"
        }

        androidResources {
            localeFilters += listOf("zh", "en")
        }
    }

    buildFeatures {
        compose = true
        aidl = true
        buildConfig = true
    }

    val keystorePath = System.getenv("KEYSTORE_PATH")?.trim().orEmpty()
    val keystorePassword = System.getenv("KEYSTORE_PASSWORD")?.trim().orEmpty()
    val keyAliasEnv = System.getenv("KEY_ALIAS")?.trim().orEmpty()
    val keyPasswordEnv = System.getenv("KEY_PASSWORD")?.trim().orEmpty()
    val hasReleaseSigning = keystorePath.isNotEmpty() &&
        keystorePassword.isNotEmpty() &&
        keyAliasEnv.isNotEmpty() &&
        keyPasswordEnv.isNotEmpty() &&
        File(keystorePath).isFile

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = File(keystorePath)
                storePassword = keystorePassword
                keyAlias = keyAliasEnv
                keyPassword = keyPasswordEnv
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            isShrinkResources = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = if (hasReleaseSigning) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
        resources {
            excludes += listOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "DebugProbesKt.bin"
            )
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

configurations.configureEach {
    exclude(group = "androidx.appcompat", module = "appcompat")
    exclude(group = "com.google.android.material", module = "material")
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.02.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.profileinstaller:profileinstaller:1.4.1")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.yaml:snakeyaml:2.3")

    // Lightweight CameraX (intentionally omits camera-view) + offline ZXing core
    implementation("androidx.camera:camera-core:1.4.1")
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("com.google.guava:listenablefuture:1.0")
    implementation("com.google.zxing:core:3.5.4")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}
