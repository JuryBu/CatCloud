# Keep JNI bridge & callback signatures intact for libmihomo.so
-keep class io.github.jurybu.catcloud.core.MihomoBridge {
    *;
}
-keep interface io.github.jurybu.catcloud.core.ProtectCallback {
    public boolean protect(int);
}
-keep class * implements io.github.jurybu.catcloud.core.ProtectCallback {
    public boolean protect(int);
}

# Keep AIDL IPC interfaces and Binder stubs
-keep class io.github.jurybu.catcloud.ipc.** {
    *;
}

# Keep Android service/receiver/activity components referenced in manifest
-keep public class io.github.jurybu.catcloud.CatCloudApp
-keep public class io.github.jurybu.catcloud.MainActivity
-keep public class io.github.jurybu.catcloud.vpn.CatCloudVpnService
-keep public class io.github.jurybu.catcloud.vpn.CatCloudTileService
-keep public class io.github.jurybu.catcloud.vpn.BootReceiver

# SnakeYAML reflective helpers & optional Java desktop classes absent on Android
-keep class org.yaml.snakeyaml.** { *; }
-dontwarn org.yaml.snakeyaml.**
-dontwarn java.beans.**

# OkHttp optional platform providers
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# CameraX & Guava annotations
-dontwarn com.google.errorprone.annotations.**
-dontwarn com.google.j2objc.annotations.**
-dontwarn org.checkerframework.**
