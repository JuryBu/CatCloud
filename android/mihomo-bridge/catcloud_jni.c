//go:build android && cmfa

#define CATCLOUD_JNI_IMPL
#include "catcloud_jni.h"

#include <jni.h>
#include <pthread.h>
#include <stdlib.h>

static pthread_mutex_t g_jni_lock = PTHREAD_MUTEX_INITIALIZER;
static JavaVM *g_jvm = NULL;
static jobject g_protect_cb = NULL;
static jmethodID g_protect_method = NULL;

static pthread_key_t g_detach_key;
static pthread_once_t g_detach_key_once = PTHREAD_ONCE_INIT;
static int g_detach_key_ready = 0;

static void catcloud_detach_thread_dtor(void *arg) {
    JavaVM *vm = (JavaVM *)arg;
    if (vm != NULL) {
        (*vm)->DetachCurrentThread(vm);
    }
}

static void catcloud_create_detach_key(void) {
    if (pthread_key_create(&g_detach_key, catcloud_detach_thread_dtor) == 0) {
        g_detach_key_ready = 1;
    }
}

static jstring catcloud_take_go_result(JNIEnv *env, char *go_err) {
    if (go_err == NULL) {
        return (*env)->NewStringUTF(env, "");
    }
    jstring result = (*env)->NewStringUTF(env, go_err);
    free(go_err);
    return result;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    pthread_mutex_lock(&g_jni_lock);
    g_jvm = vm;
    pthread_mutex_unlock(&g_jni_lock);
    pthread_once(&g_detach_key_once, catcloud_create_detach_key);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)reserved;
    jobject old_cb = NULL;
    pthread_mutex_lock(&g_jni_lock);
    old_cb = g_protect_cb;
    g_protect_cb = NULL;
    g_protect_method = NULL;
    g_jvm = NULL;
    pthread_mutex_unlock(&g_jni_lock);

    if (old_cb != NULL && vm != NULL) {
        JNIEnv *env = NULL;
        if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK && env != NULL) {
            (*env)->DeleteGlobalRef(env, old_cb);
        }
    }
}

/*
 * Thread-safe bridge from Go dialer goroutines back into Android VpnService.protect(fd).
 * Automatically attaches Go OS threads as daemon threads and registers a pthread TLS
 * destructor so ART detaches them cleanly upon thread exit without SIGABRT.
 */
int catcloud_protect_socket(int fd) {
    if (fd < 0) {
        return 0;
    }

    JavaVM *vm = NULL;
    pthread_mutex_lock(&g_jni_lock);
    vm = g_jvm;
    pthread_mutex_unlock(&g_jni_lock);
    if (vm == NULL) {
        return 0;
    }

    JNIEnv *env = NULL;
    int detach_after_call = 0;
    jint env_status = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    if (env_status == JNI_EDETACHED) {
        JavaVMAttachArgs attach_args;
        attach_args.version = JNI_VERSION_1_6;
        attach_args.name = "catcloud-mihomo-dialer";
        attach_args.group = NULL;
        if ((*vm)->AttachCurrentThreadAsDaemon(vm, &env, &attach_args) != JNI_OK || env == NULL) {
            return 0;
        }
        pthread_once(&g_detach_key_once, catcloud_create_detach_key);
        if (g_detach_key_ready) {
            if (pthread_setspecific(g_detach_key, (void *)vm) != 0) {
                detach_after_call = 1;
            }
        } else {
            detach_after_call = 1;
        }
    } else if (env_status != JNI_OK || env == NULL) {
        return 0;
    }

    /* Take a LocalRef under lock so concurrent nativeInit cannot UAF g_protect_cb. */
    jobject local_cb = NULL;
    jmethodID method_id = NULL;
    pthread_mutex_lock(&g_jni_lock);
    if (g_protect_cb != NULL && g_protect_method != NULL) {
        local_cb = (*env)->NewLocalRef(env, g_protect_cb);
        method_id = g_protect_method;
    }
    pthread_mutex_unlock(&g_jni_lock);

    if (local_cb == NULL || method_id == NULL) {
        if (local_cb != NULL) {
            (*env)->DeleteLocalRef(env, local_cb);
        }
        if (detach_after_call) {
            (*vm)->DetachCurrentThread(vm);
        }
        return 0;
    }

    jboolean protected_ok = (*env)->CallBooleanMethod(env, local_cb, method_id, (jint)fd);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        protected_ok = JNI_FALSE;
    }

    (*env)->DeleteLocalRef(env, local_cb);
    if (detach_after_call) {
        (*vm)->DetachCurrentThread(vm);
    }
    return (protected_ok == JNI_TRUE) ? 1 : 0;
}

JNIEXPORT jstring JNICALL
Java_io_github_jurybu_catcloud_core_MihomoBridge_nativeInit(
    JNIEnv *env,
    jobject thiz,
    jstring homeDir,
    jobject protectCb
) {
    (void)thiz;
    if (homeDir == NULL) {
        return (*env)->NewStringUTF(env, "homeDir must not be null");
    }
    if (protectCb == NULL) {
        return (*env)->NewStringUTF(env, "protectCb must not be null");
    }

    jclass cb_class = (*env)->GetObjectClass(env, protectCb);
    if (cb_class == NULL) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        return (*env)->NewStringUTF(env, "failed to resolve ProtectCallback class");
    }

    jmethodID protect_mid = (*env)->GetMethodID(env, cb_class, "protect", "(I)Z");
    (*env)->DeleteLocalRef(env, cb_class);
    if ((*env)->ExceptionCheck(env) || protect_mid == NULL) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        return (*env)->NewStringUTF(env, "ProtectCallback missing protect(I)Z method");
    }

    jobject new_global_cb = (*env)->NewGlobalRef(env, protectCb);
    if (new_global_cb == NULL) {
        return (*env)->NewStringUTF(env, "NewGlobalRef failed for protectCb");
    }

    JavaVM *vm = NULL;
    (*env)->GetJavaVM(env, &vm);
    pthread_once(&g_detach_key_once, catcloud_create_detach_key);

    jobject old_global_cb = NULL;
    pthread_mutex_lock(&g_jni_lock);
    if (g_jvm == NULL && vm != NULL) {
        g_jvm = vm;
    }
    old_global_cb = g_protect_cb;
    g_protect_cb = new_global_cb;
    g_protect_method = protect_mid;
    pthread_mutex_unlock(&g_jni_lock);

    if (old_global_cb != NULL) {
        (*env)->DeleteGlobalRef(env, old_global_cb);
    }

    const char *home_utf = (*env)->GetStringUTFChars(env, homeDir, NULL);
    if (home_utf == NULL) {
        return (*env)->NewStringUTF(env, "GetStringUTFChars failed for homeDir");
    }
    char *go_err = catcloud_go_init((char *)home_utf);
    (*env)->ReleaseStringUTFChars(env, homeDir, home_utf);
    return catcloud_take_go_result(env, go_err);
}

JNIEXPORT void JNICALL
Java_io_github_jurybu_catcloud_core_MihomoBridge_nativeSetMemoryLimit(
    JNIEnv *env,
    jobject thiz,
    jlong limitBytes,
    jint gcPercent
) {
    (void)env;
    (void)thiz;
    catcloud_go_set_memory_limit((long long)limitBytes, (int)gcPercent);
}

JNIEXPORT jstring JNICALL
Java_io_github_jurybu_catcloud_core_MihomoBridge_nativePrepareConfig(
    JNIEnv *env,
    jobject thiz,
    jstring configYaml,
    jstring controllerAddr,
    jstring controllerSecret
) {
    (void)thiz;
    if (configYaml == NULL) {
        return (*env)->NewStringUTF(env, "configYaml must not be null");
    }
    if (controllerAddr == NULL) {
        return (*env)->NewStringUTF(env, "controllerAddr must not be null");
    }

    const char *yaml_utf = (*env)->GetStringUTFChars(env, configYaml, NULL);
    if (yaml_utf == NULL) {
        return (*env)->NewStringUTF(env, "GetStringUTFChars failed for configYaml");
    }
    const char *addr_utf = (*env)->GetStringUTFChars(env, controllerAddr, NULL);
    if (addr_utf == NULL) {
        (*env)->ReleaseStringUTFChars(env, configYaml, yaml_utf);
        return (*env)->NewStringUTF(env, "GetStringUTFChars failed for controllerAddr");
    }

    const char *secret_utf = NULL;
    if (controllerSecret != NULL) {
        secret_utf = (*env)->GetStringUTFChars(env, controllerSecret, NULL);
        if (secret_utf == NULL) {
            (*env)->ReleaseStringUTFChars(env, controllerAddr, addr_utf);
            (*env)->ReleaseStringUTFChars(env, configYaml, yaml_utf);
            return (*env)->NewStringUTF(env, "GetStringUTFChars failed for controllerSecret");
        }
    }

    char *go_err = catcloud_go_prepare_config(
        (char *)yaml_utf,
        (char *)addr_utf,
        (char *)(secret_utf != NULL ? secret_utf : "")
    );

    if (secret_utf != NULL) {
        (*env)->ReleaseStringUTFChars(env, controllerSecret, secret_utf);
    }
    (*env)->ReleaseStringUTFChars(env, controllerAddr, addr_utf);
    (*env)->ReleaseStringUTFChars(env, configYaml, yaml_utf);
    return catcloud_take_go_result(env, go_err);
}

JNIEXPORT jstring JNICALL
Java_io_github_jurybu_catcloud_core_MihomoBridge_nativeAttachTun(
    JNIEnv *env,
    jobject thiz,
    jint tunFd,
    jint mtu
) {
    (void)thiz;
    char *go_err = catcloud_go_attach_tun((int)tunFd, (int)mtu);
    return catcloud_take_go_result(env, go_err);
}

JNIEXPORT jstring JNICALL
Java_io_github_jurybu_catcloud_core_MihomoBridge_nativeReloadConfig(
    JNIEnv *env,
    jobject thiz,
    jstring configYaml
) {
    (void)thiz;
    if (configYaml == NULL) {
        return (*env)->NewStringUTF(env, "configYaml must not be null");
    }
    const char *yaml_utf = (*env)->GetStringUTFChars(env, configYaml, NULL);
    if (yaml_utf == NULL) {
        return (*env)->NewStringUTF(env, "GetStringUTFChars failed for configYaml");
    }
    char *go_err = catcloud_go_reload_config((char *)yaml_utf);
    (*env)->ReleaseStringUTFChars(env, configYaml, yaml_utf);
    return catcloud_take_go_result(env, go_err);
}

JNIEXPORT void JNICALL
Java_io_github_jurybu_catcloud_core_MihomoBridge_nativeStopTun(
    JNIEnv *env,
    jobject thiz
) {
    (void)env;
    (void)thiz;
    catcloud_go_stop_tun();
}

JNIEXPORT void JNICALL
Java_io_github_jurybu_catcloud_core_MihomoBridge_nativeUpdateSystemDns(
    JNIEnv *env,
    jobject thiz,
    jstring dnsCsv
) {
    (void)thiz;
    if (dnsCsv == NULL) {
        catcloud_go_update_system_dns((char *)"");
        return;
    }
    const char *dns_utf = (*env)->GetStringUTFChars(env, dnsCsv, NULL);
    if (dns_utf == NULL) {
        return;
    }
    catcloud_go_update_system_dns((char *)dns_utf);
    (*env)->ReleaseStringUTFChars(env, dnsCsv, dns_utf);
}

JNIEXPORT void JNICALL
Java_io_github_jurybu_catcloud_core_MihomoBridge_nativeResetNetwork(
    JNIEnv *env,
    jobject thiz
) {
    (void)env;
    (void)thiz;
    catcloud_go_reset_network();
}

JNIEXPORT void JNICALL
Java_io_github_jurybu_catcloud_core_MihomoBridge_nativeForceGc(
    JNIEnv *env,
    jobject thiz
) {
    (void)env;
    (void)thiz;
    catcloud_go_force_gc();
}
