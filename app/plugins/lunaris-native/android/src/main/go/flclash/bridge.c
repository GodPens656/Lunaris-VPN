#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "_cgo_export.h"

static JavaVM *vm;
static jobject vpn;
static jmethodID protect_method;
static pthread_mutex_t vpn_lock = PTHREAD_MUTEX_INITIALIZER;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *runtime, void *reserved) {
    vm = runtime;
    return JNI_VERSION_1_6;
}

static void clear_vpn(JNIEnv *env) {
    pthread_mutex_lock(&vpn_lock);
    if (vpn != NULL) {
        (*env)->DeleteGlobalRef(env, vpn);
        vpn = NULL;
    }
    pthread_mutex_unlock(&vpn_lock);
}

int protectSocket(int fd) {
    JNIEnv *env = NULL;
    int attached = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED;
    if (attached && (*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) return 0;
    if (env == NULL) return 0;

    pthread_mutex_lock(&vpn_lock);
    jobject service = vpn == NULL ? NULL : (*env)->NewLocalRef(env, vpn);
    jmethodID method = protect_method;
    pthread_mutex_unlock(&vpn_lock);

    jboolean result = JNI_FALSE;
    if (service != NULL) {
        result = (*env)->CallBooleanMethod(env, service, method, (jint)fd);
        (*env)->DeleteLocalRef(env, service);
    }
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        result = JNI_FALSE;
    }
    if (attached) (*vm)->DetachCurrentThread(vm);
    return result == JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL
Java_dev_sever_vpn_MihomoNative_invoke(JNIEnv *env, jobject self, jbyteArray request) {
    jsize size = (*env)->GetArrayLength(env, request);
    jbyte *bytes = (*env)->GetByteArrayElements(env, request, NULL);
    if (bytes == NULL) return NULL;
    int length = 0;
    void *response = lunarisInvoke((char *)bytes, size, &length);
    (*env)->ReleaseByteArrayElements(env, request, bytes, JNI_ABORT);
    if (response == NULL) return NULL;
    jbyteArray reply = (*env)->NewByteArray(env, length);
    if (reply != NULL) (*env)->SetByteArrayRegion(env, reply, 0, length, response);
    free(response);
    return reply;
}

JNIEXPORT jboolean JNICALL
Java_dev_sever_vpn_MihomoNative_startTun(JNIEnv *env, jobject self, jobject service,
                                      jint fd, jstring addresses, jstring dns) {
    const char *tun_addresses = (*env)->GetStringUTFChars(env, addresses, NULL);
    const char *tun_dns = tun_addresses == NULL ? NULL : (*env)->GetStringUTFChars(env, dns, NULL);
    jclass type = tun_dns == NULL ? NULL : (*env)->GetObjectClass(env, service);
    jmethodID method = type == NULL ? NULL : (*env)->GetMethodID(env, type, "protect", "(I)Z");
    jobject owner = method == NULL ? NULL : (*env)->NewGlobalRef(env, service);
    jboolean started = JNI_FALSE;
    if (owner != NULL) {
        clear_vpn(env);
        pthread_mutex_lock(&vpn_lock);
        vpn = owner;
        protect_method = method;
        pthread_mutex_unlock(&vpn_lock);
        started = lunarisStartTun(fd, (char *)tun_addresses, (char *)tun_dns) ? JNI_TRUE : JNI_FALSE;
        if (!started) clear_vpn(env);
    } else {
        close(fd);
    }
    if (tun_dns != NULL) (*env)->ReleaseStringUTFChars(env, dns, tun_dns);
    if (tun_addresses != NULL) (*env)->ReleaseStringUTFChars(env, addresses, tun_addresses);
    return started;
}

JNIEXPORT void JNICALL
Java_dev_sever_vpn_MihomoNative_stopTun(JNIEnv *env, jobject self) {
    lunarisStopTun();
    clear_vpn(env);
}

JNIEXPORT void JNICALL
Java_dev_sever_vpn_MihomoNative_resetNetwork(JNIEnv *env, jobject self) {
    lunarisResetNetwork();
}
