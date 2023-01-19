#include <jni.h>
#include "include/react-native-libsodium.h"

extern "C"
JNIEXPORT jint JNICALL
Java_com_libsodium_LibsodiumModule_nativeMultiply(JNIEnv *env, jclass type, jdouble a, jdouble b) {
    return libsodium::multiply(a, b);
}
