#include <jni.h>
#include "react-native-rnlibsodium.h"

extern "C"
JNIEXPORT jint JNICALL
Java_com_rnlibsodium_RnlibsodiumModule_nativeMultiply(JNIEnv *env, jclass type, jdouble a, jdouble b) {
    return rnlibsodium::multiply(a, b);
}
