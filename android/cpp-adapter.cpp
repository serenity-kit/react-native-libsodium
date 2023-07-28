#include <jni.h>
#include "react-native-libsodium.h"

extern "C" JNIEXPORT void JNICALL
Java_com_libsodium_LibsodiumModule_initialize(JNIEnv *env, jclass clazz, jlong jsiPtr, jstring docPath)
{
    ReactNativeLibsodium::installLibsodium(*reinterpret_cast<facebook::jsi::Runtime *>(jsiPtr));
}