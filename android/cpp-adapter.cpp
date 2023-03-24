#include <jni.h>
#include <jsi/jsi.h>
#include "include/react-native-libsodium.h"

extern "C"
{
    JNIEXPORT void JNICALL
    Java_com_example_cpp_adapter_cppAdapter_init(JNIEnv *env, jobject thiz, jlong runtimePtr)
    {
        facebook::jsi::Runtime *runtime = reinterpret_cast<facebook::jsi::Runtime *>(runtimePtr);
        installLibsodium(*runtime);
    }
}
