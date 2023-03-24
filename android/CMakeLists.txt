cmake_minimum_required(VERSION 3.4.1)

set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 11)

add_library(cpp
            SHARED
            ../node_modules/react-native/ReactCommon/jsi/jsi/jsi.cpp
            ../cpp/react-native-libsodium.cpp
            ../cpp/include/react-native-libsodium.h
            cpp-adapter.cpp
)

# Specifies a path to native header files.
include_directories(
            ../cpp
            ../node_modules/react-native/React
            ../node_modules/react-native/React/Base
            ../node_modules/react-native/ReactCommon/jsi
            ../libsodium/build/libsodium-android-armv7-a/include
)


target_link_libraries(
    ../libsodium/build/libsodium-android-armv8-a+crypto
    ../libsodium/build/libsodium-android-armv8-a+crypto/lib
)