cmake_minimum_required(VERSION 3.4.1)

set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 14)

# add directories to "include" search paths
include_directories(
            ../cpp
            "${NODE_MODULES_DIR}/react-native/React"
            "${NODE_MODULES_DIR}/react-native/React/Base"
            "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
)

# set the base libsodium build directory
set(LIBSODIUM_BUILD_DIR ${CMAKE_CURRENT_LIST_DIR}/../libsodium/build)

# set the libsodium build directory depending on the target abi
if (${ANDROID_ABI} STREQUAL arm64-v8a)
  set(LIBSODIUM_BUILD_DIR ${LIBSODIUM_BUILD_DIR}/libsodium-android-armv8-a+crypto)
elseif(${ANDROID_ABI} STREQUAL armeabi-v7a)
  set(LIBSODIUM_BUILD_DIR ${LIBSODIUM_BUILD_DIR}/libsodium-android-armv7-a)
elseif(${ANDROID_ABI} STREQUAL x86)
  set(LIBSODIUM_BUILD_DIR ${LIBSODIUM_BUILD_DIR}/libsodium-android-i686)
else()
  set(LIBSODIUM_BUILD_DIR ${LIBSODIUM_BUILD_DIR}/libsodium-android-westmere)
endif()

add_library(sodium SHARED IMPORTED)
include_directories( ${LIBSODIUM_BUILD_DIR}/include/ )
set_target_properties( sodium PROPERTIES IMPORTED_LOCATION ${LIBSODIUM_BUILD_DIR}/lib/libsodium.so )

# here we define a library target called "libsodium"
# which will be built from the listed source files
add_library(libsodium
  SHARED
  "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi/jsi/jsi.cpp"
  ../cpp/react-native-libsodium.cpp
  ../cpp/react-native-libsodium.h
  cpp-adapter.cpp
)

# link the sodium lib with our "libsodium" library target defined earlier
target_link_libraries(libsodium sodium)
