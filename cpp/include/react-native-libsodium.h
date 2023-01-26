#ifndef CPP_INCLUDE_REACT_NATIVE_LIBSODIUM_H_
#define CPP_INCLUDE_REACT_NATIVE_LIBSODIUM_H_
#include <jsi/jsilib.h>
#include <jsi/jsi.h>

void installLibsodium(facebook::jsi::Runtime& jsiRuntime);
void cleanUpLibsodium();

#endif  // CPP_INCLUDE_REACT_NATIVE_LIBSODIUM_H_