// import our header file to implement the `installRnlibsodium` and `cleanUpRnlibsodium` functions
#include "react-native-rnlibsodium.h"
// useful functions manipulate strings in C++
#include <sstream>

// syntactic sugar around the JSI objects. ex. call: jsi::Function
using namespace facebook;

// get the runtime and create native functions
void installRnlibsodium(jsi::Runtime& jsiRuntime) {

  auto multiply = jsi::Function::createFromHostFunction(
    jsiRuntime,
    jsi::PropNameID::forAscii(jsiRuntime, "multiply"), // internal function name
    1, // number of arguments
    // needs to return a jsi::Value
    [](jsi::Runtime& runtime, const jsi::Value& thisValue, const jsi::Value* arguments, size_t count) -> jsi::Value {
      double res = 22;
      return jsi::Value(res);
    }
  );

  // Rregisters the function on the global object
  jsiRuntime.global().setProperty(jsiRuntime, "multiply", std::move(multiply));
}

void cleanUpRnlibsodium() {
  // intentionally left blank
}