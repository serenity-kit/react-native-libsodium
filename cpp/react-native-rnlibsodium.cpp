// import our header file to implement the `installRnlibsodium` and `cleanUpRnlibsodium` functions
#include "react-native-rnlibsodium.h"
// useful functions manipulate strings in C++
#include <sstream>
// libsodium
#include "sodium.h"

// syntactic sugar around the JSI objects. ex. call: jsi::Function
using namespace facebook;

// get the runtime and create native functions
void installRnlibsodium(jsi::Runtime &jsiRuntime)
{

  auto multiply = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forAscii(jsiRuntime, "multiply"), // internal function name
      1,                                                 // number of arguments
      // needs to return a jsi::Value
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        double res = 24;
        return jsi::Value(res);
      });

  // Registers the function on the global object
  jsiRuntime.global().setProperty(jsiRuntime, "multiply", std::move(multiply));

  auto from_base64 = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "from_base64"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-rnlibsodium][from_base64] value can't be null");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-rnlibsodium][from_base64] variant can't be null");
        }

        std::string base64String = arguments[0].asString(runtime).utf8(runtime);
        uint8_t variant = arguments[1].asNumber();

        std::vector<uint8_t> uint8Vector;
        uint8Vector.resize(base64String.size());

        size_t length = 0;
        sodium_base642bin((uint8_t *)uint8Vector.data(), uint8Vector.size(), (char *)base64String.data(), base64String.size(), nullptr, &length, nullptr, variant);

        uint8Vector.resize(length);

        return jsi::String::createFromUtf8(runtime, uint8Vector.data(), uint8Vector.size());
      });

  jsiRuntime.global().setProperty(jsiRuntime, "from_base64", std::move(from_base64));

  auto to_base64 = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "to_base64"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-rnlibsodium][to_base64] value can't be null");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-rnlibsodium][to_base64] variant can't be null");
        }

        std::string utf8String = arguments[0].asString(runtime).utf8(runtime);
        uint8_t variant = arguments[1].asNumber();

        std::string base64String;
        base64String.resize(sodium_base64_encoded_len(utf8String.size(), variant));
        sodium_bin2base64((char *)base64String.data(), base64String.size(), (uint8_t *)utf8String.data(), utf8String.size(), variant);

        return jsi::String::createFromUtf8(runtime, base64String);
      });
  jsiRuntime.global().setProperty(jsiRuntime, "to_base64", std::move(to_base64));
}

void cleanUpRnlibsodium()
{
  // intentionally left blank
}