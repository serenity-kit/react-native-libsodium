// import our header file to implement the `installLibsodium` and `cleanUpLibsodium` functions
#include "include/react-native-libsodium.h"
// libsodium
#include <sodium.h>
// useful functions manipulate strings in C++
#include <sstream>
#include <utility>
#include <string>
#include <vector>

// syntactic sugar around the JSI objects. ex. call: jsi::Function
using namespace facebook;

enum class JsiArgType
{
  string,
  arrayBuffer,
  null,
  undefined
};

// Convert an array buffer to a JavaScript object
jsi::Object arrayBufferAsObject(jsi::Runtime &runtime, std::vector<uint8_t> &data)
{
  jsi::Object returnBufferAsObject = runtime.global()
                                         .getPropertyAsFunction(runtime, "ArrayBuffer")
                                         .callAsConstructor(runtime, static_cast<int>(data.size()))
                                         .asObject(runtime);
  jsi::ArrayBuffer arraybuffer = returnBufferAsObject.getArrayBuffer(runtime);
  memcpy(arraybuffer.data(runtime), data.data(), data.size());
  return returnBufferAsObject;
}

void validateRequired(const std::string &functionName, jsi::Runtime &runtime, const jsi::Value &argument, std::string &argumentName)
{
  if (argument.isNull())
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " can't be null";
    throw jsi::JSError(runtime, errorMessage);
  }
}

void validateIsString(const std::string &functionName, jsi::Runtime &runtime, const jsi::Value &argument, std::string &argumentName, bool required)
{
  if (required)
  {
    validateRequired(functionName, runtime, argument, argumentName);
  }
  if (!argument.isString())
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " must be an ArrayBuffer";
    throw jsi::JSError(runtime, errorMessage);
  }
}

void validateIsArrayBuffer(const std::string &functionName, jsi::Runtime &runtime, const jsi::Value &argument, std::string &argumentName, bool required)
{
  if (required)
  {
    validateRequired(functionName, runtime, argument, argumentName);
  }
  if (!argument.isObject() ||
      !argument.asObject(runtime).isArrayBuffer(runtime))
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " must be an ArrayBuffer";
    throw jsi::JSError(runtime, errorMessage);
  }
}

JsiArgType validateIsStringOrArrayBuffer(const std::string &functionName, jsi::Runtime &runtime, const jsi::Value &argument, std::string &argumentName, bool required)
{
  if (required)
  {
    validateRequired(functionName, runtime, argument, argumentName);
  }
  if (argument.isString())
  {
    return JsiArgType::string;
  }
  else if (argument.isObject() &&
           argument.asObject(runtime).isArrayBuffer(runtime))
  {
    return JsiArgType::arrayBuffer;
  }
  else if (argument.isNull())
  {
    return JsiArgType::null;
  }
  else if (argument.isUndefined())
  {
    return JsiArgType::undefined;
  }
  else
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " must be a string or an ArrayBuffer";
    throw jsi::JSError(runtime, errorMessage);
  }
}

void validateIsNumber(const std::string &functionName, jsi::Runtime &runtime, const jsi::Value &argument, std::string &argumentName, bool required)
{
  if (required)
  {
    validateRequired(functionName, runtime, argument, argumentName);
  }
  if (!argument.isNumber())
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " must be a number";
    throw jsi::JSError(runtime, errorMessage);
  }
}

void throwOnBadResult(const std::string &functionName, jsi::Runtime &runtime, int result)
{
  if (result != 0)
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + functionName + " failed";
    throw jsi::JSError(runtime, errorMessage);
  }
}

// get the runtime and create native functions
void installLibsodium(jsi::Runtime &jsiRuntime)
{
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_KEYBYTES", static_cast<int>(crypto_secretbox_KEYBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_NONCEBYTES", static_cast<int>(crypto_secretbox_NONCEBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_SALTBYTES", static_cast<int>(crypto_pwhash_SALTBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_ALG_DEFAULT", static_cast<int>(crypto_pwhash_ALG_DEFAULT));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_OPSLIMIT_INTERACTIVE", static_cast<int>(crypto_pwhash_OPSLIMIT_INTERACTIVE));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_MEMLIMIT_INTERACTIVE", static_cast<int>(crypto_pwhash_MEMLIMIT_INTERACTIVE));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_PUBLICKEYBYTES", static_cast<int>(crypto_box_PUBLICKEYBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_SECRETKEYBYTES", static_cast<int>(crypto_box_SECRETKEYBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_NONCEBYTES", static_cast<int>(crypto_box_NONCEBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_KEYBYTES", static_cast<int>(crypto_aead_xchacha20poly1305_ietf_KEYBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", static_cast<int>(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_kdf_KEYBYTES", static_cast<int>(crypto_kdf_KEYBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_BYTES_MAX", static_cast<int>(crypto_pwhash_BYTES_MAX));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_BYTES_MIN", static_cast<int>(crypto_pwhash_BYTES_MIN));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_kdf_CONTEXTBYTES", static_cast<int>(crypto_kdf_CONTEXTBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_generichash_BYTES", static_cast<int>(crypto_generichash_BYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_generichash_BYTES_MIN", static_cast<int>(crypto_generichash_BYTES_MIN));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_generichash_BYTES_MAX", static_cast<int>(crypto_generichash_BYTES_MAX));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_generichash_KEYBYTES", static_cast<int>(crypto_generichash_KEYBYTES));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_generichash_KEYBYTES_MIN", static_cast<int>(crypto_generichash_KEYBYTES_MIN));
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_generichash_KEYBYTES_MAX", static_cast<int>(crypto_generichash_KEYBYTES_MAX));

  auto jsi_from_base64_to_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "from_base64"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "from_base64";

        std::string valueArgumentName = "value";
        unsigned int valueArgumentPosition = 0;
        validateRequired(functionName, runtime, arguments[valueArgumentPosition], valueArgumentName);

        std::string variantArgumentName = "variant";
        unsigned int variantArgumentPosition = 1;
        validateRequired(functionName, runtime, arguments[variantArgumentPosition], variantArgumentName);

        std::string base64String = arguments[0].asString(runtime).utf8(runtime);
        uint8_t variant = arguments[1].asNumber();

        std::vector<uint8_t> uint8Vector;
        uint8Vector.resize(base64String.size());

        size_t length = 0;
        int result = sodium_base642bin(
            reinterpret_cast<unsigned char *>(uint8Vector.data()),
            uint8Vector.size(),
            reinterpret_cast<const char *>(base64String.data()),
            base64String.size(),
            nullptr,
            &length,
            nullptr,
            variant);

        throwOnBadResult(functionName, runtime, result);

        uint8Vector.resize(length);
        jsi::Object returnBufferAsObject = arrayBufferAsObject(runtime, uint8Vector);
        return returnBufferAsObject;
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_from_base64_to_arraybuffer", std::move(jsi_from_base64_to_arraybuffer));

  auto jsi_to_base64 = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_to_base64"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "to_base64";

        std::string valueArgumentName = "value";
        unsigned int valueArgumentPosition = 0;
        JsiArgType valueArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[valueArgumentPosition], valueArgumentName, true);

        std::string variantArgumentName = "variant";
        unsigned int variantArgumentPosition = 1;
        validateIsNumber(functionName, runtime, arguments[variantArgumentPosition], variantArgumentName, true);

        std::string base64String;
        uint8_t variant = arguments[variantArgumentPosition].asNumber();

        if (valueArgType == JsiArgType::string)
        {
          std::string dataString = arguments[valueArgumentPosition].asString(runtime).utf8(runtime);
          base64String.resize(sodium_base64_encoded_len(dataString.length(), variant));
          sodium_bin2base64(
              const_cast<char *>(reinterpret_cast<const char *>(base64String.data())), base64String.size(),
              reinterpret_cast<const unsigned char *>(dataString.data()),
              dataString.length(),
              variant);
        }
        else
        {
          auto dataArrayBuffer = arguments[valueArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          base64String.resize(sodium_base64_encoded_len(dataArrayBuffer.length(runtime), variant));
          sodium_bin2base64(
              const_cast<char *>(reinterpret_cast<const char *>(base64String.data())),
              base64String.size(),
              dataArrayBuffer.data(runtime),
              dataArrayBuffer.length(runtime),
              variant);
        }

        // libsodium adds a nul byte (\0) terminator to the end of the string
        if (base64String.length() && base64String[base64String.length() - 1] == '\0')
        {
          base64String.pop_back();
        }

        return jsi::String::createFromUtf8(runtime, base64String);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_to_base64", std::move(jsi_to_base64));

  auto jsi_to_hex = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_to_hex"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "to_hex";

        std::string valueArgumentName = "value";
        unsigned int valueArgumentPosition = 0;
        JsiArgType valueArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[valueArgumentPosition], valueArgumentName, true);

        std::string hexString;

        if (valueArgType == JsiArgType::string)
        {
          std::string dataString = arguments[valueArgumentPosition].asString(runtime).utf8(runtime);
          hexString.resize(dataString.length() * 2 + 1);
          sodium_bin2hex(
              const_cast<char *>(reinterpret_cast<const char *>(hexString.data())),
              hexString.length(),
              reinterpret_cast<const unsigned char *>(dataString.data()),
              dataString.length());
        }
        else
        {
          auto dataArrayBuffer = arguments[valueArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          hexString.resize(dataArrayBuffer.length(runtime) * 2 + 1);
          sodium_bin2hex(
              const_cast<char *>(reinterpret_cast<const char *>(hexString.data())),
              hexString.length(),
              dataArrayBuffer.data(runtime),
              dataArrayBuffer.length(runtime));
        }

        // libsodium adds a nul byte (\0) terminator to the end of the string
        if (hexString.length() && hexString[hexString.length() - 1] == '\0')
        {
          hexString.pop_back();
        }

        return jsi::String::createFromUtf8(runtime, hexString);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_to_hex", std::move(jsi_to_hex));

  auto jsi_randombytes_buf = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_randombytes_buf"),
      1,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "randombytes_buf";

        std::string sizeArgumentName = "size";
        unsigned int sizeArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments[sizeArgumentPosition], sizeArgumentName, true);

        int size = arguments[0].asNumber();

        jsi::Object returnBufferAsObject = runtime.global()
                                               .getPropertyAsFunction(runtime, "ArrayBuffer")
                                               .callAsConstructor(runtime, size)
                                               .asObject(runtime);
        jsi::ArrayBuffer arraybuffer = returnBufferAsObject.getArrayBuffer(runtime);
        randombytes_buf(arraybuffer.data(runtime), size);
        return returnBufferAsObject;
      });
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_randombytes_buf", std::move(jsi_randombytes_buf));

  auto jsi_randombytes_uniform = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "randombytes_uniform"),
      1,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "randombytes_uniform";

        std::string upperBoundArgumentName = "upper_bound";
        unsigned int upperBoundArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments[upperBoundArgumentPosition], upperBoundArgumentName, true);

        int upperBound = arguments[0].asNumber();
        return jsi::Value(static_cast<int>(randombytes_uniform(upperBound)));
      });
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_randombytes_uniform", std::move(jsi_randombytes_uniform));

  auto jsi_crypto_secretbox_keygen = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "crypto_secretbox_keygen"),
      0,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::vector<uint8_t> key(crypto_secretbox_KEYBYTES);
        crypto_secretbox_keygen(key.data());
        return arrayBufferAsObject(runtime, key);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_keygen", std::move(jsi_crypto_secretbox_keygen));

  auto jsi_crypto_aead_xchacha20poly1305_ietf_keygen = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "crypto_aead_xchacha20poly1305_ietf_keygen"),
      0,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::vector<uint8_t> key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        crypto_aead_xchacha20poly1305_ietf_keygen(key.data());
        return arrayBufferAsObject(runtime, key);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_keygen", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_keygen));

  auto jsi_crypto_kdf_keygen = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "crypto_kdf_keygen"),
      0,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::vector<uint8_t> key(crypto_kdf_KEYBYTES);
        crypto_kdf_keygen(key.data());
        return arrayBufferAsObject(runtime, key);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_kdf_keygen", std::move(jsi_crypto_kdf_keygen));

  auto jsi_crypto_box_keypair = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "crypto_box_keypair"),
      0,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        uint64_t publickeyLength = crypto_box_PUBLICKEYBYTES;
        uint64_t secretkeyLength = crypto_box_SECRETKEYBYTES;
        std::vector<uint8_t> publickey(publickeyLength);
        std::vector<uint8_t> secretkey(secretkeyLength);
        crypto_box_keypair(publickey.data(), secretkey.data());

        jsi::Object returnPublicKeyBufferAsObject = arrayBufferAsObject(runtime, publickey);
        jsi::Object returnSecretKeyBufferAsObject = arrayBufferAsObject(runtime, secretkey);

        auto object = jsi::Object(runtime);
        object.setProperty(runtime, "publicKey", returnPublicKeyBufferAsObject);
        object.setProperty(runtime, "secretKey", returnSecretKeyBufferAsObject);
        return object;
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_keypair", std::move(jsi_crypto_box_keypair));

  auto jsi_crypto_sign_keypair = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "crypto_sign_keypair"),
      0,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        uint64_t publickeyLength = crypto_sign_PUBLICKEYBYTES;
        uint64_t secretkeyLength = crypto_sign_SECRETKEYBYTES;
        std::vector<uint8_t> publickey(publickeyLength);
        std::vector<uint8_t> secretkey(secretkeyLength);
        crypto_sign_keypair(publickey.data(), secretkey.data());

        jsi::Object returnPublicKeyBufferAsObject = arrayBufferAsObject(runtime, publickey);
        jsi::Object returnSecretKeyBufferAsObject = arrayBufferAsObject(runtime, secretkey);

        auto object = jsi::Object(runtime);
        object.setProperty(runtime, "publicKey", returnPublicKeyBufferAsObject);
        object.setProperty(runtime, "secretKey", returnSecretKeyBufferAsObject);
        return object;
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_sign_keypair", std::move(jsi_crypto_sign_keypair));

  auto jsi_crypto_sign_detached = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_sign_detached"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_sign_detached";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        JsiArgType messageArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string secretKeyArgumentName = "secretKey";
        unsigned int secretKeyArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[secretKeyArgumentPosition], secretKeyArgumentName, true);

        auto secretKeyDataArrayBuffer =
            arguments[secretKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);

        std::vector<uint8_t> sig(crypto_sign_BYTES);
        if (messageArgType == JsiArgType::string)
        {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          crypto_sign_detached(sig.data(), NULL, reinterpret_cast<const unsigned char *>(messageString.data()), messageString.length(), secretKeyDataArrayBuffer.data(runtime));
        }
        else
        {
          auto messageArrayBuffer = arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          crypto_sign_detached(sig.data(), NULL, messageArrayBuffer.data(runtime), messageArrayBuffer.length(runtime), secretKeyDataArrayBuffer.data(runtime));
        }

        return arrayBufferAsObject(runtime, sig);
      });
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_sign_detached", std::move(jsi_crypto_sign_detached));

  auto jsi_crypto_sign_verify_detached = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_sign_verify_detached"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_sign_verify_detached";

        std::string signatureArgumentName = "signature";
        unsigned int signatureArgumentPosition = 0;
        validateIsArrayBuffer(functionName, runtime, arguments[signatureArgumentPosition], signatureArgumentName, true);

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 1;
        JsiArgType messageArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string publicKeyArgumentName = "publicKey";
        unsigned int publicKeyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[publicKeyArgumentPosition], publicKeyArgumentName, true);

        auto signatureArrayBuffer = arguments[signatureArgumentPosition].asObject(runtime).getArrayBuffer(runtime);

        auto publicKeyArrayBuffer = arguments[publicKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);

        int result = -1;
        if (messageArgType == JsiArgType::string)
        {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          result = crypto_sign_verify_detached(
              signatureArrayBuffer.data(runtime),
              reinterpret_cast<const unsigned char *>(messageString.data()),
              messageString.length(),
              publicKeyArrayBuffer.data(runtime));
        }
        else
        {
          auto messageArrayBuffer = arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          result = crypto_sign_verify_detached(signatureArrayBuffer.data(runtime), messageArrayBuffer.data(runtime), messageArrayBuffer.length(runtime), publicKeyArrayBuffer.data(runtime));
        }

        return jsi::Value(static_cast<bool>(result == 0));
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_sign_verify_detached", std::move(jsi_crypto_sign_verify_detached));

  auto jsi_crypto_secretbox_easy = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_secretbox_easy"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_secretbox_easy";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        JsiArgType messageArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string keyArgumentName = "nonce";
        unsigned int keyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[keyArgumentPosition], keyArgumentName, true);

        auto nonce = arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        auto key = arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);

        if (nonce.length(runtime) != crypto_secretbox_NONCEBYTES) {
          throw jsi::JSError(runtime, "invalid nonce length");
        }
        if (key.length(runtime) != crypto_secretbox_KEYBYTES) {
          throw jsi::JSError(runtime, "invalid key length");
        }

        std::vector<uint8_t> ciphertext;

        if (messageArgType == JsiArgType::string)
        {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          ciphertext.resize(messageString.length() + crypto_secretbox_MACBYTES);
          crypto_secretbox_easy(ciphertext.data(), reinterpret_cast<const unsigned char *>(messageString.data()), messageString.length(), nonce.data(runtime), key.data(runtime));
        }
        else
        {
          auto messageArrayBuffer = arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          ciphertext.resize(messageArrayBuffer.length(runtime) + crypto_secretbox_MACBYTES);
          crypto_secretbox_easy(ciphertext.data(), messageArrayBuffer.data(runtime), messageArrayBuffer.length(runtime), nonce.data(runtime), key.data(runtime));
        }

        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_easy", std::move(jsi_crypto_secretbox_easy));

  auto jsi_crypto_secretbox_open_easy = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_secretbox_open_easy"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_secretbox_open_easy";

        std::string ciphertextArgumentName = "ciphertext";
        unsigned int ciphertextArgumentPosition = 0;
        JsiArgType ciphertextArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[ciphertextArgumentPosition], ciphertextArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[keyArgumentPosition], keyArgumentName, true);

        auto nonceArrayBuffer = arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        auto keyArrayBuffer = arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);

        if (nonceArrayBuffer.length(runtime) != crypto_secretbox_NONCEBYTES) {
          throw jsi::JSError(runtime, "invalid nonce length");
        }
        if (keyArrayBuffer.length(runtime) != crypto_secretbox_KEYBYTES) {
          throw jsi::JSError(runtime, "invalid key length");
        }

        std::vector<uint8_t> message;
        int result = -1;

        if (ciphertextArgType == JsiArgType::string)
        {
          std::string ciphertextString = arguments[ciphertextArgumentPosition].asString(runtime).utf8(runtime);
          uint64_t messageLength = ciphertextString.length() - crypto_secretbox_MACBYTES;
          message.resize(messageLength);
          result = crypto_secretbox_open_easy(
              message.data(),
              reinterpret_cast<const unsigned char *>(ciphertextString.data()),
              ciphertextString.length(),
              nonceArrayBuffer.data(runtime),
              keyArrayBuffer.data(runtime));
        }
        else
        {
          auto ciphertextArrayBuffer = arguments[ciphertextArgumentPosition].asObject(runtime).getArrayBuffer(runtime);

          uint64_t messageLength = ciphertextArrayBuffer.length(runtime) - crypto_secretbox_MACBYTES;
          message.resize(messageLength);
          result = crypto_secretbox_open_easy(
              message.data(),
              ciphertextArrayBuffer.data(runtime),
              ciphertextArrayBuffer.length(runtime),
              nonceArrayBuffer.data(runtime),
              keyArrayBuffer.data(runtime));
        }

        throwOnBadResult(functionName, runtime, result);
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_open_easy", std::move(jsi_crypto_secretbox_open_easy));

  auto jsi_crypto_box_easy = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_box_easy"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_box_easy";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        JsiArgType messageArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string publicKeyArgumentName = "publicKey";
        unsigned int publicKeyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[publicKeyArgumentPosition], publicKeyArgumentName, true);

        std::string secretKeyArgumentName = "publicKey";
        unsigned int secretKeyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments[secretKeyArgumentPosition], secretKeyArgumentName, true);

        auto nonce = arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        auto publicKey = arguments[publicKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        auto secretKey = arguments[secretKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);

        if (nonce.length(runtime) != crypto_box_NONCEBYTES) {
          throw jsi::JSError(runtime, "invalid nonce length");
        }
        if (publicKey.length(runtime) != crypto_box_PUBLICKEYBYTES) {
          throw jsi::JSError(runtime, "invalid publicKey length");
        }
        if (secretKey.length(runtime) != crypto_box_SECRETKEYBYTES) {
          throw jsi::JSError(runtime, "invalid privateKey length");
        }

        std::vector<uint8_t> ciphertext;
        int result = -1;

        if (messageArgType == JsiArgType::string)
        {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          ciphertext.resize(messageString.length() + crypto_box_MACBYTES);
          result = crypto_box_easy(
              ciphertext.data(),
              reinterpret_cast<const unsigned char *>(messageString.data()),
              messageString.length(),
              nonce.data(runtime),
              publicKey.data(runtime),
              secretKey.data(runtime));
        }
        else
        {
          auto messageArrayBuffer = arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          ciphertext.resize(messageArrayBuffer.length(runtime) + crypto_box_MACBYTES);
          result = crypto_box_easy(
              ciphertext.data(),
              messageArrayBuffer.data(runtime),
              messageArrayBuffer.length(runtime),
              nonce.data(runtime),
              publicKey.data(runtime),
              secretKey.data(runtime));
        }

        throwOnBadResult(functionName, runtime, result);
        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_easy", std::move(jsi_crypto_box_easy));

  auto jsi_crypto_box_open_easy = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_box_open_easy"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_box_open_easy";

        std::string ciphertextArgumentName = "ciphertext";
        unsigned int ciphertextArgumentPosition = 0;
        JsiArgType ciphertextArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[ciphertextArgumentPosition], ciphertextArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string publicKeyArgumentName = "publicKey";
        unsigned int publicKeyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[publicKeyArgumentPosition], publicKeyArgumentName, true);

        std::string secretKeyArgumentName = "secretKey";
        unsigned int secretKeyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments[secretKeyArgumentPosition], secretKeyArgumentName, true);

        auto nonceArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);

        auto publicKeyArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);

        auto secretKeyArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);

        if (nonceArrayBuffer.length(runtime) != crypto_box_NONCEBYTES) {
          throw jsi::JSError(runtime, "invalid nonce length");
        }
        if (publicKeyArrayBuffer.length(runtime) != crypto_box_PUBLICKEYBYTES) {
          throw jsi::JSError(runtime, "invalid publicKey length");
        }
        if (secretKeyArrayBuffer.length(runtime) != crypto_box_SECRETKEYBYTES) {
          throw jsi::JSError(runtime, "invalid privateKey length");
        }

        std::vector<uint8_t> message;
        int result = -1;

        if (ciphertextArgType == JsiArgType::string)
        {
          std::string ciphertextString = arguments[ciphertextArgumentPosition].asString(runtime).utf8(runtime);
          message.resize(ciphertextString.length() - crypto_box_MACBYTES);
          result = crypto_box_open_easy(
              message.data(),
              reinterpret_cast<const unsigned char *>(ciphertextString.data()),
              ciphertextString.length(),
              nonceArrayBuffer.data(runtime),
              publicKeyArrayBuffer.data(runtime),
              secretKeyArrayBuffer.data(runtime));
        }
        else
        {
          auto ciphertextArrayBuffer = arguments[ciphertextArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          message.resize(ciphertextArrayBuffer.length(runtime) - crypto_box_MACBYTES);
          result = crypto_box_open_easy(
              message.data(),
              ciphertextArrayBuffer.data(runtime),
              ciphertextArrayBuffer.length(runtime),
              nonceArrayBuffer.data(runtime),
              publicKeyArrayBuffer.data(runtime),
              secretKeyArrayBuffer.data(runtime));
        }

        throwOnBadResult(functionName, runtime, result);
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_open_easy", std::move(jsi_crypto_box_open_easy));

  auto jsi_crypto_pwhash = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_pwhash"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_pwhash";

        std::string keyLengthArgumentName = "keyLength";
        unsigned int keyLengthArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments[keyLengthArgumentPosition], keyLengthArgumentName, true);

        std::string passwordArgumentName = "password";
        unsigned int passwordArgumentPosition = 1;
        JsiArgType passwordArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[passwordArgumentPosition], passwordArgumentName, true);

        std::string saltArgumentName = "salt";
        unsigned int saltArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[saltArgumentPosition], saltArgumentName, true);

        std::string opsLimitArgumentName = "opsLimit";
        unsigned int opsLimitArgumentPosition = 3;
        validateIsNumber(functionName, runtime, arguments[opsLimitArgumentPosition], opsLimitArgumentName, true);

        std::string memLimitArgumentName = "memLimit";
        unsigned int memLimitArgumentPosition = 4;
        validateIsNumber(functionName, runtime, arguments[memLimitArgumentPosition], memLimitArgumentName, true);

        std::string algorithmArgumentName = "algorithm";
        unsigned int algorithmArgumentPosition = 5;
        validateIsNumber(functionName, runtime, arguments[algorithmArgumentPosition], algorithmArgumentName, true);

        int keyLength = arguments[keyLengthArgumentPosition].asNumber();
        auto saltDataArrayBuffer =
            arguments[saltArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        int opsLimit = arguments[opsLimitArgumentPosition].asNumber();
        int memLimit = arguments[memLimitArgumentPosition].asNumber();
        int algorithm = arguments[algorithmArgumentPosition].asNumber();
        std::vector<uint8_t> key(keyLength);

        int result = -1;
        if (passwordArgType == JsiArgType::string)
        {
          std::string passwordString = arguments[passwordArgumentPosition].asString(runtime).utf8(runtime);
          result = crypto_pwhash(
              key.data(),
              keyLength,
              reinterpret_cast<const char *>(passwordString.data()),
              passwordString.length(),
              saltDataArrayBuffer.data(runtime),
              opsLimit,
              memLimit,
              algorithm);
        }
        else
        {
          auto passwordArrayBuffer =
              arguments[passwordArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          result = crypto_pwhash(
              key.data(),
              keyLength,
              reinterpret_cast<const char *>(passwordArrayBuffer.data(runtime)),
              passwordArrayBuffer.length(runtime),
              saltDataArrayBuffer.data(runtime),
              opsLimit,
              memLimit,
              algorithm);
        }

        throwOnBadResult(functionName, runtime, result);
        return arrayBufferAsObject(runtime, key);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash", std::move(jsi_crypto_pwhash));

  auto jsi_crypto_kdf_derive_from_key = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_kdf_derive_from_key"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_kdf_derive_from_key";

        std::string subkeyLengthArgumentName = "subkeyLength";
        unsigned int subkeyLengthArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments[subkeyLengthArgumentPosition], subkeyLengthArgumentName, true);

        std::string subkeyIdArgumentName = "subkeyId";
        unsigned int subkeyIdArgumentPosition = 1;
        validateIsNumber(functionName, runtime, arguments[subkeyIdArgumentPosition], subkeyIdArgumentName, true);

        std::string contextArgumentName = "context";
        unsigned int contextArgumentPosition = 2;
        validateIsString(functionName, runtime, arguments[contextArgumentPosition], contextArgumentName, true);

        std::string masterKeyArgumentName = "masterKey";
        unsigned int masterKeyArgumentPosition = 3;
        JsiArgType masterKeyArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[masterKeyArgumentPosition], masterKeyArgumentName, true);

        std::string context = arguments[contextArgumentPosition].asString(runtime).utf8(runtime);
        int subkeyLength = arguments[subkeyLengthArgumentPosition].asNumber();
        int subkeyId = arguments[subkeyIdArgumentPosition].asNumber();
        std::vector<uint8_t> subkey(subkeyLength);

        int result = -1;
        if (masterKeyArgType == JsiArgType::string)
        {
          std::string masterKeyString = arguments[masterKeyArgumentPosition].asString(runtime).utf8(runtime);
          result = crypto_kdf_derive_from_key(
              subkey.data(),
              subkeyLength,
              subkeyId,
              reinterpret_cast<const char *>(context.data()),
              reinterpret_cast<const unsigned char *>(masterKeyString.data()));
        }
        else
        {
          auto masterKeyArrayBuffer = arguments[masterKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          result = crypto_kdf_derive_from_key(
              subkey.data(),
              subkeyLength,
              subkeyId,
              reinterpret_cast<const char *>(context.data()),
              masterKeyArrayBuffer.data(runtime));
        }

        throwOnBadResult(functionName, runtime, result);
        return arrayBufferAsObject(runtime, subkey);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_kdf_derive_from_key", std::move(jsi_crypto_kdf_derive_from_key));

  auto jsi_crypto_aead_xchacha20poly1305_ietf_encrypt = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_aead_xchacha20poly1305_ietf_encrypt";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        JsiArgType messageArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string additionalDataArgumentName = "additionalData";
        unsigned int additionalDataArgumentPosition = 1;
        validateIsString(functionName, runtime, arguments[additionalDataArgumentPosition], additionalDataArgumentName, true);

        std::string publicNonceArgumentName = "public_nonce";
        unsigned int publicNonceArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[publicNonceArgumentPosition], publicNonceArgumentName, true);

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments[keyArgumentPosition], keyArgumentName, true);

        std::string additionalData = arguments[additionalDataArgumentPosition].asString(runtime).utf8(runtime);
        auto publicNonceArrayBuffer =
            arguments[publicNonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        auto keyArrayBuffer =
            arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);

        if (publicNonceArrayBuffer.length(runtime) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
          throw jsi::JSError(runtime, "invalid public_nonce length");
        }
        if (keyArrayBuffer.length(runtime) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
          throw jsi::JSError(runtime, "invalid key length");
        }

        std::vector<uint8_t> ciphertext;
        int result = -1;

        if (messageArgType == JsiArgType::string)
        {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          unsigned long long ciphertextLength = messageString.length() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
          ciphertext.resize(ciphertextLength);
          result = crypto_aead_xchacha20poly1305_ietf_encrypt(
              ciphertext.data(),
              &ciphertextLength,
              reinterpret_cast<const unsigned char *>(messageString.data()),
              messageString.length(),
              reinterpret_cast<const unsigned char *>(additionalData.data()),
              additionalData.length(),
              NULL,
              publicNonceArrayBuffer.data(runtime),
              keyArrayBuffer.data(runtime));
        }
        else
        {
          auto messageArrayBuffer =
              arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          unsigned long long ciphertextLength = messageArrayBuffer.length(runtime) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
          ciphertext.resize(ciphertextLength);
          result = crypto_aead_xchacha20poly1305_ietf_encrypt(
              ciphertext.data(),
              &ciphertextLength,
              messageArrayBuffer.data(runtime),
              messageArrayBuffer.length(runtime),
              reinterpret_cast<const unsigned char *>(additionalData.data()),
              additionalData.length(),
              NULL,
              publicNonceArrayBuffer.data(runtime),
              keyArrayBuffer.data(runtime));
        }

        throwOnBadResult(functionName, runtime, result);
        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_encrypt));

  auto jsi_crypto_aead_xchacha20poly1305_ietf_decrypt = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_decrypt"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "crypto_aead_xchacha20poly1305_ietf_decrypt";

        std::string ciphertextArgumentName = "ciphertext";
        unsigned int ciphertextArgumentPosition = 0;
        JsiArgType ciphertextArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[ciphertextArgumentPosition], ciphertextArgumentName, true);

        std::string additionalDataArgumentName = "additionalData";
        unsigned int additionalDataArgumentPosition = 1;
        validateIsString(functionName, runtime, arguments[additionalDataArgumentPosition], additionalDataArgumentName, true);

        std::string publicNonceArgumentName = "public_nonce";
        unsigned int publicNonceArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[publicNonceArgumentPosition], publicNonceArgumentName, true);

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments[keyArgumentPosition], keyArgumentName, true);

        std::string additionalData = arguments[additionalDataArgumentPosition].asString(runtime).utf8(runtime);
        auto publicNonceArrayBuffer =
            arguments[publicNonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        auto keyArrayBuffer =
            arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);

        if (publicNonceArrayBuffer.length(runtime) != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
          throw jsi::JSError(runtime, "invalid public_nonce length");
        }
        if (keyArrayBuffer.length(runtime) != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
          throw jsi::JSError(runtime, "invalid key length");
        }

        std::vector<uint8_t> message;

        int result = -1;
        if (ciphertextArgType == JsiArgType::string)
        {
          std::string ciphertextString = arguments[ciphertextArgumentPosition].asString(runtime).utf8(runtime);
          unsigned long long messageLength = ciphertextString.length() - crypto_aead_xchacha20poly1305_ietf_ABYTES;
          message.resize(messageLength);
          result = crypto_aead_xchacha20poly1305_ietf_decrypt(
              message.data(),
              &messageLength,
              NULL,
              reinterpret_cast<const unsigned char *>(ciphertextString.data()),
              ciphertextString.length(),
              reinterpret_cast<const unsigned char *>(additionalData.data()),
              additionalData.length(),
              publicNonceArrayBuffer.data(runtime),
              keyArrayBuffer.data(runtime));
        }
        else
        {
          auto ciphertextArrayBuffer =
              arguments[ciphertextArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          unsigned long long messageLength = ciphertextArrayBuffer.length(runtime) - crypto_aead_xchacha20poly1305_ietf_ABYTES;
          message.resize(messageLength);
          result = crypto_aead_xchacha20poly1305_ietf_decrypt(
              message.data(),
              &messageLength,
              NULL,
              ciphertextArrayBuffer.data(runtime),
              ciphertextArrayBuffer.length(runtime),
              reinterpret_cast<const unsigned char *>(additionalData.data()),
              additionalData.length(),
              publicNonceArrayBuffer.data(runtime),
              keyArrayBuffer.data(runtime));
        }

        throwOnBadResult(functionName, runtime, result);
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_decrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_decrypt));

  auto jsi_crypto_generichash = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_generichash"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "jsi_crypto_generichash";

        std::string hashLengthArgumentName = "hashLength";
        unsigned int hashLengthArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments[hashLengthArgumentPosition], hashLengthArgumentName, true);

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 1;
        JsiArgType messageArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);
        uint64_t messageLength = 0;

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 2;
        JsiArgType keyArgType = validateIsStringOrArrayBuffer(functionName, runtime, arguments[keyArgumentPosition], keyArgumentName, false);
        uint64_t keyLength = 0;

        int hashLength = arguments[hashLengthArgumentPosition].asNumber();

        unsigned char* message;
        unsigned char* key;

        if (messageArgType == JsiArgType::string) {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          messageLength = messageString.length();
          message = (unsigned char *) messageString.data();
        } else {
          auto messageArrayBuffer = arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          messageLength = messageArrayBuffer.length(runtime);
          message = reinterpret_cast<unsigned char *>(messageArrayBuffer.data(runtime));
        }

        if (keyArgType == JsiArgType::string) {
          std::string keyString = arguments[keyArgumentPosition].asString(runtime).utf8(runtime);
          keyLength = keyString.length();
          key = (unsigned char*) keyString.data();
        } else if (keyArgType == JsiArgType::arrayBuffer) {
          auto keyArrayBuffer = arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          keyLength = keyArrayBuffer.length(runtime);
          key = reinterpret_cast<unsigned char *>(keyArrayBuffer.data(runtime));
        } else {
          keyLength = 0;
        }

        std::vector<uint8_t> hash(hashLength);
        int result = -1;

        if (keyLength == 0) {
          result = crypto_generichash(
            hash.data(),
            hashLength,
            message,
            messageLength,
            NULL,
            0);
        } else {
          result = crypto_generichash(
            hash.data(),
            hashLength,
            message,
            messageLength,
            key,
            keyLength);
        }
        throwOnBadResult(functionName, runtime, result);
        return arrayBufferAsObject(runtime, hash);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_generichash", std::move(jsi_crypto_generichash));
}

void cleanUpLibsodium()
{
  // intentionally left blank
}