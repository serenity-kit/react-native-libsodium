// import our header file to implement the `installLibsodium` and `cleanUpLibsodium` functions
#include "./react-native-libsodium.h"
// libsodium
#include <sodium.h>
// useful functions manipulate strings in C++
#include <sstream>
#include <utility>
#include <string>
#include <vector>

// syntactic sugar around the JSI objects. ex. call: jsi::Function
using namespace facebook;

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

void validateIsStringArrayBuffer(const std::string &functionName, jsi::Runtime &runtime, const jsi::Value &argument, std::string &argumentName, bool required)
{
  if (required)
  {
    validateRequired(functionName, runtime, argument, argumentName);
  }
  if (!(argument.isString() || (argument.isObject() &&
                                argument.asObject(runtime).isArrayBuffer(runtime))))
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
        sodium_base642bin((uint8_t *)uint8Vector.data(), uint8Vector.size(), (char *)base64String.data(), base64String.size(), nullptr, &length, nullptr, variant);

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
        const std::string functionName = "jsi_to_base64";

        std::string valueArgumentName = "value";
        unsigned int valueArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments[valueArgumentPosition], valueArgumentName, true);

        std::string variantArgumentName = "variant";
        unsigned int variantArgumentPosition = 1;
        validateIsNumber(functionName, runtime, arguments[variantArgumentPosition], variantArgumentName, true);

        unsigned char *data;
        uint64_t dataLength;
        if (arguments[valueArgumentPosition].isString())
        {
          std::string dataString = arguments[valueArgumentPosition].asString(runtime).utf8(runtime);
          data = (unsigned char *)dataString.data();
          dataLength = dataString.length();
        }
        else
        {
          auto dataArrayBuffer = arguments[valueArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          data = dataArrayBuffer.data(runtime);
          dataLength = dataArrayBuffer.length(runtime);
        }

        uint8_t variant = arguments[variantArgumentPosition].asNumber();

        std::string base64String;
        base64String.resize(sodium_base64_encoded_len(dataLength, variant));
        sodium_bin2base64((char *)base64String.data(), base64String.size(), data, dataLength, variant);

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
        const std::string functionName = "jsi_to_hex";

        std::string valueArgumentName = "value";
        unsigned int valueArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments[valueArgumentPosition], valueArgumentName, true);
        unsigned char *data;
        uint64_t dataLength;
        if (arguments[valueArgumentPosition].isString())
        {
          std::string dataString = arguments[valueArgumentPosition].asString(runtime).utf8(runtime);
          data = (unsigned char *)dataString.data();
          dataLength = dataString.length();
        }
        else
        {
          auto dataArrayBuffer = arguments[valueArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          data = dataArrayBuffer.data(runtime);
          dataLength = dataArrayBuffer.length(runtime);
        }

        std::string hexString;
        hexString.resize(dataLength * 2 + 1);

        sodium_bin2hex((char *)hexString.data(), hexString.length(), data, dataLength);
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
        const std::string functionName = "jsi_randombytes_buf";

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
      jsi::PropNameID::forUtf8(jsiRuntime, "from_base64"),
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
      jsi::PropNameID::forUtf8(jsiRuntime, "from_base64"),
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
      jsi::PropNameID::forUtf8(jsiRuntime, "from_base64"),
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
      jsi::PropNameID::forUtf8(jsiRuntime, "from_base64"),
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
      jsi::PropNameID::forUtf8(jsiRuntime, "from_base64"),
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
        const std::string functionName = "jsi_crypto_sign_detached";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string secretKeyArgumentName = "secretKey";
        unsigned int secretKeyArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[secretKeyArgumentPosition], secretKeyArgumentName, true);

        auto secretKeyDataArrayBuffer =
            arguments[secretKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *secretKey = secretKeyDataArrayBuffer.data(runtime);

        std::vector<uint8_t> sig(crypto_sign_BYTES);
        unsigned char *message;
        uint64_t messageLength;
        if (arguments[messageArgumentPosition].isString())
        {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          message = (unsigned char *)messageString.data();
          messageLength = messageString.length();
        }
        else
        {
          auto messageArrayBuffer = arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          message = messageArrayBuffer.data(runtime);
          messageLength = messageArrayBuffer.length(runtime);
        }

        crypto_sign_detached(sig.data(), NULL, message, messageLength, secretKey);
        return arrayBufferAsObject(runtime, sig);
      });
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_sign_detached", std::move(jsi_crypto_sign_detached));

  auto jsi_crypto_sign_verify_detached = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_sign_verify_detached"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "jsi_crypto_sign_verify_detached";

        std::string signatureArgumentName = "signature";
        unsigned int signatureArgumentPosition = 0;
        validateIsArrayBuffer(functionName, runtime, arguments[signatureArgumentPosition], signatureArgumentName, true);

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 1;
        validateIsStringArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string publicKeyArgumentName = "publicKey";
        unsigned int publicKeyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[publicKeyArgumentPosition], publicKeyArgumentName, true);
        unsigned char *signature;
        if (arguments[signatureArgumentPosition].isString())
        {
          std::string signatureString = arguments[signatureArgumentPosition].asString(runtime).utf8(runtime);
          signature = (unsigned char *)signatureString.data();
        }
        else
        {
          auto signatureArrayBuffer = arguments[signatureArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          signature = signatureArrayBuffer.data(runtime);
        }
        unsigned char *message;
        uint64_t messageLength;
        if (arguments[messageArgumentPosition].isString())
        {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          message = (unsigned char *)messageString.data();
          messageLength = messageString.length();
        }
        else
        {
          auto messageArrayBuffer = arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          message = messageArrayBuffer.data(runtime);
          messageLength = messageArrayBuffer.length(runtime);
        }

        unsigned char *publicKey = (unsigned char *)arguments[publicKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime).data(runtime);

        int result = crypto_sign_verify_detached(signature, message, messageLength, publicKey);

        return jsi::Value(static_cast<bool>(result == 0));
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_sign_verify_detached", std::move(jsi_crypto_sign_verify_detached));

  auto jsi_crypto_secretbox_easy = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_secretbox_easy"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "jsi_crypto_secretbox_easy";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string keyArgumentName = "nonce";
        unsigned int keyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[keyArgumentPosition], keyArgumentName, true);

        unsigned char *message;
        uint64_t messageLength;
        if (arguments[messageArgumentPosition].isString())
        {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          message = (unsigned char *)messageString.data();
          messageLength = messageString.length();
        }
        else
        {
          auto messageArrayBuffer = arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          message = messageArrayBuffer.data(runtime);
          messageLength = messageArrayBuffer.length(runtime);
        }
        unsigned char *nonce = (unsigned char *)arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime).data(runtime);
        unsigned char *key = (unsigned char *)arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime).data(runtime);

        uint64_t ciphertextLength = messageLength + crypto_secretbox_MACBYTES;
        std::vector<uint8_t> ciphertext(ciphertextLength);

        crypto_secretbox_easy(ciphertext.data(), message, messageLength, nonce, key);
        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_easy", std::move(jsi_crypto_secretbox_easy));

  auto jsi_crypto_secretbox_open_easy = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_secretbox_open_easy"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        const std::string functionName = "jsi_crypto_secretbox_open_easy";

        std::string ciphertextArgumentName = "ciphertext";
        unsigned int ciphertextArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments[ciphertextArgumentPosition], ciphertextArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[keyArgumentPosition], keyArgumentName, true);
        unsigned char *ciphertext;
        uint64_t ciphertextLength;
        if (arguments[ciphertextArgumentPosition].isString())
        {
          std::string ciphertextString = arguments[ciphertextArgumentPosition].asString(runtime).utf8(runtime);
          ciphertext = (unsigned char *)ciphertextString.data();
          ciphertextLength = ciphertextString.length();
        }
        else
        {
          auto ciphertextArrayBuffer = arguments[ciphertextArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          ciphertext = ciphertextArrayBuffer.data(runtime);
          ciphertextLength = ciphertextArrayBuffer.length(runtime);
        }
        unsigned char *nonce = (unsigned char *)arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime).data(runtime);
        unsigned char *key = (unsigned char *)arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime).data(runtime);

        uint64_t messageLength = ciphertextLength - crypto_secretbox_MACBYTES;
        std::vector<uint8_t> message(messageLength);

        int result = crypto_secretbox_open_easy(message.data(), ciphertext, ciphertextLength, nonce, key);

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
        const std::string functionName = "jsi_crypto_box_easy";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string publicKeyArgumentName = "publicKey";
        unsigned int publicKeyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[publicKeyArgumentPosition], publicKeyArgumentName, true);

        std::string secretKeyArgumentName = "publicKey";
        unsigned int secretKeyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments[secretKeyArgumentPosition], secretKeyArgumentName, true);

        unsigned char *message;
        uint64_t messageLength;
        if (arguments[messageArgumentPosition].isString())
        {
          std::string messageString = arguments[messageArgumentPosition].asString(runtime).utf8(runtime);
          message = (unsigned char *)messageString.data();
          messageLength = messageString.length();
        }
        else
        {
          auto messageArrayBuffer = arguments[messageArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          message = messageArrayBuffer.data(runtime);
          messageLength = messageArrayBuffer.length(runtime);
        }

        unsigned char *nonce = (unsigned char *)arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime).data(runtime);
        unsigned char *publicKey = (unsigned char *)arguments[publicKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime).data(runtime);
        unsigned char *secretKey = (unsigned char *)arguments[secretKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime).data(runtime);

        uint64_t ciphertextLength = messageLength + crypto_box_MACBYTES;
        std::vector<uint8_t> ciphertext(ciphertextLength);

        int result = crypto_box_easy(ciphertext.data(), message, messageLength, nonce, publicKey, secretKey);

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
        const std::string functionName = "jsi_crypto_box_open_easy";

        std::string ciphertextArgumentName = "ciphertext";
        unsigned int ciphertextArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments[ciphertextArgumentPosition], ciphertextArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string publicKeyArgumentName = "publicKey";
        unsigned int publicKeyArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[publicKeyArgumentPosition], publicKeyArgumentName, true);

        std::string secretKeyArgumentName = "secretKey";
        unsigned int secretKeyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments[secretKeyArgumentPosition], secretKeyArgumentName, true);

        unsigned char *ciphertext;
        uint64_t ciphertextLength;
        if (arguments[ciphertextArgumentPosition].isString())
        {
          std::string ciphertextString = arguments[ciphertextArgumentPosition].asString(runtime).utf8(runtime);
          ciphertext = (unsigned char *)ciphertextString.data();
          ciphertextLength = ciphertextString.length();
        }
        else
        {
          auto ciphertextArrayBuffer = arguments[ciphertextArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          ciphertext = ciphertextArrayBuffer.data(runtime);
          ciphertextLength = ciphertextArrayBuffer.length(runtime);
        }
        auto nonceDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto publicKeyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *publicKey = publicKeyDataArrayBuffer.data(runtime);

        auto secretKeyDataArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *secretKey = secretKeyDataArrayBuffer.data(runtime);

        uint64_t message_length = ciphertextLength - crypto_box_MACBYTES;
        std::vector<uint8_t> message(message_length);

        int result = crypto_box_open_easy(message.data(), ciphertext, ciphertextLength, nonce, publicKey, secretKey);

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
        const std::string functionName = "jsi_crypto_pwhash";

        std::string keyLengthArgumentName = "keyLength";
        unsigned int keyLengthArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments[keyLengthArgumentPosition], keyLengthArgumentName, true);

        std::string passwordArgumentName = "password";
        unsigned int passwordArgumentPosition = 1;
        validateIsStringArrayBuffer(functionName, runtime, arguments[passwordArgumentPosition], passwordArgumentName, true);

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

        const unsigned int position = passwordArgumentPosition;
        unsigned char *password;
        uint64_t passwordLength;
        if (arguments[position].isString())
        {
          std::string dataString = arguments[position].asString(runtime).utf8(runtime);
          password = (unsigned char *)dataString.data();
          passwordLength = dataString.length();
        }
        else
        {
          auto dataArrayBuffer =
              arguments[position].asObject(runtime).getArrayBuffer(runtime);
          password = dataArrayBuffer.data(runtime);
          passwordLength = dataArrayBuffer.length(runtime);
        }

        auto saltDataArrayBuffer =
            arguments[saltArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *salt = saltDataArrayBuffer.data(runtime);

        int opsLimit = arguments[opsLimitArgumentPosition].asNumber();
        int memLimit = arguments[memLimitArgumentPosition].asNumber();
        int algorithm = arguments[algorithmArgumentPosition].asNumber();

        std::vector<uint8_t> key(keyLength);

        int result = crypto_pwhash(key.data(), keyLength, (const char *)password, passwordLength, salt, opsLimit, memLimit, algorithm);

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
        const std::string functionName = "jsi_crypto_kdf_derive_from_key";

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
        validateIsStringArrayBuffer(functionName, runtime, arguments[masterKeyArgumentPosition], masterKeyArgumentName, true);

        int subkeyLength = arguments[subkeyLengthArgumentPosition].asNumber();
        int subkeyId = arguments[subkeyIdArgumentPosition].asNumber();
        std::string context = arguments[contextArgumentPosition].asString(runtime).utf8(runtime);

        unsigned char *masterKey;
        if (arguments[masterKeyArgumentPosition].isString())
        {
          std::string masterKeyString = arguments[masterKeyArgumentPosition].asString(runtime).utf8(runtime);
          masterKey = (unsigned char *)masterKeyString.data();
        }
        else
        {
          auto masterKeyArrayBuffer = arguments[masterKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
          masterKey = masterKeyArrayBuffer.data(runtime);
        }

        std::vector<uint8_t> subkey(subkeyLength);

        int result = crypto_kdf_derive_from_key(subkey.data(), subkeyLength, subkeyId, (char *)context.data(), masterKey);

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
        const std::string functionName = "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments[messageArgumentPosition], messageArgumentName, true);

        std::string additionalDataArgumentName = "additionalData";
        unsigned int additionalDataArgumentPosition = 1;
        validateIsString(functionName, runtime, arguments[additionalDataArgumentPosition], additionalDataArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments[keyArgumentPosition], keyArgumentName, true);

        const unsigned int position = messageArgumentPosition;
        unsigned char *message;
        uint64_t messageLength;
        if (arguments[position].isString())
        {
          std::string dataString = arguments[position].asString(runtime).utf8(runtime);
          message = (unsigned char *)dataString.data();
          messageLength = dataString.length();
        }
        else
        {
          auto dataArrayBuffer =
              arguments[position].asObject(runtime).getArrayBuffer(runtime);
          message = dataArrayBuffer.data(runtime);
          messageLength = dataArrayBuffer.length(runtime);
        }

        std::string additionalData = arguments[additionalDataArgumentPosition].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        uint64_t ciphertextLength = messageLength + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        std::vector<uint8_t> ciphertext(ciphertextLength);

        int result = crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertextLength, message, messageLength, (unsigned char *)additionalData.data(), additionalData.length(), NULL, nonce, key);

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
        const std::string functionName = "jsi_crypto_aead_xchacha20poly1305_ietf_decrypt";

        std::string ciphertextArgumentName = "ciphertext";
        unsigned int ciphertextArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments[ciphertextArgumentPosition], ciphertextArgumentName, true);

        std::string additionalDataArgumentName = "additionalData";
        unsigned int additionalDataArgumentPosition = 1;
        validateIsString(functionName, runtime, arguments[additionalDataArgumentPosition], additionalDataArgumentName, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments[nonceArgumentPosition], nonceArgumentName, true);

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments[keyArgumentPosition], keyArgumentName, true);

        const unsigned int position = ciphertextArgumentPosition;
        unsigned char *ciphertext;
        uint64_t ciphertextLength;
        if (arguments[position].isString())
        {
          std::string dataString = arguments[position].asString(runtime).utf8(runtime);
          ciphertext = (unsigned char *)dataString.data();
          ciphertextLength = dataString.length();
        }
        else
        {
          auto dataArrayBuffer =
              arguments[position].asObject(runtime).getArrayBuffer(runtime);
          ciphertext = dataArrayBuffer.data(runtime);
          ciphertextLength = dataArrayBuffer.length(runtime);
        }

        std::string additionalData = arguments[additionalDataArgumentPosition].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        uint64_t messageLength = ciphertextLength - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        std::vector<uint8_t> message(messageLength);

        int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
          message.data(),
          &messageLength,
          NULL,
          ciphertext,
          ciphertextLength,
          (unsigned char *)additionalData.data(),
          additionalData.length(),
          nonce,
          key);

        throwOnBadResult(functionName, runtime, result);
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_decrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_decrypt));
}

void cleanUpLibsodium()
{
  // intentionally left blank
}