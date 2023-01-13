// import our header file to implement the `installLibsodium` and `cleanUpLibsodium` functions
#include "react-native-libsodium.h"
// useful functions manipulate strings in C++
#include <sstream>
// libsodium
#include "sodium.h"

// syntactic sugar around the JSI objects. ex. call: jsi::Function
using namespace facebook;

// Convert an array buffer to a JavaScript object
jsi::Object arrayBufferAsObject (jsi::Runtime &runtime, std::vector<uint8_t> &data) {
  jsi::Object returnBufferAsObject = runtime.global()
   .getPropertyAsFunction(runtime, "ArrayBuffer")
   .callAsConstructor(runtime, (int)data.size())
   .asObject(runtime);
  jsi::ArrayBuffer arraybuffer = returnBufferAsObject.getArrayBuffer(runtime);
  memcpy(arraybuffer.data(runtime), data.data(), data.size());
  return returnBufferAsObject;
}

void validateRequired (std::string &functionName, jsi::Runtime &runtime, const jsi::Value *arguments, size_t count, std::string &argumentName, unsigned int position) {
  if (position >= count) {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] insufficient parameters passed into function";
    throw jsi::JSError(runtime, errorMessage);
  }
  if (arguments[position].isNull())
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " can't be null";
    throw jsi::JSError(runtime, errorMessage);
  }
}

void validateIsString (std::string &functionName, jsi::Runtime &runtime, const jsi::Value *arguments, size_t count, std::string &argumentName, unsigned int position, bool required) {
  if (position >= count) {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] insufficient parameters passed into function";
    throw jsi::JSError(runtime, errorMessage);
  }
  if (required) {
    validateRequired(functionName, runtime, arguments, count, argumentName, position);
  }
  if (!arguments[position].isString())
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " must be an ArrayBuffer";
    throw jsi::JSError(runtime, errorMessage);
  }
}

void validateIsArrayBuffer (std::string &functionName, jsi::Runtime &runtime, const jsi::Value *arguments, size_t count, std::string &argumentName, unsigned int position, bool required) {
  if (position >= count) {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] insufficient parameters passed into function";
    throw jsi::JSError(runtime, errorMessage);
  }
  if (required) {
    validateRequired(functionName, runtime, arguments, count, argumentName, position);
  }
  if (!arguments[position].isObject() ||
      !arguments[position].asObject(runtime).isArrayBuffer(runtime))
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " must be an ArrayBuffer";
    throw jsi::JSError(runtime, errorMessage);
  }
}

void validateIsStringArrayBuffer (std::string &functionName, jsi::Runtime &runtime, const jsi::Value *arguments, size_t count, std::string &argumentName, unsigned int position, bool required) {
  if (position >= count) {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] insufficient parameters passed into function";
    throw jsi::JSError(runtime, errorMessage);
  }
  if (required) {
    validateRequired(functionName, runtime, arguments, count, argumentName, position);
  }
  if (!(arguments[position].isString() || (arguments[position].isObject() &&
                                    arguments[position].asObject(runtime).isArrayBuffer(runtime))))
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " must be a string or an ArrayBuffer";
    throw jsi::JSError(runtime, errorMessage);
  }
}

void validateIsNumber ( std::string &functionName, jsi::Runtime &runtime, const jsi::Value *arguments, size_t count, std::string &argumentName, unsigned int position, bool required) {
  if (position >= count) {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] insufficient parameters passed into function";
    throw jsi::JSError(runtime, errorMessage);
  }
  if (required) {
    validateRequired(functionName, runtime, arguments, count, argumentName, position);
  }
  if (!arguments[position].isNumber())
  {
    std::string errorMessage = "[react-native-libsodium][" + functionName + "] " + argumentName + " must be a number";
    throw jsi::JSError(runtime, errorMessage);
  }
}


// Get the string value of a function argument. Argument may be a string or Uint8Array
unsigned char* argAsString (jsi::Runtime &runtime, const jsi::Value *arguments, size_t count, unsigned int position) {
  unsigned char *message;
  if (arguments[position].isString())
  {
    std::string messageString = arguments[position].asString(runtime).utf8(runtime);
    message = (unsigned char *)messageString.data();
  }
  else
  {
    auto messageDataArrayBuffer =
        arguments[position].asObject(runtime).getArrayBuffer(runtime);
    message = messageDataArrayBuffer.data(runtime);
  }
  return message;
}

// Get the char[] length of a function argument. Argument may be a string or Uint8Array
unsigned long long argLength (jsi::Runtime &runtime, const jsi::Value *arguments, size_t count, unsigned int position) {
  unsigned long long messageLength;
  if (arguments[position].isString())
  {
    std::string messageString = arguments[position].asString(runtime).utf8(runtime);
    messageLength = messageString.length();
  }
  else
  {
    auto messageDataArrayBuffer =
        arguments[position].asObject(runtime).getArrayBuffer(runtime);
    messageLength = messageDataArrayBuffer.length(runtime);
  }
  return messageLength;
}


// get the runtime and create native functions
void installLibsodium(jsi::Runtime &jsiRuntime)
{
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_KEYBYTES", (int)crypto_secretbox_KEYBYTES);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_NONCEBYTES", (int)crypto_secretbox_NONCEBYTES);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_SALTBYTES", (int)crypto_pwhash_SALTBYTES);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_ALG_DEFAULT", (int)crypto_pwhash_ALG_DEFAULT);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_OPSLIMIT_INTERACTIVE", (int)crypto_pwhash_OPSLIMIT_INTERACTIVE);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_MEMLIMIT_INTERACTIVE", (int)crypto_pwhash_MEMLIMIT_INTERACTIVE);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_PUBLICKEYBYTES", (int)crypto_box_PUBLICKEYBYTES);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_SECRETKEYBYTES", (int)crypto_box_SECRETKEYBYTES);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_NONCEBYTES", (int)crypto_box_NONCEBYTES);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_KEYBYTES", (int)crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", (int)crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_kdf_KEYBYTES", (int)crypto_kdf_KEYBYTES);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_BYTES_MAX", (int)crypto_pwhash_BYTES_MAX);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_BYTES_MIN", (int)crypto_pwhash_BYTES_MIN);
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_kdf_CONTEXTBYTES", (int)crypto_kdf_CONTEXTBYTES);

  auto jsi_from_base64_to_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "from_base64"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "from_base64";

        std::string valueArgumentName = "value";
        unsigned int valueArgumentPosition = 0;
        validateRequired(functionName, runtime, arguments, count, valueArgumentName, valueArgumentPosition);

        std::string variantArgumentName = "variant";
        unsigned int variantArgumentPosition = 1;
        validateRequired(functionName, runtime, arguments, count, variantArgumentName, variantArgumentPosition);

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

  auto jsi_to_base64_from_string = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_to_base64_from_string"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_to_base64_from_string";

        std::string valueArgumentName = "value";
        unsigned int valueArgumentPosition = 0;
        validateIsString(functionName, runtime, arguments, count, valueArgumentName, valueArgumentPosition, true);

        std::string variantArgumentName = "variant";
        unsigned int variantArgumentPosition = 1;
        validateRequired(functionName, runtime, arguments, count, variantArgumentName, variantArgumentPosition);

        std::string utf8String = arguments[0].asString(runtime).utf8(runtime);
        uint8_t variant = arguments[1].asNumber();

        std::string base64String;
        base64String.resize(sodium_base64_encoded_len(utf8String.size(), variant));
        sodium_bin2base64((char *)base64String.data(), base64String.size(), (uint8_t *)utf8String.data(), utf8String.size(), variant);

        // libsodium adds a nul byte (\0) terminator to the end of the string
        if (base64String.length() && base64String[base64String.length() - 1] == '\0')
        {
          base64String.pop_back();
        }

        return jsi::String::createFromUtf8(runtime, base64String);
      });
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_to_base64_from_string", std::move(jsi_to_base64_from_string));

  auto jsi_to_base64_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_to_base64_from_arraybuffer"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_to_base64_from_arraybuffer";

        std::string valueArgumentName = "value";
        unsigned int valueArgumentPosition = 0;
        validateIsArrayBuffer(functionName, runtime, arguments, count, valueArgumentName, valueArgumentPosition, true);
        
        std::string variantArgumentName = "variant";
        unsigned int variantArgummentPosition = 1;
        validateIsNumber(functionName, runtime, arguments, count, variantArgumentName, variantArgummentPosition, true);

        auto dataArrayBuffer =
            arguments[valueArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *data = dataArrayBuffer.data(runtime);
        auto dataLength = dataArrayBuffer.length(runtime);

        uint8_t variant = arguments[variantArgummentPosition].asNumber();

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

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_to_base64_from_arraybuffer", std::move(jsi_to_base64_from_arraybuffer));

  auto jsi_to_hex = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_to_hex"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_to_hex";

        std::string valueArgumentName = "value";
        unsigned int valueArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, valueArgumentName, valueArgumentPosition, true);

        unsigned char *data = argAsString(runtime, arguments, count, valueArgumentPosition);
        unsigned long long dataLength = argLength(runtime, arguments, count, valueArgumentPosition);

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
        std::string functionName = "jsi_randombytes_buf";

        std::string sizeArgumentName = "size";
        unsigned int sizeArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments, count, sizeArgumentName, sizeArgumentPosition, true);

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
        std::string functionName = "randombytes_uniform";

        std::string upperBoundArgumentName = "upper_bound";
        unsigned int upperBoundArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments, count, upperBoundArgumentName, upperBoundArgumentPosition, true);

        int upperBound = arguments[0].asNumber();
        return jsi::Value((int)randombytes_uniform(upperBound));
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
        unsigned long long publickeyLength = crypto_box_PUBLICKEYBYTES;
        unsigned long long secretkeyLength = crypto_box_SECRETKEYBYTES;
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
        unsigned long long publickeyLength = crypto_sign_PUBLICKEYBYTES;
        unsigned long long secretkeyLength = crypto_sign_SECRETKEYBYTES;
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
        std::string functionName = "jsi_crypto_sign_detached";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, messageArgumentName, messageArgumentPosition, true);

        std::string secretKeyArgumentName = "secretKey";
        unsigned int secretKeyArgumentPosition = 1;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, secretKeyArgumentName, secretKeyArgumentPosition, true);

        auto secretKeyDataArrayBuffer =
            arguments[secretKeyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *secretKey = secretKeyDataArrayBuffer.data(runtime);

        std::vector<uint8_t> sig(crypto_sign_BYTES);

        unsigned char *message = argAsString(runtime, arguments, count, messageArgumentPosition);
        unsigned long long messageLength = argLength(runtime, arguments, count, messageArgumentPosition);

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
        std::string functionName = "jsi_crypto_sign_verify_detached";

        std::string signatureArgumentName = "signature";
        unsigned int signatureArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, signatureArgumentName, signatureArgumentPosition, true);

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 1;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, messageArgumentName, messageArgumentPosition, true);

        std::string publicKeyArgumentName = "publicKey";
        unsigned int publicKeyArgumentPosition = 2;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, publicKeyArgumentName, publicKeyArgumentPosition, true);

        unsigned char *signature = argAsString(runtime, arguments, count, signatureArgumentPosition);
        unsigned char *message = argAsString(runtime, arguments, count, messageArgumentPosition);
        unsigned long long messageLength = argLength(runtime, arguments, count, messageArgumentPosition);
        unsigned char *publicKey = argAsString(runtime, arguments, count, publicKeyArgumentPosition);

        int result = crypto_sign_verify_detached(signature, message, messageLength, publicKey);

        return jsi::Value(bool(result == 0));
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_sign_verify_detached", std::move(jsi_crypto_sign_verify_detached));

  auto jsi_crypto_secretbox_easy = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_secretbox_easy"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_crypto_secretbox_easy";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, messageArgumentName, messageArgumentPosition, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, nonceArgumentName, nonceArgumentPosition, true);

        std::string keyArgumentName = "nonce";
        unsigned int keyArgumentPosition = 2;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, keyArgumentName, keyArgumentPosition, true);

        unsigned char *message = argAsString(runtime, arguments, count, messageArgumentPosition);
        unsigned long long messageLength = argLength(runtime, arguments, count, messageArgumentPosition);
        unsigned char *nonce = argAsString(runtime, arguments, count, nonceArgumentPosition);
        unsigned char *key = argAsString(runtime, arguments, count, keyArgumentPosition);

        unsigned long long ciphertextLength = messageLength + crypto_secretbox_MACBYTES;
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
        std::string functionName = "jsi_crypto_secretbox_open_easy";

        std::string ciphertextArgumentName = "ciphertext";
        unsigned int ciphertextArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, ciphertextArgumentName, ciphertextArgumentPosition, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, nonceArgumentName, nonceArgumentPosition, true);

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 2;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, keyArgumentName, keyArgumentPosition, true);

        unsigned char *ciphertext = argAsString(runtime, arguments, count, ciphertextArgumentPosition);
        unsigned long long ciphertextLength = argLength(runtime, arguments, count, ciphertextArgumentPosition);
        unsigned char *nonce = argAsString(runtime, arguments, count, nonceArgumentPosition);
        unsigned char *key = argAsString(runtime, arguments, count, keyArgumentPosition);

        unsigned long long messageLength = ciphertextLength - crypto_secretbox_MACBYTES;
        std::vector<uint8_t> message(messageLength);

        int result = crypto_secretbox_open_easy(message.data(), ciphertext, ciphertextLength, nonce, key);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy] jsi_crypto_secretbox_open_easy failed");
        }
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_open_easy", std::move(jsi_crypto_secretbox_open_easy));

  auto jsi_crypto_box_easy = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_box_easy"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_crypto_box_easy";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, messageArgumentName, messageArgumentPosition, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, nonceArgumentName, nonceArgumentPosition, true);

        std::string publicKeyArgumentName = "publicKey";
        unsigned int publicKeyArgumentPosition = 2;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, publicKeyArgumentName, publicKeyArgumentPosition, true);

        std::string secretKeyArgumentName = "secretKey";
        unsigned int secretKeyArgumentPosition = 3;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, secretKeyArgumentName, secretKeyArgumentPosition, true);

        unsigned char *message = argAsString(runtime, arguments, count, messageArgumentPosition);
        unsigned long long messageLength = argLength(runtime, arguments, count, 0);
        unsigned char *nonce = argAsString(runtime, arguments, count, nonceArgumentPosition);
        unsigned char *publicKey = argAsString(runtime, arguments, count, publicKeyArgumentPosition);
        unsigned char *secretKey = argAsString(runtime, arguments, count, secretKeyArgumentPosition);

        unsigned long long ciphertextLength = messageLength + crypto_box_MACBYTES;
        std::vector<uint8_t> ciphertext(ciphertextLength);

        int result = crypto_box_easy(ciphertext.data(), message, messageLength, nonce, publicKey, secretKey);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy] jsi_crypto_box_easy failed");
        }
        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_easy", std::move(jsi_crypto_box_easy));

  auto jsi_crypto_box_open_easy = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_box_open_easy"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_crypto_box_easy";

        std::string ciphertextArgumentName = "ciphertext";
        unsigned int ciphertextArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, ciphertextArgumentName, ciphertextArgumentPosition, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 1;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, nonceArgumentName, nonceArgumentPosition, true);

        std::string publicKeyArgumentName = "publicKey";
        unsigned int publicKeyArgumentPosition = 2;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, publicKeyArgumentName, publicKeyArgumentPosition, true);

        std::string secretKeyArgumentName = "secretKey";
        unsigned int secretKeyArgumentPosition = 3;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, secretKeyArgumentName, secretKeyArgumentPosition, true);

        unsigned char *ciphertext = argAsString(runtime, arguments, count, ciphertextArgumentPosition);
        unsigned long long ciphertextLength = argLength(runtime, arguments, count, ciphertextArgumentPosition);
        unsigned char *nonce = argAsString(runtime, arguments, count, nonceArgumentPosition);
        unsigned char *publicKey = argAsString(runtime, arguments, count, publicKeyArgumentPosition);
        unsigned char *secretKey = argAsString(runtime, arguments, count, secretKeyArgumentPosition);

        unsigned long long messageLength = ciphertextLength - crypto_box_MACBYTES;
        std::vector<uint8_t> message(messageLength);

        int result = crypto_box_open_easy(message.data(), ciphertext, ciphertextLength, nonce, publicKey, secretKey);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy] jsi_crypto_box_open_easy failed");
        }
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_open_easy", std::move(jsi_crypto_box_open_easy));

  auto jsi_crypto_pwhash = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_pwhash"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_crypto_pwhash";

        std::string keyLengthArgumentName = "keyLength";
        unsigned int keyLengthArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments, count, keyLengthArgumentName, keyLengthArgumentPosition, true);
        
        std::string passwordArgumentName = "password";
        unsigned int passwordArgumentPosition = 1;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, passwordArgumentName, passwordArgumentPosition, true);

        std::string saltArgumentName = "salt";
        unsigned int saltArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments, count, saltArgumentName, saltArgumentPosition, true);

        std::string opsLimitArgumentName = "opsLimit";
        unsigned int opsLimitArgumentPosition = 3;
        validateIsNumber(functionName, runtime, arguments, count, opsLimitArgumentName, opsLimitArgumentPosition, true);
        
        std::string memLimitArgumentName = "memLimit";
        unsigned int memLimitArgumentPosition = 4;
        validateIsNumber(functionName, runtime, arguments, count, memLimitArgumentName, memLimitArgumentPosition, true);
        
        std::string algorithmArgumentName = "algorithm";
        unsigned int algorithmArgumentPosition = 5;
        validateIsNumber(functionName, runtime, arguments, count, algorithmArgumentName, algorithmArgumentPosition, true);

        int keyLength = arguments[keyLengthArgumentPosition].asNumber();

        unsigned char *password;
        unsigned long long passwordLength;
        if (arguments[passwordArgumentPosition].isString())
        {
          std::string passwordString = arguments[passwordArgumentPosition].asString(runtime).utf8(runtime);
          password = (unsigned char *)passwordString.data();
          passwordLength = passwordString.length();
        } else {
          auto passwordDataArrayBuffer =
              arguments[passwordArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
           password = passwordDataArrayBuffer.data(runtime);
           passwordLength = passwordDataArrayBuffer.length(runtime);
        }
        auto saltDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *salt = saltDataArrayBuffer.data(runtime);

        int opsLimit = arguments[opsLimitArgumentPosition].asNumber();
        int memLimit = arguments[memLimitArgumentPosition].asNumber();
        int algorithm = arguments[algorithmArgumentPosition].asNumber();

        std::vector<uint8_t> key(keyLength);

        int result = crypto_pwhash(key.data(), keyLength, (const char *)password, passwordLength, salt, opsLimit, memLimit, algorithm);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash] jsi_crypto_pwhash failed");
        }
        return arrayBufferAsObject(runtime, key);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash", std::move(jsi_crypto_pwhash));

  auto jsi_crypto_kdf_derive_from_key = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_kdf_derive_from_key"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_crypto_kdf_derive_from_key";

        std::string subkeyLengthArgumentName = "subkeyLength";
        unsigned int subkeyLengthArgumentPosition = 0;
        validateIsNumber(functionName, runtime, arguments, count, subkeyLengthArgumentName, subkeyLengthArgumentPosition, true);
        
        std::string subkeyIdArgumentName = "subkeyId";
        unsigned int subkeyIdArgumentPosition = 1;
        validateIsNumber(functionName, runtime, arguments, count, subkeyIdArgumentName, subkeyIdArgumentPosition, true);

        std::string contextArgumentName = "context";
        unsigned int contextArgumentPosition = 2;
        validateIsString(functionName, runtime, arguments, count, contextArgumentName, contextArgumentPosition, true);

        std::string masterKeyArgumentName = "masterKey";
        unsigned int masterKeyArgumentPosition = 3;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, masterKeyArgumentName, masterKeyArgumentPosition, true);

        int subkeyLength = arguments[subkeyLengthArgumentPosition].asNumber();
        int subkeyId = arguments[subkeyIdArgumentPosition].asNumber();
        std::string context = arguments[contextArgumentPosition].asString(runtime).utf8(runtime);

        unsigned char *masterKey = argAsString(runtime, arguments, count, masterKeyArgumentPosition);

        std::vector<uint8_t> subkey(subkeyLength);

        int result = crypto_kdf_derive_from_key(subkey.data(), subkeyLength, subkeyId, (char *)context.data(), masterKey);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_kdf_derive_from_key] jsi_crypto_kdf_derive_from_key failed");
        }
        return arrayBufferAsObject(runtime, subkey);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_kdf_derive_from_key", std::move(jsi_crypto_kdf_derive_from_key));

  auto jsi_crypto_aead_xchacha20poly1305_ietf_encrypt = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt";

        std::string messageArgumentName = "message";
        unsigned int messageArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, messageArgumentName, messageArgumentPosition, true);

        std::string additionalDataArgumentName = "additionalData";
        unsigned int additionalDataArgumentPosition = 1;
        validateIsString(functionName, runtime, arguments, count, additionalDataArgumentName, additionalDataArgumentPosition, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments, count, nonceArgumentName, nonceArgumentPosition, true);

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments, count, keyArgumentName, keyArgumentPosition, true);

        unsigned char *message = argAsString(runtime, arguments, count, messageArgumentPosition);
        unsigned long long messageLength = argLength(runtime, arguments, count, messageArgumentPosition);

        std::string additionalData = arguments[additionalDataArgumentPosition].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        unsigned long long ciphertextLength = messageLength + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        std::vector<uint8_t> ciphertext(ciphertextLength);

        int result = crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertextLength, message, messageLength, (unsigned char *)additionalData.data(), additionalData.length(), NULL, nonce, key);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt] crypto_aead_xchacha20poly1305_ietf_encrypt failed");
        }
        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_encrypt));

  auto jsi_crypto_aead_xchacha20poly1305_ietf_decrypt = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_decrypt"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        std::string functionName = "jsi_crypto_aead_xchacha20poly1305_ietf_decrypt";

        std::string ciphertextArgumentName = "ciphertext";
        unsigned int ciphertextArgumentPosition = 0;
        validateIsStringArrayBuffer(functionName, runtime, arguments, count, ciphertextArgumentName, ciphertextArgumentPosition, true);

        std::string additionalDataArgumentName = "additionalData";
        unsigned int additionalDataArgumentPosition = 1;
        validateIsString(functionName, runtime, arguments, count, additionalDataArgumentName, additionalDataArgumentPosition, true);

        std::string nonceArgumentName = "nonce";
        unsigned int nonceArgumentPosition = 2;
        validateIsArrayBuffer(functionName, runtime, arguments, count, nonceArgumentName, nonceArgumentPosition, true);

        std::string keyArgumentName = "key";
        unsigned int keyArgumentPosition = 3;
        validateIsArrayBuffer(functionName, runtime, arguments, count, keyArgumentName, keyArgumentPosition, true);

        unsigned char *ciphertext = argAsString(runtime, arguments, count, ciphertextArgumentPosition);
        unsigned long long ciphertextLength = argLength(runtime, arguments, count, ciphertextArgumentPosition);

        std::string additionalData = arguments[additionalDataArgumentPosition].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[nonceArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[keyArgumentPosition].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        unsigned long long messageLength = ciphertextLength - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        std::vector<uint8_t> message(messageLength);

        int result = crypto_aead_xchacha20poly1305_ietf_decrypt(message.data(), &messageLength, NULL, ciphertext, ciphertextLength, (unsigned char *)additionalData.data(), additionalData.length(), nonce, key);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt] jsi_crypto_aead_xchacha20poly1305_ietf_decrypt failed");
        }
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_decrypt", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_decrypt));
}

void cleanUpLibsodium()
{
  // intentionally left blank
}