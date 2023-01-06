// import our header file to implement the `installLibsodium` and `cleanUpLibsodium` functions
#include "react-native-libsodium.h"
// useful functions manipulate strings in C++
#include <sstream>
// libsodium
#include "sodium.h"

// syntactic sugar around the JSI objects. ex. call: jsi::Function
using namespace facebook;

jsi::Object arrayBufferAsObject (jsi::Runtime &runtime, std::vector<uint8_t> &data) {
  jsi::Object returnBufferAsObject = runtime.global()
   .getPropertyAsFunction(runtime, "ArrayBuffer")
   .callAsConstructor(runtime, (int)data.size())
   .asObject(runtime);
  jsi::ArrayBuffer arraybuffer = returnBufferAsObject.getArrayBuffer(runtime);
  memcpy(arraybuffer.data(runtime), data.data(), data.size());
  return returnBufferAsObject;
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
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_from_base64_to_arraybuffer] value can't be null");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_from_base64_to_arraybuffer] variant can't be null");
        }

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
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_to_base64_from_string] value can't be null");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_to_base64_from_string] variant can't be null");
        }

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
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_to_base64_from_arraybuffer] value can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_to_base64_from_arraybuffer] value must be an ArrayBuffer");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_to_base64_from_arraybuffer] variant can't be null");
        }

        auto dataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *data = dataArrayBuffer.data(runtime);
        auto dataLength = dataArrayBuffer.length(runtime);

        uint8_t variant = arguments[1].asNumber();

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

  auto jsi_to_hex_from_string = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_to_hex_from_string"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_to_hex_from_string] value can't be null");
        }

        std::string utf8String = arguments[0].asString(runtime).utf8(runtime);
        std::string hexString;
        hexString.resize(utf8String.size() * 2 + 1);
        sodium_bin2hex((char *)hexString.data(), hexString.size(), (uint8_t *)utf8String.data(), utf8String.size());
        // libsodium adds a nul byte (\0) terminator to the end of the string
        if (hexString.length() && hexString[hexString.length() - 1] == '\0')
        {
          hexString.pop_back();
        }

        return jsi::String::createFromUtf8(runtime, hexString);
      });
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_to_hex_from_string", std::move(jsi_to_hex_from_string));

  auto jsi_to_hex_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_to_hex_from_arraybuffer"),
      2,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_to_hex_from_arraybuffer] value can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_to_hex_from_arraybuffer] value must be an ArrayBuffer");
        }

        auto dataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *data = dataArrayBuffer.data(runtime);
        auto dataLength = dataArrayBuffer.length(runtime);

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

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_to_hex_from_arraybuffer", std::move(jsi_to_hex_from_arraybuffer));

  auto jsi_randombytes_buf = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_randombytes_buf"),
      1,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_randombytes_buf] size can't be null");
        }

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
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][randombytes_uniform] upper_bound can't be null");
        }

        int upper_bound = arguments[0].asNumber();
        return jsi::Value((int)randombytes_uniform(upper_bound));
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
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_detached] message can't be null");
        }
        if (!(arguments[0].isString() || (arguments[0].isObject() &&
                                          arguments[0].asObject(runtime).isArrayBuffer(runtime))))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_detached] message must be a string or an ArrayBuffer");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_detached] secretKey can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_detached] secretKey must be an ArrayBuffer");
        }

        auto secretKeyDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *secretKey = secretKeyDataArrayBuffer.data(runtime);

        std::vector<uint8_t> sig(crypto_sign_BYTES);

        unsigned char *message;
        unsigned long long messageLength;
        if (arguments[0].isString())
        {
          std::string messageString = arguments[0].asString(runtime).utf8(runtime);
          message = (unsigned char *)messageString.data();
          messageLength = messageString.length();
        }
        else
        {
          auto messageDataArrayBuffer =
              arguments[0].asObject(runtime).getArrayBuffer(runtime);
          message = messageDataArrayBuffer.data(runtime);
          messageLength = messageDataArrayBuffer.length(runtime);
        }

        crypto_sign_detached(sig.data(), NULL, message, messageLength, secretKey);
        return arrayBufferAsObject(runtime, sig);
      });
  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_sign_detached", std::move(jsi_crypto_sign_detached));

  auto jsi_crypto_sign_verify_detached_from_string = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_sign_verify_detached_from_string"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_string] signature can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_string] signature must be an ArrayBuffer");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_string] message can't be null");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_string] publicKey can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_string] publicKey must be an ArrayBuffer");
        }

        auto signatureDataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *signature = signatureDataArrayBuffer.data(runtime);

        std::string utf8String = arguments[1].asString(runtime).utf8(runtime);

        auto publicKeyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *publicKey = publicKeyDataArrayBuffer.data(runtime);

        int result = crypto_sign_verify_detached(signature, (uint8_t *)utf8String.data(), utf8String.length(), publicKey);

        return jsi::Value(bool(result == 0));
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_sign_verify_detached_from_string", std::move(jsi_crypto_sign_verify_detached_from_string));

  auto jsi_crypto_sign_verify_detached_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_sign_verify_detached_from_arraybuffer"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_arraybuffer] signature can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_arraybuffer] signature must be an ArrayBuffer");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_arraybuffer] message can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_arraybuffer] message must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_arraybuffer] publicKey can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_sign_verify_detached_from_arraybuffer] publicKey must be an ArrayBuffer");
        }

        auto signatureDataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *signature = signatureDataArrayBuffer.data(runtime);

        auto messageDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *message = messageDataArrayBuffer.data(runtime);

        auto publicKeyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *publicKey = publicKeyDataArrayBuffer.data(runtime);

        int result = crypto_sign_verify_detached(signature, message, messageDataArrayBuffer.length(runtime), publicKey);

        return jsi::Value(bool(result == 0));
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_sign_verify_detached_from_arraybuffer", std::move(jsi_crypto_sign_verify_detached_from_arraybuffer));

  auto jsi_crypto_secretbox_easy_from_string = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_secretbox_easy_from_string"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_string] message can't be null");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_string] nonce can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_string] nonce must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_string] key can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_string] key must be an ArrayBuffer");
        }

        std::string utf8String = arguments[0].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        unsigned long long ciphertextLength = utf8String.length() + crypto_secretbox_MACBYTES;
        std::vector<uint8_t> ciphertext(ciphertextLength);

        crypto_secretbox_easy(ciphertext.data(), (uint8_t *)utf8String.data(), utf8String.length(), nonce, key);
        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_easy_from_string", std::move(jsi_crypto_secretbox_easy_from_string));

  auto jsi_crypto_secretbox_easy_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_secretbox_easy_from_arraybuffer"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_arraybuffer] message can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_arraybuffer] message must be an ArrayBuffer");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_arraybuffer] nonce can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_arraybuffer] nonce must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_arraybuffer] key can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_easy_from_arraybuffer] key must be an ArrayBuffer");
        }

        auto messageDataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *message = messageDataArrayBuffer.data(runtime);

        auto nonceDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        unsigned long long ciphertextLength = messageDataArrayBuffer.length(runtime) + crypto_secretbox_MACBYTES;
        std::vector<uint8_t> ciphertext(ciphertextLength);

        crypto_secretbox_easy(ciphertext.data(), message, messageDataArrayBuffer.length(runtime), nonce, key);
        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_easy_from_arraybuffer", std::move(jsi_crypto_secretbox_easy_from_arraybuffer));

  auto jsi_crypto_secretbox_open_easy_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_secretbox_open_easy_from_arraybuffer"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_arraybuffer] ciphertext can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_arraybuffer] ciphertext must be an ArrayBuffer");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_arraybuffer] nonce can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_arraybuffer] nonce must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_arraybuffer] key can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_arraybuffer] key must be an ArrayBuffer");
        }

        auto ciphertextDataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *ciphertext = ciphertextDataArrayBuffer.data(runtime);

        auto nonceDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        unsigned long long message_length = ciphertextDataArrayBuffer.length(runtime) - crypto_secretbox_MACBYTES;
        std::vector<uint8_t> message(message_length);

        int result = crypto_secretbox_open_easy(message.data(), ciphertext, ciphertextDataArrayBuffer.length(runtime), nonce, key);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_arraybuffer] jsi_crypto_secretbox_open_easy_from_arraybuffer failed");
        }
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_open_easy_from_arraybuffer", std::move(jsi_crypto_secretbox_open_easy_from_arraybuffer));

  auto jsi_crypto_secretbox_open_easy_from_string = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_secretbox_open_easy_from_string"),
      3,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_string] ciphertext can't be null");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_string] nonce can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_string] nonce must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_string] key can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_string] key must be an ArrayBuffer");
        }

        std::string ciphertext = arguments[0].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        unsigned long long messageLength = ciphertext.length() - crypto_secretbox_MACBYTES;
        std::vector<uint8_t> message(messageLength);

        int result = crypto_secretbox_open_easy(message.data(), (unsigned char *)ciphertext.data(), ciphertext.length(), nonce, key);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_secretbox_open_easy_from_string] jsi_crypto_secretbox_open_easy_from_string failed");
        }
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_secretbox_open_easy_from_string", std::move(jsi_crypto_secretbox_open_easy_from_string));

  auto jsi_crypto_box_easy_from_string = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_box_easy_from_string"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_string] message can't be null");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_string] nonce can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_string] nonce must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_string] publicKey can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_string] publicKey must be an ArrayBuffer");
        }

        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_string] secretKey can't be null");
        }
        if (!arguments[3].isObject() ||
            !arguments[3].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_string] secretKey must be an ArrayBuffer");
        }

        std::string message = arguments[0].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto publicKeyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *publicKey = publicKeyDataArrayBuffer.data(runtime);

        auto secretKeyDataArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *secretKey = secretKeyDataArrayBuffer.data(runtime);

        unsigned long long ciphertextLength = message.length() + crypto_box_MACBYTES;
        std::vector<uint8_t> ciphertext(ciphertextLength);

        int result = crypto_box_easy(ciphertext.data(), (unsigned char *)message.data(), message.length(), nonce, publicKey, secretKey);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_string] jsi_crypto_box_easy_from_string failed");
        }
        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_easy_from_string", std::move(jsi_crypto_box_easy_from_string));

  auto jsi_crypto_box_easy_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_box_easy_from_arraybuffer"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_arraybuffer] message can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_arraybuffer] message must be an ArrayBuffer");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_arraybuffer] nonce can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_arraybuffer] nonce must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_arraybuffer] publicKey can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_arraybuffer] publicKey must be an ArrayBuffer");
        }

        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_arraybuffer] secretKey can't be null");
        }
        if (!arguments[3].isObject() ||
            !arguments[3].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_arraybuffer] secretKey must be an ArrayBuffer");
        }

        auto messageDataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *message = messageDataArrayBuffer.data(runtime);

        auto nonceDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto publicKeyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *publicKey = publicKeyDataArrayBuffer.data(runtime);

        auto secretKeyDataArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *secretKey = secretKeyDataArrayBuffer.data(runtime);

        unsigned long long ciphertextLength = messageDataArrayBuffer.size(runtime) + crypto_box_MACBYTES;
        std::vector<uint8_t> ciphertext(ciphertextLength);

        int result = crypto_box_easy(ciphertext.data(), message, messageDataArrayBuffer.size(runtime), nonce, publicKey, secretKey);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_easy_from_arraybuffer] jsi_crypto_box_easy_from_arraybuffer failed");
        }
        return arrayBufferAsObject(runtime, ciphertext);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_easy_from_arraybuffer", std::move(jsi_crypto_box_easy_from_arraybuffer));

  auto jsi_crypto_box_open_easy_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_box_open_easy_from_arraybuffer"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_arraybuffer] ciphertext can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_arraybuffer] ciphertext must be an ArrayBuffer");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_arraybuffer] nonce can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_arraybuffer] nonce must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_arraybuffer] publicKey can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_arraybuffer] publicKey must be an ArrayBuffer");
        }

        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_arraybuffer] secretKey can't be null");
        }
        if (!arguments[3].isObject() ||
            !arguments[3].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_arraybuffer] secretKey must be an ArrayBuffer");
        }

        auto ciphertextDataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *ciphertext = ciphertextDataArrayBuffer.data(runtime);

        auto nonceDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto publicKeyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *publicKey = publicKeyDataArrayBuffer.data(runtime);

        auto secretKeyDataArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *secretKey = secretKeyDataArrayBuffer.data(runtime);

        unsigned long long message_length = ciphertextDataArrayBuffer.size(runtime) - crypto_box_MACBYTES;
        std::vector<uint8_t> message(message_length);

        int result = crypto_box_open_easy(message.data(), ciphertext, ciphertextDataArrayBuffer.size(runtime), nonce, publicKey, secretKey);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_arraybuffer] jsi_crypto_box_open_easy_from_arraybuffer failed");
        }
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_open_easy_from_arraybuffer", std::move(jsi_crypto_box_open_easy_from_arraybuffer));

  auto jsi_crypto_box_open_easy_from_string = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_box_open_easy_from_string"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] ciphertext can't be null");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] nonce can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] nonce must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] publicKey can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] publicKey must be an ArrayBuffer");
        }

        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] secretKey can't be null");
        }
        if (!arguments[3].isObject() ||
            !arguments[3].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] secretKey must be an ArrayBuffer");
        }

        std::string ciphertext = arguments[0].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto publicKeyDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *publicKey = publicKeyDataArrayBuffer.data(runtime);

        auto secretKeyDataArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *secretKey = secretKeyDataArrayBuffer.data(runtime);

        unsigned long long message_length = ciphertext.length() - crypto_box_MACBYTES;
        std::vector<uint8_t> message(message_length);

        int result = crypto_box_open_easy(message.data(), (unsigned char *)ciphertext.data(), ciphertext.length(), nonce, publicKey, secretKey);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] jsi_crypto_box_open_easy_from_string failed");
        }
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_box_open_easy_from_string", std::move(jsi_crypto_box_open_easy_from_string));

  auto jsi_crypto_pwhash_from_string = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_pwhash_from_string"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] keyLength can't be null");
        }
        if (!arguments[0].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] keyLength must be a number");
        }

        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] password can't be null");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] salt can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] salt must be an ArrayBuffer");
        }

        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] outputLength can't be null");
        }
        if (!arguments[3].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] outputLength must be a number");
        }

        if (arguments[4].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] opsLimit can't be null");
        }
        if (!arguments[4].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] opsLimit must be a number");
        }

        if (arguments[5].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] algorithm can't be null");
        }
        if (!arguments[5].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_string] algorithm must be a number");
        }

        int keyLength = arguments[0].asNumber();

        std::string password = arguments[1].asString(runtime).utf8(runtime);

        auto saltDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *salt = saltDataArrayBuffer.data(runtime);

        int opsLimit = arguments[3].asNumber();
        int memLimit = arguments[4].asNumber();
        int algorithm = arguments[5].asNumber();

        std::vector<uint8_t> key(keyLength);

        int result = crypto_pwhash(key.data(), keyLength, (const char *)password.data(), password.length(), salt, opsLimit, memLimit, algorithm);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] jsi_crypto_box_open_easy_from_string failed");
        }
        return arrayBufferAsObject(runtime, key);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_from_string", std::move(jsi_crypto_pwhash_from_string));

  auto jsi_crypto_pwhash_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_pwhash_from_arraybuffer"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] keyLength can't be null");
        }
        if (!arguments[0].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] keyLength must be a number");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] password can't be null");
        }
        if (!arguments[1].isObject() ||
            !arguments[1].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] password must be an ArrayBuffer");
        }

        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] salt can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] salt must be an ArrayBuffer");
        }

        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] outputLength can't be null");
        }
        if (!arguments[3].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] outputLength must be a number");
        }

        if (arguments[4].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] opsLimit can't be null");
        }
        if (!arguments[4].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] opsLimit must be a number");
        }

        if (arguments[5].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] algorithm can't be null");
        }
        if (!arguments[5].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_pwhash_from_arraybuffer] algorithm must be a number");
        }

        int keyLength = arguments[0].asNumber();

        auto passwordDataArrayBuffer =
            arguments[1].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *password = passwordDataArrayBuffer.data(runtime);

        auto saltDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *salt = saltDataArrayBuffer.data(runtime);

        int opsLimit = arguments[3].asNumber();
        int memLimit = arguments[4].asNumber();
        int algorithm = arguments[5].asNumber();

        std::vector<uint8_t> key(keyLength);

        int result = crypto_pwhash(key.data(), keyLength, (char *)password, passwordDataArrayBuffer.length(runtime), salt, opsLimit, memLimit, algorithm);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_box_open_easy_from_string] jsi_crypto_box_open_easy_from_string failed");
        }
        return arrayBufferAsObject(runtime, key);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_pwhash_from_arraybuffer", std::move(jsi_crypto_pwhash_from_arraybuffer));

  auto jsi_crypto_kdf_derive_from_key = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_kdf_derive_from_key"),
      4,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_kdf_derive_from_key] subkeyLength can't be null");
        }
        if (!arguments[0].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_kdf_derive_from_key] subkeyLength must be a number");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_kdf_derive_from_key] subkeyId can't be null");
        }
        if (!arguments[1].isNumber())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_kdf_derive_from_key] subkeyId must be a number");
        }
        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_kdf_derive_from_key] context can't be null");
        }

        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_kdf_derive_from_key] masterKey can't be null");
        }
        if (!arguments[3].isObject() ||
            !arguments[3].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_kdf_derive_from_key] masterKey must be an ArrayBuffer");
        }

        int subkeyLength = arguments[0].asNumber();
        int subkeyId = arguments[1].asNumber();
        std::string context = arguments[2].asString(runtime).utf8(runtime);

        auto masterKeyDataArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *masterKey = masterKeyDataArrayBuffer.data(runtime);

        std::vector<uint8_t> subkey(subkeyLength);

        int result = crypto_kdf_derive_from_key(subkey.data(), subkeyLength, subkeyId, (char *)context.data(), masterKey);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_kdf_derive_from_key] jsi_crypto_kdf_derive_from_key failed");
        }
        return arrayBufferAsObject(runtime, subkey);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_kdf_derive_from_key", std::move(jsi_crypto_kdf_derive_from_key));

  auto jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string] message can't be null");
        }
        if (!arguments[0].isString())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string] message must be a string");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string] additionalData can't be null");
        }
        if (!arguments[1].isString())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string] additionalData must be a string");
        }
        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string] nonce can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string] nonce must be an ArrayBuffer");
        }
        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string] key can't be null");
        }
        if (!arguments[3].isObject() ||
            !arguments[3].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string] key must be an ArrayBuffer");
        }

        std::string message = arguments[0].asString(runtime).utf8(runtime);
        std::string additionalData = arguments[1].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        unsigned long long cipherTextLength = message.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        std::vector<uint8_t> cipherText(cipherTextLength);

        int result = crypto_aead_xchacha20poly1305_ietf_encrypt(cipherText.data(), &cipherTextLength, (unsigned char *)message.data(), message.length(), (unsigned char *)additionalData.data(), additionalData.size(), NULL, nonce, key);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string] jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string failed");
        }
        return arrayBufferAsObject(runtime, cipherText);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_string));

  auto jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer] message can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer] message must be an ArrayBuffer");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer] additionalData can't be null");
        }
        if (!arguments[1].isString())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer] additionalData must be a string");
        }
        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer] nonce can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer] nonce must be an ArrayBuffer");
        }
        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer] key can't be null");
        }
        if (!arguments[3].isObject() ||
            !arguments[3].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer] key must be an ArrayBuffer");
        }

        auto messageDataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *message = messageDataArrayBuffer.data(runtime);

        std::string additionalData = arguments[1].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        unsigned long long cipherTextLength = messageDataArrayBuffer.size(runtime) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        std::vector<uint8_t> cipherText(cipherTextLength);

        int result = crypto_aead_xchacha20poly1305_ietf_encrypt(cipherText.data(), &cipherTextLength, message, messageDataArrayBuffer.size(runtime), (unsigned char *)additionalData.data(), additionalData.length(), NULL, nonce, key);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer] crypto_aead_xchacha20poly1305_ietf_encrypt failed");
        }
        return arrayBufferAsObject(runtime, cipherText);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_encrypt_from_arraybuffer));

  auto jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer = jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forUtf8(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer"),
      6,
      [](jsi::Runtime &runtime, const jsi::Value &thisValue, const jsi::Value *arguments, size_t count) -> jsi::Value
      {
        if (arguments[0].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer] cipherText can't be null");
        }
        if (!arguments[0].isObject() ||
            !arguments[0].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer] cipherText must be an ArrayBuffer");
        }
        if (arguments[1].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer] additionalData can't be null");
        }
        if (!arguments[1].isString())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer] additionalData must be a string");
        }
        if (arguments[2].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer] nonce can't be null");
        }
        if (!arguments[2].isObject() ||
            !arguments[2].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer] nonce must be an ArrayBuffer");
        }
        if (arguments[3].isNull())
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer] key can't be null");
        }
        if (!arguments[3].isObject() ||
            !arguments[3].asObject(runtime).isArrayBuffer(runtime))
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer] key must be an ArrayBuffer");
        }

        auto cipherTextDataArrayBuffer =
            arguments[0].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *cipherText = cipherTextDataArrayBuffer.data(runtime);
        unsigned long long cipherTextLength = cipherTextDataArrayBuffer.size(runtime);

        std::string additionalData = arguments[1].asString(runtime).utf8(runtime);

        auto nonceDataArrayBuffer =
            arguments[2].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *nonce = nonceDataArrayBuffer.data(runtime);

        auto keyDataArrayBuffer =
            arguments[3].asObject(runtime).getArrayBuffer(runtime);
        const unsigned char *key = keyDataArrayBuffer.data(runtime);

        unsigned long long messageLength = cipherTextLength - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        std::vector<uint8_t> message(messageLength);

        int result = crypto_aead_xchacha20poly1305_ietf_decrypt(message.data(), &messageLength, NULL, cipherText, cipherTextLength, (unsigned char *)additionalData.data(), additionalData.length(), nonce, key);

        if (result != 0)
        {
          throw jsi::JSError(runtime, "[react-native-libsodium][jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer] jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer failed");
        }
        return arrayBufferAsObject(runtime, message);
      });

  jsiRuntime.global().setProperty(jsiRuntime, "jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer", std::move(jsi_crypto_aead_xchacha20poly1305_ietf_decrypt_from_arraybuffer));
}

void cleanUpLibsodium()
{
  // intentionally left blank
}