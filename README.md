# react-native-libsodium

React Native bindings to Libsodium aiming to be a drop-in replacement for the [libsodium-wrappers package](https://www.npmjs.com/package/libsodium-wrappers).

Currently only a subset of the libsodium-wrappers exposed funtionality is implemented and only iOS support is working.

We planning to provide Android and Web support in the coming months.

For missing functionality we welcome pull-requests or you can sponsor the development. Get in touch with us at `hi@serenity.re`.

## Installation

```sh
npm install react-native-libsodium
```

## Usage

```js
import {
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_box_easy,
  crypto_box_keypair,
  crypto_box_open_easy,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_kdf_derive_from_key,
  crypto_kdf_KEYBYTES,
  crypto_kdf_keygen,
  crypto_pwhash,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_keygen,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  crypto_sign_detached,
  crypto_sign_keypair,
  crypto_sign_verify_detached,
  from_base64,
  randombytes_buf,
  randombytes_uniform,
  to_base64,
  to_hex,
  to_string,
} from 'react-native-libsodium';

// ...
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

The `to_string` function was copied from the libsodium.js project and you can find the license at [LICENSE_libsodiumjs](LICENSE_libsodiumjs).

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
