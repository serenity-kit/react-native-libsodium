# react-native-libsodium

React Native bindings to Libsodium matching the [libsodium-wrappers package](https://www.npmjs.com/package/libsodium-wrappers) API

Supported Platforms:

- iOS
- Android
- Web

Currently only a subset of the libsodium-wrappers exposed functionality is implemented. For missing functionality we welcome pull-requests or you can sponsor the development. Get in touch with us at `hi@serenity.re`.

## Installation Expo (dev-client)

This package support the Expo plugin system and can be used together with the [Expo dev-client](https://docs.expo.dev/clients/introduction/).

```sh
npm install react-native-libsodium
```

Extend app.config.js with the following plugins entry:

```js
export default {
  expo: {
    …
    plugins: [["react-native-libsodium", {}]],
  }
}
```

## Installation React Native

```sh
npm install react-native-libsodium
cd ios && pod install
```

## Usage

**Hint:** see the `example` app in the repository regarding how to use the functions

```js
import {
  crypto_auth,
  crypto_auth_verify,
  crypto_auth_BYTES,
  crypto_auth_KEYBYTES,
  crypto_auth_keygen,
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_box_easy,
  crypto_box_keypair,
  crypto_box_open_easy,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_kdf_CONTEXTBYTES,
  crypto_kdf_derive_from_key,
  crypto_kdf_KEYBYTES,
  crypto_kdf_keygen,
  crypto_pwhash, // only with loadSumoVersion with react-native-web
  crypto_pwhash_ALG_DEFAULT, // only with loadSumoVersion with react-native-web
  crypto_pwhash_MEMLIMIT_INTERACTIVE, // only with loadSumoVersion with react-native-web
  crypto_pwhash_OPSLIMIT_INTERACTIVE, // only with loadSumoVersion with react-native-web
  crypto_pwhash_SALTBYTES, // only with loadSumoVersion with react-native-web
  crypto_generichash,
  crypto_generichash_BYTES,
  crypto_generichash_BYTES_MIN,
  crypto_generichash_BYTES_MAX,
  crypto_generichash_KEYBYTES,
  crypto_generichash_KEYBYTES_MIN,
  crypto_generichash_KEYBYTES_MAX,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_keygen,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  crypto_sign_detached,
  crypto_sign_keypair,
  crypto_sign_SEEDBYTES,
  crypto_sign_verify_detached,
  from_base64,
  randombytes_buf,
  randombytes_uniform,
  to_base64,
  to_hex,
  to_string,
  ready, // only needed for react-native-web
  loadSumoVersion, // only relevant for react-native-web
} from 'react-native-libsodium';

// ...
```

## React Native Web

For the web platform the constants and functions from the `libsodium-wrappers` package is exposed. This also means you need to wait for the `ready` Promise to be resolved before using any constant or function.

Certain constants and functions e.g. `crypto_pwhash` are only available in the `libsodium-wrappers-sumo` package. To load this package instead for web you can call `loadSumoVersion` right after importing the package.

```ts
import { loadSumoVersion, ready } from 'react-native-libsodium';

loadSumoVersion();
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

The `to_string` function and `base64_variants` enum was copied from the libsodium.js project and you can find the license at [LICENSE_libsodiumjs](LICENSE_libsodiumjs).

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)

## Acknowledgment

Thanks to [Donus](https://github.com/donus3) for freeing up the `react-native-libsodium` package name on npm.
