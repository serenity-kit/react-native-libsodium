import * as React from 'react';

import { StyleSheet, Text, View } from 'react-native';
import {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_kdf_KEYBYTES,
  crypto_kdf_keygen,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_keygen,
  crypto_secretbox_NONCEBYTES,
  from_base64,
  to_base64,
  to_hex,
  to_string,
} from 'react-native-rnlibsodium';

export default function App() {
  const resultBase64 = to_base64('Hello World');
  const resultUint8Array = from_base64(resultBase64);
  const result2Base64 = to_base64(resultUint8Array);
  const resultString = to_string(resultUint8Array);
  const hex = to_hex('Hello World');
  console.log({
    resultBase64,
    resultUint8Array,
    result2Base64,
    resultString,
    hex,
  });
  console.log({
    crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES,
    crypto_pwhash_SALTBYTES,
    crypto_pwhash_ALG_DEFAULT,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_kdf_KEYBYTES,
  });
  const secretbox_key = crypto_secretbox_keygen();
  const secretbox_key_base64 = crypto_secretbox_keygen('base64');
  const secretbox_key_hex = crypto_secretbox_keygen('hex');
  const aead_xchacha20poly1305_ietf_key =
    crypto_aead_xchacha20poly1305_ietf_keygen();
  const aead_xchacha20poly1305_ietf_key_base64 =
    crypto_aead_xchacha20poly1305_ietf_keygen('base64');
  const aead_xchacha20poly1305_ietf_key_hex =
    crypto_aead_xchacha20poly1305_ietf_keygen('hex');
  const kdf_key = crypto_kdf_keygen();
  const kdf_key_base64 = crypto_kdf_keygen('base64');
  const kdf_key_hex = crypto_kdf_keygen('hex');

  return (
    <View style={styles.container}>
      <Text>secretbox_key: {to_base64(secretbox_key)}</Text>
      <Text>secretbox_key_base64: {secretbox_key_base64}</Text>
      <Text>secretbox_key_hex: {secretbox_key_hex}</Text>
      <Text>
        aead_xchacha20poly1305_ietf_key:{' '}
        {to_base64(aead_xchacha20poly1305_ietf_key)}
      </Text>
      <Text>
        aead_xchacha20poly1305_ietf_key_base64:{' '}
        {aead_xchacha20poly1305_ietf_key_base64}
      </Text>
      <Text>
        aead_xchacha20poly1305_ietf_key_hex:{' '}
        {aead_xchacha20poly1305_ietf_key_hex}
      </Text>
      <Text>kdf_key:{to_base64(kdf_key)}</Text>
      <Text>kdf_key_base64:{kdf_key_base64}</Text>
      <Text>kdf_key_hex:{kdf_key_hex}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
