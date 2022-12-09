import * as React from 'react';

import { StyleSheet, Text, View } from 'react-native';
import {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_box_keypair,
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
  crypto_sign_detached,
  crypto_sign_keypair,
  crypto_sign_verify_detached,
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

  const box_keypair = crypto_box_keypair();
  const sign_keypair = crypto_sign_keypair();

  const sign_detached_from_uint8array_message = from_base64(
    to_base64('Hello World')
  );
  const sign_detached_from_uint8array = crypto_sign_detached(
    sign_detached_from_uint8array_message,
    sign_keypair.privateKey
  );
  const sign_verify_detached_from_uint8array = crypto_sign_verify_detached(
    sign_detached_from_uint8array,
    sign_detached_from_uint8array_message,
    sign_keypair.publicKey
  );

  const sign_detached_from_string = crypto_sign_detached(
    'Hello World',
    sign_keypair.privateKey
  );
  const sign_verify_detached_from_string = crypto_sign_verify_detached(
    sign_detached_from_string,
    'Hello World',
    sign_keypair.publicKey
  );
  const sign_verify_detached_from_string_2 = crypto_sign_verify_detached(
    sign_detached_from_string,
    sign_detached_from_uint8array_message,
    sign_keypair.publicKey
  );

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

      <Text>box_keypair.privateKey: {to_base64(box_keypair.privateKey)}</Text>
      <Text>box_keypair.publicKey: {to_base64(box_keypair.publicKey)}</Text>
      <Text>box_keypair.keyType: {box_keypair.keyType}</Text>

      <Text>sign_keypair.privateKey: {to_base64(sign_keypair.privateKey)}</Text>
      <Text>sign_keypair.publicKey: {to_base64(sign_keypair.publicKey)}</Text>
      <Text>sign_keypair.keyType: {sign_keypair.keyType}</Text>

      <Text>
        sign_detached_from_uint8array:{' '}
        {to_base64(sign_detached_from_uint8array)}
      </Text>
      <Text>
        sign_verify_detached_from_uint8array:{' '}
        {String(sign_verify_detached_from_uint8array)}
      </Text>

      <Text>
        sign_detached_from_string: {to_base64(sign_detached_from_string)}
      </Text>
      <Text>
        sign_verify_detached_from_string:{' '}
        {String(sign_verify_detached_from_string)}
      </Text>
      <Text>
        sign_verify_detached_from_string_2:{' '}
        {String(sign_verify_detached_from_string_2)}
      </Text>
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
