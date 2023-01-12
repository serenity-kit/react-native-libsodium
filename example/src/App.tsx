import * as React from 'react';

import { Image, ScrollView, StyleSheet, Text, View } from 'react-native';
import sodium, {
  base64_variants,
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  crypto_box_easy,
  crypto_box_keypair,
  crypto_box_NONCEBYTES,
  crypto_box_open_easy,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_kdf_CONTEXTBYTES,
  crypto_kdf_derive_from_key,
  crypto_kdf_KEYBYTES,
  crypto_kdf_keygen,
  crypto_pwhash,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash_BYTES_MAX,
  crypto_pwhash_BYTES_MIN,
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
  ready,
  to_base64,
  to_hex,
  to_string,
} from 'react-native-libsodium';
import { largeContent } from './largeContent';
import { threeMbImage } from './threeMbImage';

const encryptAndDecryptImage = (contentAsBas64: string) => {
  const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
  const publicNonce = sodium.randombytes_buf(24);
  const additionalData = '';
  const content = from_base64(contentAsBas64, base64_variants.ORIGINAL);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    content,
    additionalData,
    null,
    publicNonce,
    key
  );

  const decryptedContent = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    additionalData,
    publicNonce,
    key
  );
  if (content.length !== decryptedContent.length) {
    throw new Error('encryptAndDecryptImage failed: length mismatch');
  }
  const result = to_base64(decryptedContent, base64_variants.ORIGINAL);
  if (result !== contentAsBas64) {
    throw new Error('encryptAndDecryptImage failed: content mismatch');
  }
  return result;
};

function LibsodiumTests() {
  const resultBase64 = to_base64('Hello World');
  const resultUint8Array = from_base64(resultBase64);
  const result2Base64 = to_base64(resultUint8Array);
  const resultString = to_string(resultUint8Array);
  const hex = to_hex('Hello World');
  if (sodium.crypto_secretbox_KEYBYTES !== 32) {
    throw new Error('export default not working');
  }
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
    crypto_pwhash_BYTES_MIN,
    crypto_pwhash_BYTES_MAX,
    crypto_kdf_CONTEXTBYTES,
  });

  if (crypto_kdf_CONTEXTBYTES !== 8) {
    throw new Error('crypto_kdf_CONTEXTBYTES not properly exported');
  }

  const randombytes_buf_1 = randombytes_buf(1);
  const randombytes_buf_3 = randombytes_buf(3);
  const randombytes_buf_9 = randombytes_buf(9);
  console.log({ randombytes_buf_1, randombytes_buf_3, randombytes_buf_9 });

  const randombytes_uniform_1 = randombytes_uniform(1);
  const randombytes_uniform_10 = randombytes_uniform(10);

  console.log({ randombytes_uniform_1, randombytes_uniform_10 });

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

  const secretbox_easy_nonce = randombytes_buf(crypto_secretbox_NONCEBYTES);
  const secretbox_easy_from_string = crypto_secretbox_easy(
    'Hello World',
    secretbox_easy_nonce,
    secretbox_key
  );

  // TODO is this a bug? or how should it be used?
  // const secretbox_open_easy_from_string = crypto_secretbox_open_easy(
  //   to_string(secretbox_easy_from_string),
  //   secretbox_easy_nonce,
  //   secretbox_key
  // );
  // if (to_string(secretbox_open_easy_from_string) !== 'Hello World') {
  //   throw new Error('secretbox_open_easy_from_string failed');
  // }

  const secretbox_easy_from_uint8array = crypto_secretbox_easy(
    from_base64(to_base64('Hello World')),
    secretbox_easy_nonce,
    secretbox_key
  );
  const secretbox_open_easy_from_uint8array = crypto_secretbox_open_easy(
    secretbox_easy_from_uint8array,
    secretbox_easy_nonce,
    secretbox_key
  );
  if (to_string(secretbox_open_easy_from_uint8array) !== 'Hello World') {
    throw new Error('secretbox_open_easy_from_uint8array failed');
  }

  const box_easy_nonce = randombytes_buf(crypto_box_NONCEBYTES);
  const box_easy_keypair_alice = crypto_box_keypair();
  const box_easy_keypair_bob = crypto_box_keypair();

  const box_easy_from_string = crypto_box_easy(
    'Hello World',
    box_easy_nonce,
    box_easy_keypair_alice.publicKey,
    box_easy_keypair_bob.privateKey
  );
  // TODO is this a bug? or how should it be used?
  // const box_open_easy_from_string = crypto_box_open_easy(
  //   to_string(box_easy_from_string),
  //   box_easy_nonce,
  //   box_easy_keypair_bob.publicKey,
  //   box_easy_keypair_alice.privateKey
  // );
  // if (to_string(box_open_easy_from_string) !== 'Hello World') {
  //   throw new Error('box_open_easy_from_string failed');
  // }

  const box_easy_from_uint8array = crypto_box_easy(
    from_base64(to_base64('Hello World')),
    box_easy_nonce,
    box_easy_keypair_alice.publicKey,
    box_easy_keypair_bob.privateKey
  );
  const box_open_easy_from_uint8array = crypto_box_open_easy(
    box_easy_from_uint8array,
    box_easy_nonce,
    box_easy_keypair_bob.publicKey,
    box_easy_keypair_alice.privateKey
  );
  if (to_string(box_open_easy_from_uint8array) !== 'Hello World') {
    throw new Error('box_open_easy_from_uint8array failed');
  }

  const pwhash_salt = randombytes_buf(crypto_pwhash_SALTBYTES);

  const pwhash_from_string = crypto_pwhash(
    crypto_pwhash_BYTES_MIN,
    'password123',
    pwhash_salt,
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_DEFAULT
  );

  const pwhash_from_uint8array = crypto_pwhash(
    crypto_pwhash_BYTES_MIN,
    from_base64(to_base64('password123')),
    from_base64(to_base64(pwhash_salt)),
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_DEFAULT
  );
  console.log(to_base64(pwhash_from_string));
  console.log(to_base64(pwhash_from_uint8array));
  if (to_base64(pwhash_from_string) !== to_base64(pwhash_from_uint8array)) {
    throw new Error('crypto_pwhash failed');
  }

  const kdf_keygen = crypto_kdf_keygen();
  const kdf_derive_from_key = crypto_kdf_derive_from_key(
    32,
    42,
    'context',
    kdf_keygen
  );
  const kdf_derive_from_key_2 = crypto_kdf_derive_from_key(
    32,
    42,
    'context',
    kdf_keygen
  );
  const kdf_derive_from_key_3 = crypto_kdf_derive_from_key(
    32,
    43,
    'context',
    kdf_keygen
  );
  if (
    to_base64(kdf_derive_from_key) !== to_base64(kdf_derive_from_key_2) ||
    to_base64(kdf_derive_from_key) === to_base64(kdf_derive_from_key_3)
  ) {
    throw new Error('crypto_kdf_derive_from_key failed');
  }

  const aead_xchacha20poly1305_ietf_nonce = randombytes_buf(
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const aead_xchacha20poly1305_ietf_encrypt_from_string =
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      'Hello World',
      'additional data',
      null,
      aead_xchacha20poly1305_ietf_nonce,
      aead_xchacha20poly1305_ietf_key
    );
  const aead_xchacha20poly1305_ietf_encrypt_from_uin8array =
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      from_base64(to_base64('Hello World')),
      'additional data',
      null,
      aead_xchacha20poly1305_ietf_nonce,
      aead_xchacha20poly1305_ietf_key
    );

  // FIXME: there is a bug in the aead_xchacha20poly1305_ietf encryption
  // that is preventing decryption:
  // const aead_xchacha20poly1305_ietf_decrypt_encrypted_from_string =
  //   crypto_aead_xchacha20poly1305_ietf_decrypt(
  //     null,
  //     aead_xchacha20poly1305_ietf_encrypt_from_string,
  //     'additional data',
  //     aead_xchacha20poly1305_ietf_nonce,
  //     aead_xchacha20poly1305_ietf_key
  //   );
  // if (
  //   to_string(aead_xchacha20poly1305_ietf_decrypt_encrypted_from_string) !==
  //   'Hello World'
  // ) {
  //   throw new Error('aead_xchacha20poly1305_ietf_decrypt failed');
  // }

  // const aead_xchacha20poly1305_ietf_decrypt_encrypted_from_uint8array =
  //   crypto_aead_xchacha20poly1305_ietf_decrypt(
  //     null,
  //     aead_xchacha20poly1305_ietf_encrypt_from_uin8array,
  //     'additional data',
  //     aead_xchacha20poly1305_ietf_nonce,
  //     aead_xchacha20poly1305_ietf_key
  //   );
  // if (
  //   to_string(aead_xchacha20poly1305_ietf_decrypt_encrypted_from_uint8array) !==
  //   'Hello World'
  // ) {
  //   throw new Error('aead_xchacha20poly1305_ietf_decrypt failed');
  // }

  const decryptedImage = encryptAndDecryptImage(largeContent);
  const decryptedImageThreeMb = encryptAndDecryptImage(threeMbImage);

  return (
    <ScrollView>
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

        <Text>
          sign_keypair.privateKey: {to_base64(sign_keypair.privateKey)}
        </Text>
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

        <Text>
          secretbox_easy_from_string: {to_base64(secretbox_easy_from_string)}
        </Text>

        <Text>
          secretbox_easy_from_uint8array:{' '}
          {to_base64(secretbox_easy_from_uint8array)}
        </Text>

        <Text>box_easy_from_string: {to_base64(box_easy_from_string)}</Text>
        <Text>
          box_easy_from_uint8array: {to_base64(box_easy_from_uint8array)}
        </Text>

        <Image
          style={{ width: 120, height: 100 }}
          source={{ uri: `data:image/jpeg;base64,${decryptedImage}` }}
        />
        <Image
          style={{ width: 120, height: 100 }}
          source={{ uri: `data:image/jpeg;base64,${decryptedImageThreeMb}` }}
        />
      </View>
    </ScrollView>
  );
}

export default function App() {
  const [isReady, setIsReady] = React.useState(false);

  React.useEffect(() => {
    (async () => {
      await ready;
      setIsReady(true);
    })();
  }, []);

  if (!isReady) {
    return null;
  }
  return <LibsodiumTests />;
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
