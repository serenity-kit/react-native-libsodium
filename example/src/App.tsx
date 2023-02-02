import * as React from 'react';
import { SafeAreaView, ScrollView, StyleSheet, View } from 'react-native';
import sodium, { from_base64, ready, to_base64 } from 'react-native-libsodium';
import { Header } from './components/Header';
import { Test_constants } from './components/tests/Test_constants';
import { Test_crypto_aead_xchacha20poly1305_ietf_decrypt } from './components/tests/Test_crypto_aead_xchacha20poly1305_ietf_decrypt';
import { Test_crypto_aead_xchacha20poly1305_ietf_encrypt } from './components/tests/Test_crypto_aead_xchacha20poly1305_ietf_encrypt';
import { Test_crypto_aead_xchacha20poly1305_ietf_keygen } from './components/tests/Test_crypto_aead_xchacha20poly1305_ietf_keygen';
import { Test_crypto_box_easy } from './components/tests/Test_crypto_box_easy';
import { Test_crypto_box_keypair } from './components/tests/Test_crypto_box_keypair';
import { Test_crypto_box_open_easy } from './components/tests/Test_crypto_box_open_easy';
import { Test_crypto_kdf_derive_from_key } from './components/tests/Test_crypto_kdf_derive_from_key';
import { Test_crypto_kdf_keygen } from './components/tests/Test_crypto_kdf_keygen';
import { Test_crypto_pwhash } from './components/tests/Test_crypto_pwhash';
import { Test_crypto_secretbox_easy } from './components/tests/Test_crypto_secretbox_easy';
import { Test_crypto_secretbox_keygen } from './components/tests/Test_crypto_secretbox_keygen';
import { Test_crypto_secretbox_open_easy } from './components/tests/Test_crypto_secretbox_open_easy';
import { Test_crypto_sign_detached } from './components/tests/Test_crypto_sign_detached';
import { Test_crypto_sign_keypair } from './components/tests/Test_crypto_sign_keypair';
import { Test_crypto_sign_verify_detached } from './components/tests/Test_crypto_sign_verify_detached';
import { Test_from_base64 } from './components/tests/Test_from_base64';
import { Test_image_encryption } from './components/tests/Test_image_encryption';
import { Test_large_image_encryption } from './components/tests/Test_large_image_encryption';
import { Test_randombytes_buf } from './components/tests/Test_randombytes_buf';
import { Test_randombytes_uniform } from './components/tests/Test_randombytes_uniform';
import { Test_to_base64 } from './components/tests/Test_to_base64';
import { Test_to_hex } from './components/tests/Test_to_hex';

function LibsodiumTests() {
  if (sodium.crypto_secretbox_KEYBYTES !== 32) {
    throw new Error('export default not working');
  }

  return (
    <SafeAreaView style={styles.safeAreaContainer}>
      <ScrollView style={styles.scrollContainer}>
        <View style={styles.container}>
          <Header>constants</Header>
          <Test_constants />

          <Header>base64</Header>
          <Test_to_base64 />
          <Test_from_base64 />

          <Header>hex</Header>
          <Test_to_hex />

          <Header>random</Header>
          <Test_randombytes_buf />
          <Test_randombytes_uniform />

          <Header>password hashing</Header>
          <Test_crypto_pwhash />

          <Header>key derivation</Header>
          <Test_crypto_kdf_keygen />
          <Test_crypto_kdf_derive_from_key />

          <Header>signing</Header>
          <Test_crypto_sign_keypair />
          <Test_crypto_sign_detached />
          <Test_crypto_sign_verify_detached />

          <Header>box encryption (asymmetric)</Header>
          <Test_crypto_box_keypair />
          <Test_crypto_box_easy />
          <Test_crypto_box_open_easy />

          <Header>secretbox encryption (symmetric)</Header>
          <Test_crypto_secretbox_keygen />
          <Test_crypto_secretbox_easy />
          <Test_crypto_secretbox_open_easy />

          <Header>AEAD encryption (symmetric)</Header>
          <Test_crypto_aead_xchacha20poly1305_ietf_keygen />
          <Test_crypto_aead_xchacha20poly1305_ietf_keygen
            outputFormat={'base64'}
          />
          <Test_crypto_aead_xchacha20poly1305_ietf_keygen
            outputFormat={'hex'}
          />
          <Test_crypto_aead_xchacha20poly1305_ietf_encrypt
            message={'Hello World'}
            additionalData={'additional data'}
          />
          <Test_crypto_aead_xchacha20poly1305_ietf_encrypt
            message={from_base64(to_base64('Hello World'))}
            additionalData={'additional data'}
          />
          <Test_crypto_aead_xchacha20poly1305_ietf_decrypt
            message={'Hello World'}
            additionalData={'additional data'}
          />
          <Test_crypto_aead_xchacha20poly1305_ietf_decrypt
            message={from_base64(to_base64('Hello World'))}
            additionalData={'additional data'}
          />

          <Header>Image Encryption (Symmetric Key)</Header>
          <Test_image_encryption />

          <Header>Large Image Encryption (Symmetric Key)</Header>
          <Test_large_image_encryption />
        </View>
      </ScrollView>
    </SafeAreaView>
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
  safeAreaContainer: {
    flex: 1,
  },
  scrollContainer: {
    padding: 0,
  },
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
