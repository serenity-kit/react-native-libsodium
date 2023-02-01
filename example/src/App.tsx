import * as React from 'react';
import { SafeAreaView, ScrollView, StyleSheet, View } from 'react-native';
import sodium, {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_kdf_CONTEXTBYTES,
  crypto_kdf_KEYBYTES,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash_BYTES_MAX,
  crypto_pwhash_BYTES_MIN,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  from_base64,
  randombytes_buf,
  ready,
  to_base64,
  to_hex,
} from 'react-native-libsodium';
import { Header } from './components/Header';
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

function LibsodiumTests() {
  const hex = to_hex('Hello World');

  if (sodium.crypto_secretbox_KEYBYTES !== 32) {
    throw new Error('export default not working');
  }
  console.log({
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

  return (
    <SafeAreaView style={styles.safeAreaContainer}>
      <ScrollView style={styles.scrollContainer}>
        <View style={styles.container}>
          <Header>Base64</Header>
          <Test_to_base64 />
          <Test_from_base64 />
          <Header>Random Numbers</Header>
          <Test_randombytes_buf length={1} />
          <Test_randombytes_buf length={3} />
          <Test_randombytes_buf length={9} />
          <Test_randombytes_uniform max={1} />
          <Test_randombytes_uniform max={10} />
          <Header>Password Hashing</Header>
          <Test_crypto_pwhash
            password={'password123'}
            salt={randombytes_buf(crypto_pwhash_SALTBYTES)}
          />
          <Test_crypto_pwhash
            password={from_base64(to_base64('password123'))}
            salt={randombytes_buf(crypto_pwhash_SALTBYTES)}
          />
          <Header>Key Derivations</Header>
          <Test_crypto_kdf_keygen />
          <Test_crypto_kdf_keygen outputFormat={'base64'} />
          <Test_crypto_kdf_keygen outputFormat={'hex'} />
          <Test_crypto_kdf_derive_from_key subkeyLength={32} />
          <Test_crypto_kdf_derive_from_key subkeyLength={32} />
          <Header>Signatures (Asymmetric Key)</Header>
          <Test_crypto_sign_keypair />
          <Test_crypto_sign_keypair outputFormat={'base64'} />
          <Test_crypto_sign_keypair outputFormat={'hex'} />
          <Test_crypto_sign_detached message={'Hello World'} />
          <Test_crypto_sign_detached
            message={from_base64(to_base64('Hello World'))}
          />
          <Test_crypto_sign_verify_detached message={'Hello World'} />
          <Test_crypto_sign_verify_detached
            message={from_base64(to_base64('Hello World'))}
          />
          <Header>Box Encryption (Asymmetric Key)</Header>
          <Test_crypto_box_keypair />
          <Test_crypto_box_keypair outputFormat={'base64'} />
          <Test_crypto_box_keypair outputFormat={'hex'} />
          <Test_crypto_box_easy message={'Hello World'} />
          <Test_crypto_box_easy
            message={from_base64(to_base64('Hello World'))}
          />
          <Test_crypto_box_open_easy message={'Hello World'} />
          <Test_crypto_box_open_easy
            message={from_base64(to_base64('Hello World'))}
          />
          <Header>Secret Box Encryption (Symmetric Key)</Header>
          <Test_crypto_secretbox_keygen />
          <Test_crypto_secretbox_keygen outputFormat={'base64'} />
          <Test_crypto_secretbox_keygen outputFormat={'hex'} />
          <Test_crypto_secretbox_easy message={'Hello World'} />
          <Test_crypto_secretbox_easy
            message={from_base64(to_base64('Hello World'))}
          />
          <Test_crypto_secretbox_open_easy message={'Hello World'} />
          <Test_crypto_secretbox_open_easy
            message={from_base64(to_base64('Hello World'))}
          />
          <Header>AEAD Encryption (Symmetric Key)</Header>
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
