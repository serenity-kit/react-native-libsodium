import * as React from 'react';

import {
  Image,
  ScrollView,
  StyleSheet,
  View,
  SafeAreaView,
} from 'react-native';
import sodium, {
  base64_variants,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  crypto_box_keypair,
  crypto_box_NONCEBYTES,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_kdf_CONTEXTBYTES,
  crypto_kdf_KEYBYTES,
  crypto_kdf_keygen,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash_BYTES_MAX,
  crypto_pwhash_BYTES_MIN,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_sign_detached,
  crypto_sign_keypair,
  from_base64,
  randombytes_buf,
  ready,
  to_base64,
  to_hex,
} from 'react-native-libsodium';
import { largeContent } from './largeContent';
import { Header } from './components/Header';
import { Test_from_base64 } from './components/tests/Test_from_base64';
import { Test_to_base64 } from './components/tests/Test_to_base64';
import { Test_randombytes_buf } from './components/tests/Test_randombytes_buf';
import { Test_randombytes_uniform } from './components/tests/Test_randombytes_uniform';
import { Test_crypto_secretbox_keygen } from './components/tests/Test_crypto_secretbox_keygen';
import { Test_crypto_secretbox_easy } from './components/tests/Test_crypto_secretbox_easy';
import { Test_crypto_aead_xchacha20poly1305_ietf_keygen } from './components/tests/Test_crypto_aead_xchacha20poly1305_ietf_keygen';
import { Test_crypto_kdf_keygen } from './components/tests/Test_crypto_kdf_keygen';
import { Test_crypto_box_keypair } from './components/tests/Test_crypto_box_keypair';
import { Test_crypto_sign_keypair } from './components/tests/Test_crypto_sign_keypair';
import { Test_crypto_sign_detached } from './components/tests/Test_crypto_sign_detached';
import { Test_crypto_sign_verify_detached } from './components/tests/Test_crypto_sign_verify_detached';
import { Test_crypto_pwhash } from './components/tests/Test_crypto_pwhash';
import { Test_crypto_kdf_derive_from_key } from './components/tests/Test_crypto_kdf_derive_from_key';
import { Test_crypto_box_easy } from './components/tests/Test_crypto_box_easy';
import { Test_crypto_aead_xchacha20poly1305_ietf_encrypt } from './components/tests/Test_crypto_aead_xchacha20poly1305_ietf_encrypt';

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

  const secretbox_key = sodium.crypto_secretbox_keygen();
  const aead_xchacha20poly1305_ietf_key =
    crypto_aead_xchacha20poly1305_ietf_keygen();

  const sign_keypair = crypto_sign_keypair();

  const secretbox_easy_nonce = randombytes_buf(crypto_secretbox_NONCEBYTES);

  // const secretbox_easy_from_uint8array = crypto_secretbox_easy(
  //   from_base64(to_base64('Hello World')),
  //   secretbox_easy_nonce,
  //   secretbox_key
  // );
  // const secretbox_open_easy_from_uint8array = crypto_secretbox_open_easy(
  //   secretbox_easy_from_uint8array,
  //   secretbox_easy_nonce,
  //   secretbox_key
  // );
  // if (to_string(secretbox_open_easy_from_uint8array) !== 'Hello World') {
  //   throw new Error('secretbox_open_easy_from_uint8array failed');
  // }

  const box_easy_nonce = randombytes_buf(crypto_box_NONCEBYTES);
  const box_easy_keypair_alice = crypto_box_keypair();
  const box_easy_keypair_bob = crypto_box_keypair();

  const kdf_keygen = crypto_kdf_keygen();

  const aead_xchacha20poly1305_ietf_nonce = randombytes_buf(
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
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
    <SafeAreaView>
      <ScrollView style={styles.scrollContainer}>
        <View style={styles.container}>
          <Header>Base64</Header>
          <Test_to_base64 />
          <Test_from_base64 />
          <Header>Random Numbers</Header>
          {/*randombytes_buf*/}
          <Test_randombytes_buf length={1} />
          <Test_randombytes_buf length={3} />
          <Test_randombytes_buf length={9} />
          {/*randombytes_uniform*/}
          <Test_randombytes_uniform max={1} />
          <Test_randombytes_uniform max={10} />
          <Header>Secretbox (symmetric key)</Header>
          <Test_crypto_secretbox_keygen />
          <Test_crypto_secretbox_keygen outputFormat={'base64'} />
          <Test_crypto_secretbox_keygen outputFormat={'hex'} />
          <Test_crypto_secretbox_easy
            message={'Hello World'}
            nonce={secretbox_easy_nonce}
            symmetricKey={secretbox_key}
          />
          <Test_crypto_secretbox_easy
            message={from_base64(to_base64('Hello World'))}
            nonce={secretbox_easy_nonce}
            symmetricKey={secretbox_key}
          />
          <Header>AEAD (symmetric key)</Header>
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
            nonce={aead_xchacha20poly1305_ietf_nonce}
            symmetricKey={aead_xchacha20poly1305_ietf_key}
          />
          <Test_crypto_aead_xchacha20poly1305_ietf_encrypt
            message={from_base64(to_base64('Hello World'))}
            additionalData={'additional data'}
            nonce={aead_xchacha20poly1305_ietf_nonce}
            symmetricKey={crypto_aead_xchacha20poly1305_ietf_keygen()}
          />
          <Header>Key Derivations</Header>
          <Test_crypto_kdf_keygen />
          <Test_crypto_kdf_keygen outputFormat={'base64'} />
          <Test_crypto_kdf_keygen outputFormat={'hex'} />
          <Test_crypto_kdf_derive_from_key
            subkeyLength={32}
            subkeyId={42}
            context={'context'}
            masterKey={kdf_keygen}
          />
          <Test_crypto_kdf_derive_from_key
            subkeyLength={32}
            subkeyId={43}
            context={'context'}
            masterKey={kdf_keygen}
          />
          <Header>Box (asymmetric key)</Header>
          <Test_crypto_box_keypair />
          <Test_crypto_box_easy
            message={'Hello World'}
            nonce={box_easy_nonce}
            senderPrivateKey={box_easy_keypair_alice.privateKey}
            receiverPublicKey={box_easy_keypair_bob.publicKey}
          />
          <Test_crypto_box_easy
            message={from_base64(to_base64('Hello World'))}
            nonce={box_easy_nonce}
            senderPrivateKey={box_easy_keypair_alice.privateKey}
            receiverPublicKey={box_easy_keypair_bob.publicKey}
          />
          <Header>Signatures (asymmetric key)</Header>
          <Test_crypto_sign_keypair />
          <Test_crypto_sign_detached
            message={'Hello World'}
            privateKey={sign_keypair.privateKey}
          />
          <Test_crypto_sign_verify_detached
            signature={crypto_sign_detached(
              'Hello World',
              sign_keypair.privateKey
            )}
            message={'Hello World'}
            publicKey={sign_keypair.publicKey}
          />
          <Test_crypto_sign_detached
            message={from_base64(to_base64('Hello World'))}
            privateKey={sign_keypair.privateKey}
          />
          <Test_crypto_sign_verify_detached
            signature={crypto_sign_detached(
              from_base64(to_base64('Hello World')),
              sign_keypair.privateKey
            )}
            message={'Hello World'}
            publicKey={sign_keypair.publicKey}
          />
          <Header>Password Hashing</Header>
          <Test_crypto_pwhash
            password={'password123'}
            salt={randombytes_buf(crypto_pwhash_SALTBYTES)}
          />
          <Test_crypto_pwhash
            password={from_base64(to_base64('password123'))}
            salt={randombytes_buf(crypto_pwhash_SALTBYTES)}
          />

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
