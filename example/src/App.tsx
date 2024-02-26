import * as React from 'react';
import { SafeAreaView, ScrollView, StyleSheet, View } from 'react-native';
import sodium, { loadSumoVersion, ready } from 'react-native-libsodium';
import { TestResults } from './components/TestResults';
import { VisualImageTest } from './components/VisualImageTest';
import {
  crypto_sign_seed_keypair,
  crypto_sign_ed25519_sk_to_curve25519,
  crypto_sign_ed25519_pk_to_curve25519,
} from '../../src/lib.native';

loadSumoVersion();

function LibsodiumTests() {
  if (sodium.crypto_secretbox_KEYBYTES !== 32) {
    throw new Error('export default not working');
  }
  verify_soidum();

  return (
    <SafeAreaView style={styles.safeAreaContainer}>
      <ScrollView style={styles.scrollContainer}>
        <View style={styles.container}>
          <TestResults />
          <VisualImageTest />
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

async function generateAsymmetricKey(iv = generateEntropy(32)) {
  console.log(
    'sodium crypto_sign_ed25519_pk_to_curve25519:',
    crypto_sign_ed25519_pk_to_curve25519
  );
  console.log('sodium crypto_sign_seed_keypair:', crypto_sign_seed_keypair);

  const ed25519KeyPair = crypto_sign_seed_keypair(iv);
  console.log('PubKey: ', ed25519KeyPair.publicKey);
  console.log('privateKey: ', ed25519KeyPair.privateKey);
  console.log('Keypair: ', ed25519KeyPair);
  // debugger;
  const uint8_pubKey = new Uint8Array(ed25519KeyPair.publicKey);
  console.log('uint8_pubKey', uint8_pubKey);
  const uint8_privKey = new Uint8Array(ed25519KeyPair.privateKey);
  console.log('uint8_privKey', uint8_privKey);
  const uint8_encPK = crypto_sign_ed25519_pk_to_curve25519(uint8_pubKey);
  const uint8_encSK = crypto_sign_ed25519_sk_to_curve25519(uint8_privKey);
  console.log('uint8_encPK=', uint8_encPK);
  console.log('uint8_encSK=', uint8_encSK);
  // console.log("crypto_sign_ed25519_pk_to_curve25519", crypto_sign_ed25519_pk_to_curve25519(new Un));

  return Promise.resolve({
    iv,
    publicKey: ed25519KeyPair.publicKey,
    privateKey: ed25519KeyPair.privateKey,
    encPK: crypto_sign_ed25519_pk_to_curve25519(ed25519KeyPair.publicKey),
    encSK: crypto_sign_ed25519_sk_to_curve25519(ed25519KeyPair.privateKey),
  });
}
function generateEntropy(numBytes = 16) {
  return sodium.randombytes_buf(numBytes);
}

async function verify_soidum() {
  const keyPairInfo = generateAsymmetricKey();
  return keyPairInfo;
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
