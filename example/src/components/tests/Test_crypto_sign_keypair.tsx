import React from 'react';
import { Text } from 'react-native';
import { to_base64, crypto_sign_keypair } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_sign_keypair: React.FC = () => {
  const keyPair = crypto_sign_keypair();

  return (
    <>
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_keygen"
        success={keyPair.keyType === 'ed25519'}
      >
        <Text>privateKey: {to_base64(keyPair.privateKey)}</Text>
        <Text>publicKey: {to_base64(keyPair.publicKey)}</Text>
        <Text>keyType: {keyPair.keyType}</Text>
      </FunctionStatus>
    </>
  );
};
