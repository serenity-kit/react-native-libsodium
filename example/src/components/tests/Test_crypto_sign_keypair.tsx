import React from 'react';
import { crypto_sign_keypair } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_sign_keypair: React.FC = () => {
  const keyPair = crypto_sign_keypair();
  const keyPairBase64 = crypto_sign_keypair('base64');

  console.log(keyPairBase64.publicKey.length, keyPairBase64.privateKey.length);

  return (
    <FunctionStatus
      name="crypto_sign_keypair"
      success={
        keyPair.keyType === 'ed25519' &&
        keyPair.publicKey.length === 32 &&
        typeof keyPair.publicKey === 'object' &&
        keyPair.privateKey.length === 64 &&
        typeof keyPair.privateKey === 'object' &&
        keyPairBase64.keyType === 'ed25519' &&
        keyPairBase64.publicKey.length === 43 &&
        typeof keyPairBase64.publicKey === 'string' &&
        keyPairBase64.privateKey.length === 86 &&
        typeof keyPairBase64.privateKey === 'string'
      }
    />
  );
};
