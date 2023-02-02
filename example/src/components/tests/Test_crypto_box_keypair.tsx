import React from 'react';
import {
  crypto_box_keypair,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_box_keypair: React.FC = () => {
  const keyPair = crypto_box_keypair();
  const keyPairBase64 = crypto_box_keypair('base64');

  return (
    <FunctionStatus
      name="crypto_box_keypair"
      success={
        keyPair.keyType === 'x25519' &&
        keyPair.publicKey.length === crypto_box_PUBLICKEYBYTES &&
        typeof keyPair.publicKey === 'object' &&
        keyPair.privateKey.length === crypto_box_SECRETKEYBYTES &&
        typeof keyPair.privateKey === 'object' &&
        keyPairBase64.keyType === 'x25519' &&
        keyPairBase64.publicKey.length === 43 &&
        typeof keyPairBase64.publicKey === 'string' &&
        keyPairBase64.privateKey.length === 43 &&
        typeof keyPairBase64.privateKey === 'string'
      }
    />
  );
};
