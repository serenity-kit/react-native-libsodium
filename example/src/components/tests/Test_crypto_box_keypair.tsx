import React from 'react';
import {
  crypto_box_keypair,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  from_base64,
  KeyPair,
  StringKeyPair,
} from 'react-native-libsodium';
import type { OutputFormat } from 'src/types';
import { FunctionStatus } from '../FunctionStatus';

const lengthVerifies = (
  key: any,
  expectedLength: number,
  outputFormat: OutputFormat
) => {
  const keyLength = key.length;
  if (outputFormat === 'base64') {
    return (
      typeof key === 'string' && from_base64(key).length === expectedLength
    );
  } else if (outputFormat === 'hex') {
    return typeof key === 'string' && keyLength === expectedLength * 2;
  } else {
    return typeof key === 'object' && keyLength === expectedLength;
  }
};

const expectKeyPair = (
  keyPair: KeyPair | StringKeyPair,
  outputFormat: OutputFormat
) => {
  return (
    keyPair.keyType === 'x25519' &&
    lengthVerifies(
      keyPair.publicKey,
      crypto_box_PUBLICKEYBYTES,
      outputFormat
    ) &&
    lengthVerifies(keyPair.privateKey, crypto_box_SECRETKEYBYTES, outputFormat)
  );
};

export const Test_crypto_box_keypair: React.FC = () => {
  return (
    <>
      <FunctionStatus
        name="crypto_box_keypair"
        success={
          expectKeyPair(crypto_box_keypair(), 'uint8array') &&
          expectKeyPair(crypto_box_keypair('uint8array'), 'uint8array') &&
          expectKeyPair(crypto_box_keypair('base64'), 'base64') &&
          expectKeyPair(crypto_box_keypair('hex'), 'hex')
        }
      />
    </>
  );
};
