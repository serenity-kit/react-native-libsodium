import React from 'react';
import { crypto_sign_seed_keypair, from_base64 } from 'react-native-libsodium';
import { isEqualUint8Array } from '../../utils/isEqualUint8Array';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_sign_seed_keypair: React.FC = () => {
  const seed = from_base64('XRryjUamW8IGY7zhYlVdh2DP3Ph7yCQ1cC6gVFdX3RE');
  const keyPair = crypto_sign_seed_keypair(seed);
  const keyPairBase64 = crypto_sign_seed_keypair(seed, 'base64');

  return (
    <FunctionStatus
      name="crypto_sign_seed_keypair"
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
        typeof keyPairBase64.privateKey === 'string' &&
        isEqualUint8Array(
          keyPair.privateKey,
          new Uint8Array([
            93, 26, 242, 141, 70, 166, 91, 194, 6, 99, 188, 225, 98, 85, 93,
            135, 96, 207, 220, 248, 123, 200, 36, 53, 112, 46, 160, 84, 87, 87,
            221, 17, 23, 23, 36, 156, 1, 212, 20, 188, 23, 83, 200, 144, 223,
            201, 109, 13, 94, 73, 140, 176, 3, 76, 60, 224, 68, 171, 41, 37, 55,
            251, 75, 186,
          ])
        ) &&
        isEqualUint8Array(
          keyPair.publicKey,
          new Uint8Array([
            23, 23, 36, 156, 1, 212, 20, 188, 23, 83, 200, 144, 223, 201, 109,
            13, 94, 73, 140, 176, 3, 76, 60, 224, 68, 171, 41, 37, 55, 251, 75,
            186,
          ])
        )
      }
    />
  );
};
