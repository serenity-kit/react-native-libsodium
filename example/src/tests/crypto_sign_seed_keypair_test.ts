import { crypto_sign_seed_keypair, from_base64 } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_sign_seed_keypair', () => {
  const seed = from_base64('XRryjUamW8IGY7zhYlVdh2DP3Ph7yCQ1cC6gVFdX3RE');
  const keyPair = crypto_sign_seed_keypair(seed);
  const keyPairBase64 = crypto_sign_seed_keypair(seed, 'base64');

  expect(keyPair.keyType).toEqual('ed25519');
  expect(keyPair.publicKey.length).toEqual(32);
  expect(typeof keyPair.publicKey).toEqual('object');
  expect(keyPair.privateKey.length).toEqual(64);
  expect(typeof keyPair.privateKey).toEqual('object');
  expect(keyPairBase64.keyType).toEqual('ed25519');
  expect(keyPairBase64.publicKey.length).toEqual(43);
  expect(typeof keyPairBase64.publicKey).toEqual('string');
  expect(keyPairBase64.privateKey.length).toEqual(86);
  expect(typeof keyPairBase64.privateKey).toEqual('string');
  expect(keyPair.privateKey).toEqual(
    new Uint8Array([
      93, 26, 242, 141, 70, 166, 91, 194, 6, 99, 188, 225, 98, 85, 93, 135, 96,
      207, 220, 248, 123, 200, 36, 53, 112, 46, 160, 84, 87, 87, 221, 17, 23,
      23, 36, 156, 1, 212, 20, 188, 23, 83, 200, 144, 223, 201, 109, 13, 94, 73,
      140, 176, 3, 76, 60, 224, 68, 171, 41, 37, 55, 251, 75, 186,
    ])
  );

  expect(keyPair.publicKey).toEqual(
    new Uint8Array([
      23, 23, 36, 156, 1, 212, 20, 188, 23, 83, 200, 144, 223, 201, 109, 13, 94,
      73, 140, 176, 3, 76, 60, 224, 68, 171, 41, 37, 55, 251, 75, 186,
    ])
  );
});
