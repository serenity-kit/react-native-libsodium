import {
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_box_seed_keypair,
  from_base64,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_box_seed_keypair', () => {
  const seed = from_base64('KI70zL1z1j7-IRjn1YG-qgkbbR0QCFggiqWcAA5bXIk');

  const keyPair = crypto_box_seed_keypair(seed);
  const keyPairBase64 = crypto_box_seed_keypair(seed, 'base64');

  expect(keyPair.keyType).toEqual('x25519');
  expect(keyPair.publicKey.length).toEqual(crypto_box_PUBLICKEYBYTES);
  expect(typeof keyPair.publicKey).toEqual('object');
  expect(keyPair.publicKey).toEqual(
    new Uint8Array([
      108, 139, 52, 190, 205, 39, 174, 21, 111, 62, 10, 12, 133, 182, 39, 113,
      221, 51, 135, 183, 139, 101, 52, 64, 119, 21, 133, 7, 85, 73, 93, 7,
    ])
  );

  expect(keyPair.privateKey.length).toEqual(crypto_box_SECRETKEYBYTES);
  expect(typeof keyPair.privateKey).toEqual('object');
  expect(keyPair.privateKey).toEqual(
    new Uint8Array([
      28, 193, 69, 156, 167, 29, 242, 149, 39, 5, 162, 42, 15, 246, 31, 73, 182,
      214, 112, 23, 214, 0, 1, 101, 65, 125, 229, 229, 10, 180, 106, 124,
    ])
  );

  expect(keyPairBase64.keyType).toEqual('x25519');
  expect(keyPairBase64.publicKey.length).toEqual(43);
  expect(typeof keyPairBase64.publicKey).toEqual('string');
  expect(keyPairBase64.publicKey).toEqual(
    'bIs0vs0nrhVvPgoMhbYncd0zh7eLZTRAdxWFB1VJXQc'
  );
  expect(keyPairBase64.privateKey.length).toEqual(43);
  expect(typeof keyPairBase64.privateKey).toEqual('string');
  expect(keyPairBase64.privateKey).toEqual(
    'HMFFnKcd8pUnBaIqD_YfSbbWcBfWAAFlQX3l5Qq0anw'
  );
});
