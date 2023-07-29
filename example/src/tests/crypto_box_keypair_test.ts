import {
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_box_keypair,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_box_keypair', () => {
  const keyPair = crypto_box_keypair();
  const keyPairBase64 = crypto_box_keypair('base64');

  expect(keyPair.keyType).toEqual('x25519');
  expect(keyPair.publicKey.length).toEqual(crypto_box_PUBLICKEYBYTES);
  expect(typeof keyPair.publicKey).toEqual('object');
  expect(keyPair.privateKey.length).toEqual(crypto_box_SECRETKEYBYTES);
  expect(typeof keyPair.privateKey).toEqual('object');
  expect(keyPairBase64.keyType).toEqual('x25519');
  expect(keyPairBase64.publicKey.length).toEqual(43);
  expect(typeof keyPairBase64.publicKey).toEqual('string');
  expect(keyPairBase64.privateKey.length).toEqual(43);
  expect(typeof keyPairBase64.privateKey).toEqual('string');
});
