import { crypto_sign_keypair } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_sign_keypair', () => {
  const keyPair = crypto_sign_keypair();
  const keyPairBase64 = crypto_sign_keypair('base64');

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
});
