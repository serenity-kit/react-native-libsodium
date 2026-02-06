import {
  crypto_box_BEFORENMBYTES,
  crypto_box_beforenm,
  crypto_box_keypair,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_box_beforenm', () => {
  const alice = crypto_box_keypair();
  const bob = crypto_box_keypair();

  // produces symmetric shared keys
  const sharedAlice = crypto_box_beforenm(bob.publicKey, alice.privateKey);
  const sharedBob = crypto_box_beforenm(alice.publicKey, bob.privateKey);

  expect(sharedAlice.length).toEqual(crypto_box_BEFORENMBYTES);
  expect(sharedBob.length).toEqual(crypto_box_BEFORENMBYTES);
  expect(sharedAlice).toEqual(sharedBob);

  // validates its inputs
  expect(() => {
    crypto_box_beforenm(
      alice.publicKey.slice(0, alice.publicKey.length - 1),
      alice.privateKey
    );
  }).toThrow();

  expect(() => {
    crypto_box_beforenm(
      alice.publicKey,
      alice.privateKey.slice(0, alice.privateKey.length - 1)
    );
  }).toThrow();

  expect(() => {
    crypto_box_beforenm(
      new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
      alice.privateKey
    );
  }).toThrow();
});
