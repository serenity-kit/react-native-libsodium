import { crypto_sign_ed25519_pk_to_curve25519 } from 'react-native-libsodium';
import { isEqualUint8Array } from '../utils/isEqualUint8Array';
import { expect, test } from '../utils/testRunner';

test('crypto_sign_ed25519_pk_to_curve25519', () => {
  const publicKey = new Uint8Array([
    38, 187, 152, 175, 122, 23, 12, 100, 83, 68, 221, 23, 158, 24, 170, 13, 234,
    4, 53, 212, 90, 147, 161, 67, 243, 45, 175, 177, 59, 239, 38, 65,
  ]);

  expect(
    isEqualUint8Array(
      crypto_sign_ed25519_pk_to_curve25519(publicKey),
      new Uint8Array([
        1, 123, 90, 189, 215, 54, 174, 97, 2, 183, 14, 184, 18, 115, 105, 142,
        141, 119, 109, 227, 130, 213, 21, 35, 162, 131, 125, 189, 213, 158, 9,
        17,
      ])
    )
  ).toBe(true);
});
