import { _unstable_crypto_kdf_hkdf_sha256_expand } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('_unstable_crypto_kdf_hkdf_sha256_expand_test', () => {
  const key = new Uint8Array([
    75, 222, 64, 255, 217, 41, 81, 229, 21, 194, 0, 72, 125, 254, 2, 182, 113,
    28, 24, 1, 227, 2, 226, 196, 127, 221, 56, 72, 15, 126, 128, 30,
  ]);

  expect(
    _unstable_crypto_kdf_hkdf_sha256_expand(key, 'some_context', 32)
  ).toEqual(
    new Uint8Array([
      94, 202, 158, 208, 160, 172, 67, 223, 68, 62, 180, 53, 79, 68, 173, 141,
      136, 4, 177, 112, 84, 31, 14, 18, 40, 35, 230, 251, 53, 81, 81, 151,
    ])
  );
});
