import { _unstable_crypto_kdf_hkdf_sha256_extract } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('_unstable_crypto_kdf_hkdf_sha256_extract_test', () => {
  const key = new Uint8Array([
    75, 222, 64, 255, 217, 41, 81, 229, 21, 194, 0, 72, 125, 254, 2, 182, 113,
    28, 24, 1, 227, 2, 226, 196, 127, 221, 56, 72, 15, 126, 128, 30,
  ]);

  const salt = new Uint8Array([
    75, 222, 64, 255, 217, 41, 81, 229, 21, 194, 0, 72, 125, 254, 2, 182, 113,
    28, 24, 1, 227, 2, 226, 196, 127, 221, 56, 72, 15, 126, 128, 30,
  ]);

  expect(_unstable_crypto_kdf_hkdf_sha256_extract(key, salt)).toEqual(
    new Uint8Array([
      96, 198, 77, 78, 235, 17, 136, 179, 112, 240, 235, 48, 24, 198, 36, 27,
      180, 72, 174, 165, 180, 1, 95, 228, 38, 21, 51, 60, 114, 37, 20, 108,
    ])
  );
});
