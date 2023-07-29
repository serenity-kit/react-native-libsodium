import {
  crypto_kdf_derive_from_key,
  crypto_kdf_keygen,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_kdf_derive_from_key', () => {
  const masterKey = new Uint8Array([
    63, 142, 237, 166, 3, 192, 237, 23, 28, 111, 151, 159, 105, 61, 63, 20, 65,
    36, 44, 128, 232, 72, 60, 49, 247, 203, 202, 70, 141, 235, 38, 225,
  ]);
  const key1 = crypto_kdf_derive_from_key(32, 1, 'context_', masterKey);
  const key2 = crypto_kdf_derive_from_key(32, 2, 'context_', masterKey);
  const key3 = crypto_kdf_derive_from_key(32, 1, 'another_', masterKey);

  expect(key1).toEqual(
    new Uint8Array([
      77, 165, 162, 159, 203, 242, 248, 208, 228, 56, 56, 187, 39, 57, 212, 123,
      45, 242, 93, 91, 175, 75, 192, 213, 233, 132, 178, 26, 172, 48, 203, 2,
    ])
  );
  expect(key2).toEqual(
    new Uint8Array([
      211, 182, 206, 227, 147, 141, 31, 111, 198, 138, 48, 111, 239, 104, 3,
      160, 142, 225, 208, 115, 188, 176, 111, 41, 161, 194, 245, 239, 206, 141,
      171, 34,
    ])
  );
  expect(key3).toEqual(
    new Uint8Array([
      228, 110, 32, 118, 202, 11, 138, 200, 194, 241, 175, 30, 237, 14, 111, 58,
      84, 39, 224, 128, 73, 76, 75, 236, 166, 201, 232, 77, 120, 237, 166, 179,
    ])
  );
  expect(key1).not.toEqual(masterKey);
  expect(key2).not.toEqual(masterKey);
  expect(key3).not.toEqual(masterKey);
  expect(key1).not.toEqual(key2);
  expect(key2).not.toEqual(key3);
  expect(key1).not.toEqual(key3);
  expect(
    crypto_kdf_derive_from_key(42, 1, 'another_', crypto_kdf_keygen()).length
  ).toEqual(42);
});
