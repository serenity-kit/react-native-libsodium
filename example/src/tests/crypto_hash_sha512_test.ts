import {
  crypto_hash,
  crypto_hash_sha512,
  crypto_hash_sha512_BYTES,
  to_hex,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_hash_sha512', () => {
  // FIPS 180-4 SHA-512 test vector for "abc"
  const abcHash =
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';

  expect(crypto_hash_sha512('abc').length).toEqual(crypto_hash_sha512_BYTES);
  expect(to_hex(crypto_hash_sha512('abc'))).toBe(abcHash);
  expect(to_hex(crypto_hash_sha512(new Uint8Array([97, 98, 99])))).toBe(
    abcHash
  );
  expect(crypto_hash_sha512('abc', 'hex')).toBe(abcHash);

  // crypto_hash is SHA-512, so both must produce the same digest
  expect(crypto_hash_sha512('abc')).toEqual(crypto_hash('abc'));
});
