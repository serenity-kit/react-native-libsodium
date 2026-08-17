import {
  crypto_hash_sha256,
  crypto_hash_sha256_BYTES,
  to_hex,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_hash_sha256', () => {
  // FIPS 180-4 SHA-256 test vector for "abc"
  const abcHash =
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

  expect(crypto_hash_sha256('abc').length).toEqual(crypto_hash_sha256_BYTES);
  expect(to_hex(crypto_hash_sha256('abc'))).toBe(abcHash);
  expect(to_hex(crypto_hash_sha256(new Uint8Array([97, 98, 99])))).toBe(
    abcHash
  );
  expect(crypto_hash_sha256('abc', 'hex')).toBe(abcHash);

  // FIPS 180-4 SHA-256 test vector for the two-block message
  expect(
    to_hex(
      crypto_hash_sha256(
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
      )
    )
  ).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
});
