import { crypto_hash, crypto_hash_BYTES, to_hex } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_hash', () => {
  // FIPS 180-4 SHA-512 test vector for "abc"
  const abcHash =
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';

  expect(crypto_hash('abc').length).toEqual(crypto_hash_BYTES);
  expect(to_hex(crypto_hash('abc'))).toBe(abcHash);
  expect(to_hex(crypto_hash(new Uint8Array([97, 98, 99])))).toBe(abcHash);
  expect(crypto_hash('abc', 'hex')).toBe(abcHash);

  // FIPS 180-4 SHA-512 test vector for the two-block message
  expect(
    to_hex(
      crypto_hash(
        'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'
      )
    )
  ).toBe(
    '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'
  );
});
