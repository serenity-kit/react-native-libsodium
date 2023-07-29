import { crypto_kdf_KEYBYTES, crypto_kdf_keygen } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_kdf_keygen', () => {
  expect(crypto_kdf_keygen().length).toEqual(crypto_kdf_KEYBYTES);
});
