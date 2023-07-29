import {
  crypto_auth_KEYBYTES,
  crypto_auth_keygen,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_auth_keygen', () => {
  expect(crypto_auth_keygen().length).toEqual(crypto_auth_KEYBYTES);
});
