import {
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_keygen,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_secretbox_keygen', () => {
  expect(crypto_secretbox_keygen().length).toEqual(crypto_secretbox_KEYBYTES);
});
