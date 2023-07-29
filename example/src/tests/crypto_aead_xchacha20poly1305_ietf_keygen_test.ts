import {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_aead_xchacha20poly1305_ietf_keygen', () => {
  expect(crypto_aead_xchacha20poly1305_ietf_keygen().length).toEqual(
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES
  );
});
