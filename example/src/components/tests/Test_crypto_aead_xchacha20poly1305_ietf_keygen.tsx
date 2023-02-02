import React from 'react';
import {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_aead_xchacha20poly1305_ietf_keygen: React.FC = () => {
  return (
    <>
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_keygen"
        success={
          crypto_aead_xchacha20poly1305_ietf_keygen().length ===
          crypto_aead_xchacha20poly1305_ietf_KEYBYTES
        }
      />
    </>
  );
};
