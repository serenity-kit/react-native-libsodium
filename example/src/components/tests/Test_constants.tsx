import React from 'react';
import {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_auth_BYTES,
  crypto_auth_KEYBYTES,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_kdf_CONTEXTBYTES,
  crypto_kdf_KEYBYTES,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_sign_SEEDBYTES,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_constants: React.FC = () => {
  console.log({
    crypto_auth_BYTES,
    crypto_auth_KEYBYTES,
  });
  return (
    <>
      <FunctionStatus
        name="constants"
        success={
          crypto_auth_BYTES === 32 &&
          crypto_auth_KEYBYTES === 32 &&
          crypto_secretbox_KEYBYTES === 32 &&
          crypto_secretbox_NONCEBYTES === 24 &&
          crypto_box_PUBLICKEYBYTES === 32 &&
          crypto_box_SECRETKEYBYTES === 32 &&
          crypto_aead_xchacha20poly1305_ietf_KEYBYTES === 32 &&
          crypto_kdf_KEYBYTES === 32 &&
          crypto_kdf_CONTEXTBYTES === 8 &&
          crypto_sign_SEEDBYTES === 32
        }
      />
    </>
  );
};
