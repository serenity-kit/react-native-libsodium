import React from 'react';
import {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  crypto_kdf_CONTEXTBYTES,
  crypto_kdf_KEYBYTES,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash_BYTES_MAX,
  crypto_pwhash_BYTES_MIN,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_constants: React.FC = () => {
  return (
    <>
      <FunctionStatus
        name="constants"
        success={
          crypto_secretbox_KEYBYTES === 32 &&
          crypto_secretbox_NONCEBYTES === 24 &&
          crypto_pwhash_SALTBYTES === 16 &&
          crypto_pwhash_ALG_DEFAULT === 2 &&
          crypto_pwhash_OPSLIMIT_INTERACTIVE === 2 &&
          crypto_pwhash_MEMLIMIT_INTERACTIVE === 67108864 &&
          crypto_box_PUBLICKEYBYTES === 32 &&
          crypto_box_SECRETKEYBYTES === 32 &&
          crypto_aead_xchacha20poly1305_ietf_KEYBYTES === 32 &&
          crypto_kdf_KEYBYTES === 32 &&
          crypto_pwhash_BYTES_MIN === 16 &&
          crypto_pwhash_BYTES_MAX === -1 &&
          crypto_kdf_CONTEXTBYTES === 8
        }
      />
    </>
  );
};
