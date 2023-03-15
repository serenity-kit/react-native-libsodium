import React from 'react';
import {
  randombytes_buf,
  crypto_generichash,
  crypto_generichash_BYTES,
  crypto_generichash_BYTES_MIN,
  crypto_generichash_BYTES_MAX,
  crypto_generichash_KEYBYTES,
  crypto_generichash_KEYBYTES_MIN,
  crypto_generichash_KEYBYTES_MAX,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_generichash: React.FC = () => {
  const message = 'Hello World';

  return (
    <>
      <FunctionStatus
        name="crypto_generichash"
        success={
          crypto_generichash(crypto_generichash_BYTES_MIN, message).length ===
            crypto_generichash_BYTES_MIN &&
          crypto_generichash(crypto_generichash_BYTES, message).length ===
            crypto_generichash_BYTES &&
          crypto_generichash(crypto_generichash_BYTES_MAX, message).length ===
            crypto_generichash_BYTES_MAX &&
          crypto_generichash(
            crypto_generichash_BYTES,
            message,
            randombytes_buf(crypto_generichash_KEYBYTES_MIN)
          ).length === crypto_generichash_BYTES &&
          crypto_generichash(
            crypto_generichash_BYTES,
            message,
            randombytes_buf(crypto_generichash_KEYBYTES)
          ).length === crypto_generichash_BYTES &&
          crypto_generichash(
            crypto_generichash_BYTES,
            message,
            randombytes_buf(crypto_generichash_KEYBYTES_MAX)
          ).length === crypto_generichash_BYTES
        }
      />
    </>
  );
};
