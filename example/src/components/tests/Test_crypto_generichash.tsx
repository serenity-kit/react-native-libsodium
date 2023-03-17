import React from 'react';
import {
  crypto_generichash,
  crypto_generichash_BYTES,
  crypto_generichash_BYTES_MAX,
  crypto_generichash_BYTES_MIN,
  crypto_generichash_KEYBYTES,
  crypto_generichash_KEYBYTES_MAX,
  crypto_generichash_KEYBYTES_MIN,
  randombytes_buf,
  to_base64,
} from 'react-native-libsodium';
import { isEqualUint8Array } from '../../utils/isEqualUint8Array';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_generichash: React.FC = () => {
  const message = 'Hello World';
  const message2 = new Uint8Array([
    8, 231, 240, 41, 106, 138, 234, 14, 38, 102, 70, 86, 168, 115, 93, 238, 3,
    95, 224, 157, 125, 40, 151, 150, 147, 223, 7, 153, 132, 32, 92, 36,
  ]);

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
          crypto_generichash(crypto_generichash_BYTES, message2).length ===
            crypto_generichash_BYTES &&
          crypto_generichash(
            crypto_generichash_BYTES,
            message,
            randombytes_buf(crypto_generichash_KEYBYTES)
          ).length === crypto_generichash_BYTES &&
          crypto_generichash(
            crypto_generichash_BYTES,
            message,
            randombytes_buf(crypto_generichash_KEYBYTES_MAX)
          ).length === crypto_generichash_BYTES &&
          crypto_generichash(
            crypto_generichash_BYTES,
            message2,
            randombytes_buf(crypto_generichash_KEYBYTES_MAX)
          ).length === crypto_generichash_BYTES &&
          crypto_generichash(
            crypto_generichash_BYTES,
            message2,
            to_base64(randombytes_buf(crypto_generichash_KEYBYTES))
          ).length === crypto_generichash_BYTES &&
          isEqualUint8Array(
            crypto_generichash(crypto_generichash_BYTES, message),
            new Uint8Array([
              29, 192, 23, 114, 238, 1, 113, 245, 246, 20, 198, 115, 227, 199,
              250, 17, 7, 168, 207, 114, 123, 223, 90, 109, 173, 179, 121, 233,
              60, 13, 29, 0,
            ])
          )
        }
      />
    </>
  );
};
