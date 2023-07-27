import React from 'react';
import {
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_easy,
  randombytes_buf,
  to_base64,
} from 'react-native-libsodium';
import { isEqualUint8Array } from '../../utils/isEqualUint8Array';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_secretbox_easy: React.FC = () => {
  // const key = crypto_secretbox_keygen();
  const key = new Uint8Array([
    45, 143, 243, 24, 147, 155, 142, 65, 114, 72, 52, 134, 77, 17, 18, 35, 150,
    234, 249, 64, 38, 174, 29, 133, 16, 10, 161, 111, 174, 96, 165, 46,
  ]);
  // const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES);
  const nonce = new Uint8Array([
    137, 227, 82, 42, 82, 132, 82, 104, 235, 79, 24, 168, 55, 132, 76, 5, 90,
    79, 19, 92, 233, 51, 170, 207,
  ]);

  const message = 'Hello World';
  const message2 = new Uint8Array([
    8, 231, 240, 41, 106, 138, 234, 14, 38, 102, 70, 86, 168, 115, 93, 238, 3,
    95, 224, 157, 125, 40, 151, 150, 147, 223, 7, 153, 132, 32, 92, 36,
  ]);

  let throwErrorForInvalidPrivateKey = false;
  try {
    crypto_secretbox_easy(
      message,
      nonce,
      // @ts-expect-error
      'wrong_private_ke'
    );
  } catch (e) {
    throwErrorForInvalidPrivateKey = true;
  }

  let throwErrorForInvalidNonceLength = false;
  try {
    const badNonce = randombytes_buf(crypto_secretbox_NONCEBYTES + 1);
    crypto_secretbox_easy(message, badNonce, key);
  } catch (e) {
    throwErrorForInvalidNonceLength = true;
  }

  let throwErrorForInvalidKeyLength = false;
  try {
    const badKey = randombytes_buf(crypto_secretbox_KEYBYTES + 1);
    crypto_secretbox_easy(message, nonce, badKey);
  } catch (e) {
    throwErrorForInvalidKeyLength = true;
  }

  return (
    <>
      <FunctionStatus
        name="crypto_secretbox_easy"
        success={
          throwErrorForInvalidPrivateKey &&
          throwErrorForInvalidNonceLength &&
          throwErrorForInvalidKeyLength &&
          isEqualUint8Array(
            crypto_secretbox_easy(message, nonce, key),
            new Uint8Array([
              107, 200, 44, 53, 220, 73, 233, 105, 148, 23, 198, 167, 238, 238,
              50, 158, 211, 196, 113, 159, 40, 6, 156, 203, 145, 204, 154,
            ])
          ) &&
          isEqualUint8Array(
            crypto_secretbox_easy(message2, nonce, key),
            new Uint8Array([
              81, 43, 179, 172, 2, 65, 182, 138, 224, 247, 78, 222, 103, 38,
              110, 82, 147, 70, 237, 218, 45, 172, 33, 170, 197, 198, 184, 165,
              223, 163, 162, 49, 134, 126, 137, 235, 132, 50, 134, 130, 21, 133,
              44, 234, 138, 193, 91, 12,
            ])
          ) &&
          isEqualUint8Array(
            crypto_secretbox_easy(to_base64(message2), nonce, key),
            new Uint8Array([
              8, 131, 116, 242, 11, 46, 35, 59, 232, 121, 183, 4, 34, 70, 211,
              66, 216, 238, 123, 132, 12, 113, 186, 239, 213, 199, 202, 158, 45,
              187, 165, 136, 244, 105, 39, 18, 206, 125, 95, 114, 178, 16, 26,
              74, 69, 171, 98, 127, 209, 161, 137, 4, 217, 172, 40, 8, 72, 53,
              77,
            ])
          )
        }
      />
    </>
  );
};
