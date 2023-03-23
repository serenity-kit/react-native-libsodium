import React from 'react';
import {
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  randombytes_buf,
  to_base64,
} from 'react-native-libsodium';
import { isEqualUint8Array } from '../../utils/isEqualUint8Array';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_aead_xchacha20poly1305_ietf_encrypt: React.FC = () => {
  const message = 'Hello, world!';
  const message2 = new Uint8Array([
    8, 231, 240, 41, 106, 138, 234, 14, 38, 102, 70, 86, 168, 115, 93, 238, 3,
    95, 224, 157, 125, 40, 151, 150, 147, 223, 7, 153, 132, 32, 92, 36,
  ]);
  const additionalData = 'additional data';
  // const key = crypto_aead_xchacha20poly1305_ietf_keygen();
  const key = new Uint8Array([
    108, 17, 177, 237, 16, 132, 96, 213, 10, 50, 109, 157, 209, 207, 131, 239,
    199, 127, 249, 166, 146, 48, 155, 115, 190, 244, 210, 252, 219, 38, 200,
    159,
  ]);
  const secretNonce = null;
  // const publicNonce = randombytes_buf(
  //   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  // );
  const publicNonce = new Uint8Array([
    137, 27, 59, 167, 152, 253, 53, 78, 125, 80, 246, 158, 107, 239, 217, 210,
    3, 212, 219, 223, 63, 14, 97, 107,
  ]);

  let throwErrorForInvalidPrivateKey = false;
  try {
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      to_base64(message2),
      additionalData,
      secretNonce,
      publicNonce,
      // @ts-expect-error
      'wrong_private_ke'
    );
  } catch (e) {
    throwErrorForInvalidPrivateKey = true;
  }

  let throwErrorForInvalidPublicNonceLength = false;
  try {
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      to_base64(message2),
      additionalData,
      secretNonce,
      randombytes_buf(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 1),
      key
    );
  } catch (e) {
    throwErrorForInvalidPublicNonceLength = true;
  }

  let throwErrorForInvalidKeyLength = false;
  try {
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      to_base64(message2),
      additionalData,
      secretNonce,
      publicNonce,
      randombytes_buf(crypto_aead_xchacha20poly1305_ietf_KEYBYTES + 1)
    );
  } catch (e) {
    throwErrorForInvalidKeyLength = true;
  }

  return (
    <>
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_encrypt"
        success={
          throwErrorForInvalidPrivateKey &&
          throwErrorForInvalidPublicNonceLength &&
          throwErrorForInvalidKeyLength &&
          isEqualUint8Array(
            crypto_aead_xchacha20poly1305_ietf_encrypt(
              message,
              additionalData,
              secretNonce,
              publicNonce,
              key
            ),
            new Uint8Array([
              249, 165, 41, 20, 8, 68, 254, 59, 157, 166, 196, 51, 98, 212, 168,
              126, 136, 102, 109, 38, 148, 139, 198, 4, 142, 86, 112, 89, 239,
            ])
          ) &&
          isEqualUint8Array(
            crypto_aead_xchacha20poly1305_ietf_encrypt(
              message2,
              additionalData,
              secretNonce,
              publicNonce,
              key
            ),
            new Uint8Array([
              185, 39, 181, 81, 13, 226, 52, 66, 212, 178, 238, 1, 235, 85, 226,
              122, 82, 229, 252, 76, 236, 32, 229, 224, 208, 100, 160, 6, 152,
              125, 40, 74, 46, 105, 75, 60, 68, 154, 148, 224, 95, 83, 219, 49,
              174, 206, 129, 111,
            ])
          ) &&
          isEqualUint8Array(
            crypto_aead_xchacha20poly1305_ietf_encrypt(
              to_base64(message2),
              additionalData,
              secretNonce,
              publicNonce,
              key
            ),
            new Uint8Array([
              242, 143, 35, 15, 44, 63, 175, 7, 196, 179, 156, 58, 25, 77, 229,
              195, 32, 242, 82, 181, 166, 111, 60, 16, 119, 241, 150, 166, 87,
              23, 17, 57, 44, 214, 68, 157, 139, 62, 227, 105, 35, 105, 97, 244,
              52, 94, 112, 4, 151, 133, 209, 47, 121, 76, 49, 216, 89, 185, 245,
            ])
          )
        }
      />
    </>
  );
};
