import React from 'react';
import { crypto_box_easy, to_base64 } from 'react-native-libsodium';
import { isEqualUint8Array } from '../../utils/isEqualUint8Array';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_box_easy: React.FC = () => {
  const message = 'Hello, world!';
  const senderKeyPair = {
    keyType: 'x25519',
    privateKey: new Uint8Array([
      75, 222, 64, 255, 217, 41, 81, 229, 21, 194, 0, 72, 125, 254, 2, 182, 113,
      28, 24, 1, 227, 2, 226, 196, 127, 221, 56, 72, 15, 126, 128, 30,
    ]),
    publicKey: new Uint8Array([
      244, 123, 174, 160, 45, 184, 205, 250, 78, 208, 138, 200, 88, 36, 126, 12,
      19, 168, 140, 14, 151, 209, 47, 0, 36, 93, 189, 49, 182, 176, 19, 90,
    ]),
  };
  const receiverKeyPair = {
    keyType: 'x25519',
    privateKey: new Uint8Array([
      232, 167, 21, 228, 54, 165, 143, 50, 85, 27, 167, 176, 163, 211, 176, 7,
      159, 111, 77, 250, 19, 16, 169, 199, 109, 135, 21, 253, 184, 239, 207,
      172,
    ]),
    publicKey: new Uint8Array([
      142, 127, 163, 61, 43, 54, 5, 80, 178, 86, 18, 245, 253, 136, 7, 152, 90,
      152, 194, 31, 23, 253, 243, 87, 53, 66, 15, 42, 18, 238, 19, 12,
    ]),
  };
  // const nonce = randombytes_buf(crypto_box_NONCEBYTES);
  const nonce = new Uint8Array([
    253, 94, 45, 132, 44, 169, 219, 10, 185, 140, 94, 2, 10, 248, 211, 105, 251,
    45, 230, 58, 232, 72, 246, 100,
  ]);

  const message2 = new Uint8Array([
    8, 231, 240, 41, 106, 138, 234, 14, 38, 102, 70, 86, 168, 115, 93, 238, 3,
    95, 224, 157, 125, 40, 151, 150, 147, 223, 7, 153, 132, 32, 92, 36,
  ]);

  return (
    <>
      <FunctionStatus
        name="crypto_box_easy"
        success={
          isEqualUint8Array(
            crypto_box_easy(
              message,
              nonce,
              receiverKeyPair.publicKey,
              senderKeyPair.privateKey
            ),
            new Uint8Array([
              7, 9, 231, 28, 150, 42, 179, 98, 167, 141, 62, 183, 24, 32, 73,
              231, 239, 21, 211, 106, 137, 87, 233, 188, 43, 218, 126, 150, 252,
            ])
          ) &&
          isEqualUint8Array(
            crypto_box_easy(
              message2,
              nonce,
              receiverKeyPair.publicKey,
              senderKeyPair.privateKey
            ),
            new Uint8Array([
              46, 208, 135, 144, 121, 127, 67, 177, 231, 152, 118, 114, 190, 79,
              51, 6, 175, 151, 79, 47, 140, 241, 35, 197, 98, 206, 84, 164, 117,
              128, 122, 77, 40, 0, 16, 21, 100, 89, 91, 101, 44, 171, 227, 152,
              72, 48, 83, 198,
            ])
          ) &&
          isEqualUint8Array(
            crypto_box_easy(
              to_base64(message2),
              nonce,
              receiverKeyPair.publicKey,
              senderKeyPair.privateKey
            ),
            new Uint8Array([
              214, 245, 100, 63, 207, 192, 24, 15, 198, 69, 221, 75, 237, 213,
              191, 56, 228, 63, 217, 113, 173, 44, 184, 128, 114, 207, 38, 159,
              135, 152, 125, 244, 90, 23, 190, 236, 46, 22, 130, 149, 139, 62,
              213, 56, 135, 90, 106, 181, 98, 209, 31, 244, 109, 215, 244, 217,
              102, 38, 151,
            ])
          )
        }
      />
    </>
  );
};
