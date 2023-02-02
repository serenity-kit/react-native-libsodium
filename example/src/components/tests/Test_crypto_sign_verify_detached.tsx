import React from 'react';
import { crypto_sign_verify_detached, to_base64 } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

export const Test_crypto_sign_verify_detached: React.FC = () => {
  const signature = new Uint8Array([
    154, 39, 102, 2, 196, 230, 161, 247, 167, 233, 155, 107, 60, 147, 34, 127,
    184, 171, 14, 160, 82, 141, 238, 184, 214, 212, 171, 91, 142, 14, 156, 25,
    89, 190, 173, 162, 109, 217, 249, 251, 2, 48, 82, 74, 113, 85, 136, 138,
    200, 168, 70, 229, 251, 204, 208, 244, 105, 184, 217, 146, 173, 186, 63, 7,
  ]);
  const message = 'Hello World';
  const keyPair = {
    keyType: 'ed25519',
    privateKey: new Uint8Array([
      75, 127, 199, 101, 131, 29, 66, 210, 17, 236, 170, 64, 109, 224, 45, 127,
      172, 71, 87, 75, 101, 215, 119, 116, 5, 253, 248, 81, 177, 54, 59, 228,
      129, 33, 141, 186, 47, 179, 213, 15, 14, 148, 158, 145, 120, 152, 16, 22,
      235, 222, 236, 209, 157, 235, 235, 137, 190, 203, 245, 111, 49, 126, 250,
      158,
    ]),
    publicKey: new Uint8Array([
      129, 33, 141, 186, 47, 179, 213, 15, 14, 148, 158, 145, 120, 152, 16, 22,
      235, 222, 236, 209, 157, 235, 235, 137, 190, 203, 245, 111, 49, 126, 250,
      158,
    ]),
  };

  return (
    <FunctionStatus
      name="crypto_sign_verify_detached"
      success={
        crypto_sign_verify_detached(signature, message, keyPair.publicKey) &&
        crypto_sign_verify_detached(
          new Uint8Array([
            107, 84, 114, 136, 229, 176, 248, 23, 73, 244, 240, 46, 11, 126,
            107, 214, 100, 208, 246, 242, 56, 44, 245, 76, 224, 227, 174, 232,
            2, 134, 176, 232, 19, 171, 162, 52, 112, 240, 176, 246, 105, 36,
            117, 174, 30, 224, 164, 140, 27, 167, 196, 86, 139, 157, 143, 194,
            3, 240, 76, 89, 23, 129, 10, 9,
          ]),
          to_base64(
            new Uint8Array([
              72, 90, 158, 219, 156, 134, 114, 6, 249, 234, 125, 71, 159, 107,
              113, 242, 178, 31, 178, 48, 132, 136, 226, 123, 218, 227, 79, 228,
              199, 161, 3, 71,
            ])
          ),
          keyPair.publicKey
        )
      }
    />
  );
};
