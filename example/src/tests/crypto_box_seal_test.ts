import { crypto_box_seal, crypto_box_seal_open } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_box_seal', () => {
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

  const message = 'Hello, world!';
  const messageSealed = crypto_box_seal(message, receiverKeyPair.publicKey);
  const messageOpen = crypto_box_seal_open(
    messageSealed,
    receiverKeyPair.publicKey,
    receiverKeyPair.privateKey
  );
  expect(messageOpen).toEqual(
    new Uint8Array([
      72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
    ])
  );

  const message2 = new Uint8Array([
    8, 231, 240, 41, 106, 138, 234, 14, 38, 102, 70, 86, 168, 115, 93, 238, 3,
    95, 224, 157, 125, 40, 151, 150, 147, 223, 7, 153, 132, 32, 92, 36,
  ]);
  const message2Sealed = crypto_box_seal(message2, receiverKeyPair.publicKey);
  const message2Open = crypto_box_seal_open(
    message2Sealed,
    receiverKeyPair.publicKey,
    receiverKeyPair.privateKey
  );
  expect(message2Open).toEqual(message2);

  expect(() => {
    crypto_box_seal(
      message,
      new Uint8Array([
        232, 167, 21, 228, 54, 165, 143, 50, 85, 27, 167, 176, 163, 211, 176, 7,
        159, 111, 77, 250, 19, 16, 169, 199, 109, 135, 21, 253, 184, 239, 207,
        172, 100,
      ])
    );
  }).toThrow();
});
