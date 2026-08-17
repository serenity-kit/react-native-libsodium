import {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  from_string,
  randombytes_buf,
  to_base64,
  to_string,
} from 'react-native-libsodium';
import { largeContent } from '../largeContent';
import { threeMbImage } from '../threeMbImage';
import { encryptAndDecryptImage } from '../utils/encryptAndDecryptImage';
import { expect, test } from '../utils/testRunner';

test('crypto_aead_xchacha20poly1305_ietf_decrypt', () => {
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

  let validImageEncryptionAndDecryption = true;
  try {
    encryptAndDecryptImage(threeMbImage);
    encryptAndDecryptImage(largeContent);
  } catch {
    validImageEncryptionAndDecryption = false;
  }

  expect(validImageEncryptionAndDecryption).toEqual(true);

  expect(
    to_string(
      crypto_aead_xchacha20poly1305_ietf_decrypt(
        secretNonce,
        new Uint8Array([
          249, 165, 41, 20, 8, 68, 254, 59, 157, 166, 196, 51, 98, 212, 168,
          126, 136, 102, 109, 38, 148, 139, 198, 4, 142, 86, 112, 89, 239,
        ]),
        additionalData,
        publicNonce,
        key
      )
    )
  ).toEqual(message);
  expect(
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      secretNonce,
      new Uint8Array([
        185, 39, 181, 81, 13, 226, 52, 66, 212, 178, 238, 1, 235, 85, 226, 122,
        82, 229, 252, 76, 236, 32, 229, 224, 208, 100, 160, 6, 152, 125, 40, 74,
        46, 105, 75, 60, 68, 154, 148, 224, 95, 83, 219, 49, 174, 206, 129, 111,
      ]),
      additionalData,
      publicNonce,
      key
    )
  ).toEqual(message2);
  expect(
    to_string(
      crypto_aead_xchacha20poly1305_ietf_decrypt(
        secretNonce,
        new Uint8Array([
          242, 143, 35, 15, 44, 63, 175, 7, 196, 179, 156, 58, 25, 77, 229, 195,
          32, 242, 82, 181, 166, 111, 60, 16, 119, 241, 150, 166, 87, 23, 17,
          57, 44, 214, 68, 157, 139, 62, 227, 105, 35, 105, 97, 244, 52, 94,
          112, 4, 151, 133, 209, 47, 121, 76, 49, 216, 89, 185, 245,
        ]),
        additionalData,
        publicNonce,
        key
      )
    )
  ).toEqual(to_base64(message2));

  expect(() => {
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      secretNonce,
      new Uint8Array([
        249, 165, 41, 20, 8, 68, 254, 59, 157, 166, 196, 51, 98, 212, 168, 126,
        136, 102, 109, 38, 148, 139, 198, 4, 142, 86, 112, 89, 239,
      ]),
      additionalData,
      publicNonce,
      crypto_aead_xchacha20poly1305_ietf_keygen() // random private key
    );
  }).toThrow();
  expect(() => {
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      secretNonce,
      from_string(message),
      additionalData,
      randombytes_buf(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 1),
      key
    );
  }).toThrow();
  expect(() => {
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      secretNonce,
      from_string(message),
      additionalData,
      publicNonce,
      randombytes_buf(crypto_aead_xchacha20poly1305_ietf_KEYBYTES + 1)
    );
  }).toThrow();
});

test('crypto_aead_xchacha20poly1305_ietf_decrypt with Uint8Array and null additional_data', () => {
  const message = 'Hello, world!';
  const key = new Uint8Array([
    108, 17, 177, 237, 16, 132, 96, 213, 10, 50, 109, 157, 209, 207, 131, 239,
    199, 127, 249, 166, 146, 48, 155, 115, 190, 244, 210, 252, 219, 38, 200,
    159,
  ]);
  const publicNonce = new Uint8Array([
    137, 27, 59, 167, 152, 253, 53, 78, 125, 80, 246, 158, 107, 239, 217, 210,
    3, 212, 219, 223, 63, 14, 97, 107,
  ]);
  // the ciphertext of 'Hello, world!' created with the string additional_data
  // 'additional data'
  const ciphertext = new Uint8Array([
    249, 165, 41, 20, 8, 68, 254, 59, 157, 166, 196, 51, 98, 212, 168, 126, 136,
    102, 109, 38, 148, 139, 198, 4, 142, 86, 112, 89, 239,
  ]);
  // the UTF-8 bytes of the string 'additional data'
  const additionalDataBytes = new Uint8Array([
    97, 100, 100, 105, 116, 105, 111, 110, 97, 108, 32, 100, 97, 116, 97,
  ]);

  // a Uint8Array additional_data must authenticate the exact same bytes as
  // its UTF-8 string equivalent
  expect(
    to_string(
      crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        additionalDataBytes,
        publicNonce,
        key
      )
    )
  ).toEqual(message);

  // round-trip with a Uint8Array additional_data that is no valid UTF-8
  const roundTripKey = crypto_aead_xchacha20poly1305_ietf_keygen();
  const roundTripNonce = randombytes_buf(
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const roundTripAdditionalData = new Uint8Array([0, 255, 254, 1, 128, 7]);
  const roundTripCiphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    roundTripAdditionalData,
    null,
    roundTripNonce,
    roundTripKey
  );
  expect(
    to_string(
      crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        roundTripCiphertext,
        roundTripAdditionalData,
        roundTripNonce,
        roundTripKey
      )
    )
  ).toEqual(message);

  // a single tampered additional_data byte (first byte flipped from 0 to 1)
  // must fail to decrypt
  const tamperedAdditionalData = new Uint8Array([1, 255, 254, 1, 128, 7]);
  expect(() => {
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      roundTripCiphertext,
      tamperedAdditionalData,
      roundTripNonce,
      roundTripKey
    );
  }).toThrow();

  // null additional_data
  expect(
    to_string(
      crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        new Uint8Array([
          249, 165, 41, 20, 8, 68, 254, 59, 157, 166, 196, 51, 98, 245, 181,
          152, 162, 160, 8, 101, 170, 191, 221, 127, 9, 8, 14, 197, 128,
        ]),
        null,
        publicNonce,
        key
      )
    )
  ).toEqual(message);
});
