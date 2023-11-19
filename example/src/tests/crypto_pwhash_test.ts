import {
  crypto_pwhash,
  crypto_pwhash_ALG_DEFAULT,
  crypto_pwhash_BYTES_MIN,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
  randombytes_buf,
} from 'react-native-libsodium';
import { isEqualUint8Array } from '../utils/isEqualUint8Array';

test('crypto_pwhash', () => {
  const password = 'password123';
  const salt = new Uint8Array([
    149, 177, 121, 247, 17, 38, 67, 49, 150, 68, 118, 228, 16, 98, 110, 175,
  ]);
  const randomSalt = randombytes_buf(crypto_pwhash_SALTBYTES);

  expect(() =>
    crypto_pwhash(
      crypto_pwhash_BYTES_MIN,
      password,
      salt,
      crypto_pwhash_OPSLIMIT_INTERACTIVE,
      crypto_pwhash_MEMLIMIT_INTERACTIVE,
      200
    )
  ).toThrow();

  expect(() =>
    crypto_pwhash(
      15,
      password,
      salt,
      crypto_pwhash_OPSLIMIT_INTERACTIVE,
      crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_DEFAULT
    )
  ).toThrow();

  expect(() =>
    crypto_pwhash(
      crypto_pwhash_BYTES_MIN,
      password,
      new Uint8Array([10]),
      crypto_pwhash_OPSLIMIT_INTERACTIVE,
      crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_DEFAULT
    )
  ).toThrow();

  expect(
    isEqualUint8Array(
      crypto_pwhash(
        crypto_pwhash_BYTES_MIN,
        password,
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT
      ),
      new Uint8Array([
        75, 92, 252, 55, 217, 21, 210, 156, 216, 33, 97, 101, 153, 119, 14, 177,
      ])
    )
  ).toBe(true);

  expect(
    isEqualUint8Array(
      crypto_pwhash(
        crypto_pwhash_BYTES_MIN,
        new Uint8Array([100, 100, 100]),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT
      ),
      new Uint8Array([
        136, 232, 104, 134, 32, 193, 138, 249, 192, 236, 243, 239, 248, 70, 117,
        160,
      ])
    )
  ).toBe(true);

  expect(
    isEqualUint8Array(
      crypto_pwhash(
        crypto_pwhash_BYTES_MIN,
        password,
        randomSalt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT
      ),
      crypto_pwhash(
        crypto_pwhash_BYTES_MIN,
        password,
        randomSalt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT
      )
    )
  ).toBe(true);
});
