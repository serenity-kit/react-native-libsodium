import { memcmp } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('memcmp', () => {
  const bytes = new Uint8Array([222, 173, 190, 239]);
  expect(memcmp(bytes, new Uint8Array([222, 173, 190, 239]))).toEqual(true);

  // a difference in the last byte and a difference in the first must both be
  // reported, since a constant-time compare reads the whole length either way
  expect(memcmp(bytes, new Uint8Array([222, 173, 190, 238]))).toEqual(false);
  expect(memcmp(bytes, new Uint8Array([221, 173, 190, 239]))).toEqual(false);

  // two empty views are equal, as they are under libsodium-wrappers
  expect(memcmp(new Uint8Array([]), new Uint8Array([]))).toEqual(true);

  // only the bytes of the view are compared, not the whole underlying buffer
  const buffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  expect(memcmp(buffer.subarray(2, 6), new Uint8Array([3, 4, 5, 6]))).toEqual(
    true
  );
  // two views onto one buffer, offset from each other
  expect(memcmp(buffer.subarray(2, 6), buffer.subarray(4, 8))).toEqual(false);
  expect(memcmp(buffer.subarray(2, 6), buffer.subarray(2, 6))).toEqual(true);

  expect(() =>
    memcmp([0, 1, 2, 3] as unknown as Uint8Array, new Uint8Array([0, 1, 2, 3]))
  ).toThrow('Only Uint8Array instances can be compared');

  expect(() =>
    memcmp(new Uint8Array([0, 1, 2]), new Uint8Array([0, 1, 2, 3]))
  ).toThrow('Only instances of identical length can be compared');
});
