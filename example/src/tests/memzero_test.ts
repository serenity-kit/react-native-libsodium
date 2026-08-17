import { memzero } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('memzero', () => {
  const bytes = new Uint8Array([222, 173, 190, 239]);
  memzero(bytes);
  expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0]));

  // only the bytes of the view must be wiped, not the whole underlying buffer
  const buffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  memzero(buffer.subarray(2, 6));
  expect(buffer).toEqual(new Uint8Array([1, 2, 0, 0, 0, 0, 7, 8]));

  expect(() => memzero([0, 1, 2, 3] as unknown as Uint8Array)).toThrow(
    'Only Uint8Array instances can be wiped'
  );
});
