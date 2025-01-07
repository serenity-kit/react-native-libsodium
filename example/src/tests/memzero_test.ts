import { memzero, to_hex } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('memzero', () => {
  let buf = new Uint8Array([222, 173, 190, 239]);
  memzero(buf);
  expect(to_hex(buf)).toBe('00000000');

  expect(() => memzero([0, 1, 2, 3] as unknown as Uint8Array)).toThrow();
});
