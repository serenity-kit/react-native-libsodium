import { from_hex } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('from_hex', () => {
  const expected = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const expectedLong = new Uint8Array([
    52, 125, 140, 6, 103, 79, 108, 103, 145, 118, 54, 183, 101, 165, 190, 42,
    70, 149, 117, 81, 155, 62, 117, 95, 73, 130, 215, 200, 10, 253, 194, 195,
  ]);

  expect(from_hex('deadbeef')).toEqual(expected);
  expect(
    from_hex('347d8c06674f6c67917636b765a5be2a469575519b3e755f4982d7c80afdc2c3')
  ).toEqual(expectedLong);
  expect(from_hex('')).toEqual(new Uint8Array([]));
  expect(() => from_hex('ggg')).toThrow();
});
