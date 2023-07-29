import { randombytes_buf } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('randombytes_buf', () => {
  expect(randombytes_buf(1).length).toEqual(1);
  expect(randombytes_buf(3).length).toEqual(3);
  expect(randombytes_buf(9).length).toEqual(9);
});
