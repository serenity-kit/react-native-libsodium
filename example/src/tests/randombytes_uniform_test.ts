import { randombytes_uniform } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('randombytes_uniform', () => {
  expect(randombytes_uniform(10) <= 10).toEqual(true);
  expect(randombytes_uniform(1)).toEqual(0);
  expect(randombytes_uniform(0)).toEqual(0);
});
