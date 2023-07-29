import { to_hex } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('to_hex', () => {
  expect(to_hex('Hello World')).toEqual('48656c6c6f20576f726c64');
});
