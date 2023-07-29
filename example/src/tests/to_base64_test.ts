import {
  base64_variants,
  from_base64,
  to_base64,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('to_base64', () => {
  const input = 'Hello World';
  const resultUint8Array = from_base64(to_base64(input));
  // test expect(to_base64 with other variants
  const inputForVariants = new Uint8Array([
    179, 235, 62, 250, 207, 236, 255, 255, 218, 109,
  ]);
  const expected_URLSAFE = 'SGVsbG8gV29ybGQ';

  expect(to_base64(input)).toEqual(expected_URLSAFE);
  expect(to_base64(resultUint8Array)).toEqual(expected_URLSAFE);
  expect(to_base64(inputForVariants, base64_variants.ORIGINAL)).toEqual(
    's+s++s/s///abQ=='
  );
  expect(
    to_base64(inputForVariants, base64_variants.ORIGINAL_NO_PADDING)
  ).toEqual('s+s++s/s///abQ');
  expect(to_base64(inputForVariants, base64_variants.URLSAFE)).toEqual(
    's-s--s_s___abQ=='
  );
  expect(
    to_base64(inputForVariants, base64_variants.URLSAFE_NO_PADDING)
  ).toEqual('s-s--s_s___abQ');
});
