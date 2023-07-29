import { base64_variants, from_base64 } from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('from_base64', () => {
  const expectedForVariants = new Uint8Array([
    179, 235, 62, 250, 207, 236, 255, 255, 218, 109,
  ]);

  expect(from_base64('SGVsbG8gV29ybGQ')).toEqual(
    new Uint8Array([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
  );
  expect(from_base64('')).toEqual(new Uint8Array([]));
  expect(from_base64('s+s++s/s///abQ==', base64_variants.ORIGINAL)).toEqual(
    expectedForVariants
  );
  expect(
    from_base64('s+s++s/s///abQ', base64_variants.ORIGINAL_NO_PADDING)
  ).toEqual(expectedForVariants);
  expect(from_base64('s-s--s_s___abQ==', base64_variants.URLSAFE)).toEqual(
    expectedForVariants
  );
  expect(
    from_base64('s-s--s_s___abQ', base64_variants.URLSAFE_NO_PADDING)
  ).toEqual(expectedForVariants);
  expect(() => from_base64('111')).toThrow();
});
