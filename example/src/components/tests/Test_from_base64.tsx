import React from 'react';
import { base64_variants, from_base64 } from 'react-native-libsodium';
import { isEqualUint8Array } from '../../utils/isEqualUint8Array';
import { FunctionStatus } from '../FunctionStatus';

export const Test_from_base64: React.FC = () => {
  const expectedForVariants = new Uint8Array([
    179, 235, 62, 250, 207, 236, 255, 255, 218, 109,
  ]);

  let throwErrorForInvalidInput = false;
  try {
    from_base64('111');
  } catch (e) {
    throwErrorForInvalidInput = true;
  }

  return (
    <>
      <FunctionStatus
        name="from_base64"
        success={
          isEqualUint8Array(
            from_base64('SGVsbG8gV29ybGQ'),
            new Uint8Array([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100])
          ) &&
          isEqualUint8Array(from_base64(''), new Uint8Array([])) &&
          isEqualUint8Array(
            from_base64('s+s++s/s///abQ==', base64_variants.ORIGINAL),
            expectedForVariants
          ) &&
          isEqualUint8Array(
            from_base64('s+s++s/s///abQ', base64_variants.ORIGINAL_NO_PADDING),
            expectedForVariants
          ) &&
          isEqualUint8Array(
            from_base64('s-s--s_s___abQ==', base64_variants.URLSAFE),
            expectedForVariants
          ) &&
          isEqualUint8Array(
            from_base64('s-s--s_s___abQ', base64_variants.URLSAFE_NO_PADDING),
            expectedForVariants
          ) &&
          throwErrorForInvalidInput
        }
      />
    </>
  );
};
