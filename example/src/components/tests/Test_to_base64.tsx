import React from 'react';
import {
  base64_variants,
  from_base64,
  to_base64,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

const expected_URLSAFE = 'SGVsbG8gV29ybGQ';

export const Test_to_base64: React.FC = () => {
  const input = 'Hello World';
  const resultUint8Array = from_base64(to_base64(input));
  // test to_base64 with other variants
  const inputForVariants = new Uint8Array([
    179, 235, 62, 250, 207, 236, 255, 255, 218, 109,
  ]);

  return (
    <>
      <FunctionStatus
        name="to_base64"
        success={
          to_base64(input) === expected_URLSAFE &&
          to_base64(resultUint8Array) === expected_URLSAFE &&
          to_base64(inputForVariants, base64_variants.ORIGINAL) ===
            's+s++s/s///abQ==' &&
          to_base64(inputForVariants, base64_variants.ORIGINAL_NO_PADDING) ===
            's+s++s/s///abQ' &&
          to_base64(inputForVariants, base64_variants.URLSAFE) ===
            's-s--s_s___abQ==' &&
          to_base64(inputForVariants, base64_variants.URLSAFE_NO_PADDING) ===
            's-s--s_s___abQ'
        }
      />
    </>
  );
};
