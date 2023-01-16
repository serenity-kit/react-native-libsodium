export const isArrayEqual = (output: Uint8Array, expected: Uint8Array) => {
  if (output.length !== expected.length) {
    return false;
  }

  for (var index = 0; index < output.length; index++) {
    if (expected[index] !== output[index]) {
      return false;
    }
  }
  return true;
};
