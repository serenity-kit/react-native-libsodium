export const isEqualUint8Array = (a: Uint8Array, b: Uint8Array) => {
  if (a.length !== b.length) {
    return false;
  }

  for (var index = 0; index < a.length; index++) {
    if (b[index] !== a[index]) {
      return false;
    }
  }
  return true;
};
